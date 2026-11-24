package com.broker.fixguard

import scala.collection.mutable.ListBuffer

/**
 * Thin runtime SPI. A production implementation adapts this to Netty/Aeron/TLS and writes to a
 * durable sequence/order journal. The guard itself remains blocking-free and single-writer.
 */
trait SessionTransport {
  def send(
      channelId: String,
      seq: Long,
      msgType: String,
      fields: Vector[FixField],
      retransmission: Boolean
  ): Unit

  def close(channelId: String, reason: String): Unit

  def reconciliationRequired(code: String, detail: String): Unit = ()
}

trait BusinessDeduplicationSink {
  def onFirstSeen(message: FixMessage, record: InboundRequestRecord): Unit = ()
  def onDuplicate(message: FixMessage, record: InboundRequestRecord): Unit = ()
  def onConflict(message: FixMessage, outcome: LedgerOutcome.ConflictingRequest): Unit = ()
  def onUnidentifiable(message: FixMessage, reason: String): Unit = ()
}

object NoopBusinessSink extends BusinessDeduplicationSink

/**
 * One runtime instance belongs to one SessionKey and should be driven by one actor/event-loop
 * thread. The synchronized methods are a safety net for tests; in Netty/Akka use the normal
 * happens-before/actor mailbox instead of contended locks.
 *
 * The outbound journal is authoritative for outbound sequence numbers. The guard's outbound
 * high-water is updated after a durable append.
 */
final class SessionRuntime(
    val guard: SequenceGuard,
    val ledger: InboundRequestLedger,
    val journal: OutboundJournal,
    transport: SessionTransport,
    authenticator: MessageAuthenticator = AllowAllAuthenticator,
    businessSink: BusinessDeduplicationSink = NoopBusinessSink,
    nanoTime: () => Long = () => System.nanoTime()
) {
  // The durable journal is the source of truth for outbound high-water. Align the pure guard
  // before processing the first frame; restore(state) can later replace the whole snapshot.
  @volatile private var currentState: GuardState =
    guard.initialState.copy(outboundNext = journal.nextSeq)

  def state: GuardState = currentState

  /** Restore a durably snapshot plus replay journal before opening the socket. */
  def restore(state: GuardState): Unit = synchronized {
    require(state.inboundExpected >= 1)
    currentState = state
  }

  def open(binding: ChannelBinding): GuardResult = synchronized {
    val result = guard.channelOpened(currentState, binding)
    currentState = result.state
    handleEffects(result)
    result
  }

  def channelClosed(channelId: String, reason: String): GuardResult = synchronized {
    val result = guard.channelClosed(currentState, channelId, nanoTime(), reason)
    currentState = result.state
    handleEffects(result)
    result
  }

  def receiveReadable(text: String, channelId: String): Either[FixWire.ParseError, GuardResult] = {
    FixWire.parseReadable(text, channelId, nanoTime()).map(receive(_))
  }

  def receive(
      message: FixMessage,
      resetAuthorization: Option[ResetAuthorization] = None
  ): GuardResult = synchronized {
    val auth = authenticator.verify(message)
    val result = guard.receive(currentState, message, auth, resetAuthorization)
    currentState = result.state
    handleEffects(result, explicitReplyChannel = Some(message.channelId))
    result.delivered.foreach(applyBusinessIdempotency)
    // Known same-sequence/same-hash replays are not routed, but still hit the business ledger so
    // operational metrics and conflict handling stay complete.
    result.suppressed.foreach(applyBusinessIdempotency)
    result
  }

  def tickResendTimer(nowNanos: Long = nanoTime()): GuardResult = synchronized {
    val result = guard.onResendTimeout(currentState, nowNanos)
    currentState = result.state
    handleEffects(result)
    result
  }

  /** Durably append first, then write. The returned envelope must be reconciled by ExecID. */
  def sendBusinessMessage(
      msgType: String,
      clOrdId: Option[String],
      execId: Option[String],
      fields: Vector[FixField]
  ): OutboundEnvelope = synchronized {
    val envelope = journal.append(msgType, fields, nanoTime(), clOrdId, execId)
    currentState = guard.outboundAssigned(currentState, envelope.seq)
    currentState.channel.map(_.channelId).foreach { channelId =>
      transport.send(channelId, envelope.seq, envelope.msgType, envelope.fields, retransmission = false)
      journal.markWireSent(envelope.seq, ok = true)
    }
    envelope
  }

  private def replyChannel(explicit: Option[String]): Option[String] =
    explicit
      .orElse(currentState.activeChannelId)
      .orElse(currentState.channel.map(_.channelId))

  private def handleEffects(
      result: GuardResult,
      explicitReplyChannel: Option[String] = None
  ): Unit = {
    val originallySentThisBatch = scala.collection.mutable.Set.empty[Long]
    result.effects.foreach {
      case GuardEffect.SendAdmin(msgType, fields) =>
        val envelope = journal.append(msgType, fields, nanoTime())
        currentState = guard.outboundAssigned(currentState, envelope.seq)
        replyChannel(explicitReplyChannel).foreach { channelId =>
          transport.send(channelId, envelope.seq, msgType, envelope.fields, retransmission = false)
          journal.markWireSent(envelope.seq, ok = true)
          originallySentThisBatch += envelope.seq
        }

      case GuardEffect.ServeOutboundResend(from, to, _) =>
        replyChannel(explicitReplyChannel).foreach { channelId =>
          journal.resend(from, to).foreach { envelope =>
            transport.send(
              channelId,
              envelope.seq,
              envelope.msgType,
              RetransmissionView.fields(envelope),
              retransmission = true
            )
            journal.markWireSent(envelope.seq, ok = true)
          }
        }

      case GuardEffect.CloseChannel(channelId, reason) =>
        transport.close(channelId, reason)

      case GuardEffect.PeerExpectedOutboundChanged(nextExpected) =>
        // The guard has already range-checked this against its high-water. The journal performs
        // the state transition; this is session receipt, not business confirmation.
        journal.markPeerExpected(nextExpected)

        // Logon 789 below our high-water means the peer is missing outbound reports. Retransmit
        // the suffix from its next expected seq. This is idempotent because ExecID/ClOrdID and
        // PossDupFlag stay stable. An explicit ResendRequest effect does the same on demand.
        val missingFromPeerExpected =
          journal.resend(nextExpected, 0L).filterNot(env => originallySentThisBatch.contains(env.seq))
        replyChannel(explicitReplyChannel).foreach { channelId =>
          missingFromPeerExpected.foreach { envelope =>
            transport.send(
              channelId,
              envelope.seq,
              envelope.msgType,
              RetransmissionView.fields(envelope),
              retransmission = true
            )
            journal.markWireSent(envelope.seq, ok = true)
          }
        }

      case GuardEffect.RequireReconciliation(code, detail) =>
        transport.reconciliationRequired(code, detail)

      case GuardEffect.ScheduleResendTimeout(_, _) =>
      // Production runtime registers a timer and calls tickResendTimer. Tests call it directly.

      case GuardEffect.PersistSnapshot(_) =>
      // Production implementation fsyncs/replicates currentState here. The in-memory reference
      // implementation intentionally has no hidden blocking I/O inside the pure guard.
    }
  }

  private def applyBusinessIdempotency(message: FixMessage): Unit = {
    val hash = MessageFingerprint.businessHash(message, guard.config.authTag)
    ClientRequestKey.from(guard.config.session, message) match {
      case Left(reason) => businessSink.onUnidentifiable(message, reason)
      case Right(_) =>
        ledger.register(message, hash, message.receivedAtNanos) match {
          case LedgerOutcome.FirstSeen(record) => businessSink.onFirstSeen(message, record)
          case LedgerOutcome.DuplicateSameRequest(record) => businessSink.onDuplicate(message, record)
          case conflict: LedgerOutcome.ConflictingRequest => businessSink.onConflict(message, conflict)
        }
    }
  }
}

final case class SentFrame(
    channelId: String,
    seq: Long,
    msgType: String,
    retransmission: Boolean
)

/** Test/demo transport that records outbound session actions instead of opening a socket. */
final class RecordingSessionTransport extends SessionTransport {
  private val sentFrames = ListBuffer.empty[SentFrame]
  private val closedChannels = ListBuffer.empty[(String, String)]
  private val reconciliations = ListBuffer.empty[(String, String)]

  override def send(
      channelId: String,
      seq: Long,
      msgType: String,
      fields: Vector[FixField],
      retransmission: Boolean
  ): Unit = synchronized {
    sentFrames += SentFrame(channelId, seq, msgType, retransmission)
  }

  override def close(channelId: String, reason: String): Unit = synchronized {
    closedChannels += ((channelId, reason))
  }

  override def reconciliationRequired(code: String, detail: String): Unit = synchronized {
    reconciliations += ((code, detail))
  }

  def sent: Vector[SentFrame] = synchronized(sentFrames.toVector)
  def closed: Vector[(String, String)] = synchronized(closedChannels.toVector)
  def reconciliationRequests: Vector[(String, String)] = synchronized(reconciliations.toVector)
}
