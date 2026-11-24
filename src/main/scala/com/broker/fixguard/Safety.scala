package com.broker.fixguard

import java.util.concurrent.atomic.AtomicLong
import scala.collection.concurrent.TrieMap

/**
 * Application-level idempotency. Sequence numbers alone do not provide exactly-once order
 * semantics across authorized resets, failover, or peer bugs; ClOrdID/OrigClOrdID and content
 * hashes are the durable business dedup keys.
 */
final case class ClientRequestKey(
    sessionLabel: String,
    msgType: String,
    clOrdId: String,
    origClOrdId: Option[String]
)

final case class InboundRequestRecord(
    key: ClientRequestKey,
    firstSeq: Long,
    fingerprint: String,
    firstAtNanos: Long,
    channelId: String,
    routed: Boolean = false,
    resultRef: Option[String] = None
)

sealed trait LedgerOutcome
object LedgerOutcome {
  final case class FirstSeen(record: InboundRequestRecord) extends LedgerOutcome
  final case class DuplicateSameRequest(record: InboundRequestRecord) extends LedgerOutcome
  final case class ConflictingRequest(existing: InboundRequestRecord, attemptedHash: String)
      extends LedgerOutcome
}

trait InboundRequestLedger {
  def register(message: FixMessage, fingerprint: String, atNanos: Long): LedgerOutcome
  def get(key: ClientRequestKey): Option[InboundRequestRecord]
  def markRouted(key: ClientRequestKey, resultRef: String): Option[InboundRequestRecord]
}

object ClientRequestKey {
  def from(session: SessionKey, message: FixMessage): Either[String, ClientRequestKey] = {
    message.value(Tags.ClOrdID).filter(_.nonEmpty) match {
      case Some(clOrdId) =>
        Right(ClientRequestKey(
          sessionLabel = session.label,
          msgType = message.msgType,
          clOrdId = clOrdId,
          origClOrdId = message.value(Tags.OrigClOrdID).filter(_.nonEmpty)
        ))
      case None =>
        Left(s"${message.msgType} seq=${message.seqNum} has no ClOrdID; cannot provide order idempotency")
    }
  }
}

/**
 * Durable implementations should write this record to the same replicated ledger/transaction
 * that creates the broker's order/intent. The in-memory version is for tests and single-process
 * demos only.
 */
final class InMemoryInboundRequestLedger(session: SessionKey) extends InboundRequestLedger {
  private val rows = TrieMap.empty[ClientRequestKey, InboundRequestRecord]

  override def get(key: ClientRequestKey): Option[InboundRequestRecord] = rows.get(key)

  override def register(
      message: FixMessage,
      fingerprint: String,
      atNanos: Long
  ): LedgerOutcome = {
    ClientRequestKey.from(session, message) match {
      case Left(reason) =>
        // Messages without a business id are outside order dedup; callers may still reject them.
        val synthetic = ClientRequestKey(session.label, message.msgType, s"seq:${message.seqNum}", None)
        registerKey(synthetic, message, fingerprint, atNanos)
      case Right(key) => registerKey(key, message, fingerprint, atNanos)
    }
  }

  private def registerKey(
      key: ClientRequestKey,
      message: FixMessage,
      fingerprint: String,
      atNanos: Long
  ): LedgerOutcome = {
    rows.get(key) match {
      case Some(existing) if existing.fingerprint == fingerprint =>
        LedgerOutcome.DuplicateSameRequest(existing)
      case Some(existing) =>
        LedgerOutcome.ConflictingRequest(existing, fingerprint)
      case None =>
        val record = InboundRequestRecord(
          key = key,
          firstSeq = message.seqNum,
          fingerprint = fingerprint,
          firstAtNanos = atNanos,
          channelId = message.channelId
        )
        rows.putIfAbsent(key, record) match {
          case None => LedgerOutcome.FirstSeen(record)
          case Some(raced) if raced.fingerprint == fingerprint =>
            LedgerOutcome.DuplicateSameRequest(raced)
          case Some(raced) =>
            LedgerOutcome.ConflictingRequest(raced, fingerprint)
        }
    }
  }

  override def markRouted(
      key: ClientRequestKey,
      resultRef: String
  ): Option[InboundRequestRecord] = {
    rows.get(key).map { rec =>
      val updated = rec.copy(routed = true, resultRef = Some(resultRef))
      rows.update(key, updated)
      updated
    }
  }
}

sealed trait ReportDeliveryState {
  def name: String = getClass.getSimpleName.stripSuffix("$")
}
object ReportDeliveryState {
  case object AppendedDurably extends ReportDeliveryState
  case object WireSent extends ReportDeliveryState
  /** Authenticated peer 789/sequence window proves transport receipt only. */
  case object PeerSequenceAcked extends ReportDeliveryState
  /** External execution/ack reconciliation proves the business report was processed. */
  case object BusinessConfirmed extends ReportDeliveryState
  case object SendFailed extends ReportDeliveryState
}

final case class OutboundEnvelope(
    seq: Long,
    msgType: String,
    clOrdId: Option[String],
    execId: Option[String],
    fingerprint: String,
    fields: Vector[FixField],
    createdAtNanos: Long,
    deliveryState: ReportDeliveryState = ReportDeliveryState.AppendedDurably
)

sealed trait PeerAckResult
object PeerAckResult {
  final case class Accepted(newlySequenceAcked: Vector[OutboundEnvelope]) extends PeerAckResult
  final case class ImpossibleHighWater(nextExpected: Long, localNext: Long) extends PeerAckResult
}

/**
 * Source of truth for outbound sequence numbers and resend. Append durably before writing to the
 * socket. A ResendRequest must be served from this journal, never reconstructed from current UI
 * state or from an attacker-controlled reset.
 */
trait OutboundJournal {
  def nextSeq: Long
  def append(
      msgType: String,
      fields: Vector[FixField],
      createdAtNanos: Long,
      clOrdId: Option[String] = None,
      execId: Option[String] = None
  ): OutboundEnvelope

  def get(seq: Long): Option[OutboundEnvelope]
  def resend(fromInclusive: Long, toInclusiveOrZero: Long): Vector[OutboundEnvelope]
  def markWireSent(seq: Long, ok: Boolean): Option[OutboundEnvelope]
  def markPeerExpected(nextExpectedSeq: Long): PeerAckResult
  def markBusinessConfirmedByExecId(execId: String): Option[OutboundEnvelope]
  def unconfirmedBusinessReports(nowNanos: Long, olderThanNanos: Long): Vector[OutboundEnvelope]
}

final class InMemoryOutboundJournal(startNextSeq: Long = 1L) extends OutboundJournal {
  private val sequence = new AtomicLong(startNextSeq)
  private val rows = TrieMap.empty[Long, OutboundEnvelope]

  override def nextSeq: Long = sequence.get()

  override def append(
      msgType: String,
      fields: Vector[FixField],
      createdAtNanos: Long,
      clOrdId: Option[String],
      execId: Option[String]
  ): OutboundEnvelope = {
    val seq = sequence.getAndIncrement()
    val fingerprint = MessageFingerprint.sha256Hex(
      MessageFingerprint.canonicalFields(fields, Set(Tags.BodyLength, Tags.CheckSum, Tags.PossDupFlag))
    )
    val envelope = OutboundEnvelope(
      seq = seq,
      msgType = msgType,
      clOrdId = clOrdId,
      execId = execId,
      fingerprint = fingerprint,
      fields = fields,
      createdAtNanos = createdAtNanos
    )
    rows.update(seq, envelope)
    envelope
  }

  override def get(seq: Long): Option[OutboundEnvelope] = rows.get(seq)

  override def resend(fromInclusive: Long, toInclusiveOrZero: Long): Vector[OutboundEnvelope] = {
    val highWater = sequence.get() - 1L
    val to = if (toInclusiveOrZero <= 0L) highWater else math.min(toInclusiveOrZero, highWater)
    if (fromInclusive > to) Vector.empty
    else (fromInclusive to to).flatMap(rows.get).toVector
  }

  override def markWireSent(seq: Long, ok: Boolean): Option[OutboundEnvelope] = {
    rows.get(seq).map { env =>
      val state = if (ok) ReportDeliveryState.WireSent else ReportDeliveryState.SendFailed
      val updated = env.copy(deliveryState = state)
      rows.update(seq, updated)
      updated
    }
  }

  override def markPeerExpected(nextExpectedSeq: Long): PeerAckResult = {
    val localNext = sequence.get()
    if (nextExpectedSeq > localNext) {
      PeerAckResult.ImpossibleHighWater(nextExpectedSeq, localNext)
    } else {
      val newly = (1L until nextExpectedSeq).flatMap { seq =>
        rows.get(seq).collect {
          case env if env.deliveryState != ReportDeliveryState.BusinessConfirmed =>
            val updated = env.copy(deliveryState = ReportDeliveryState.PeerSequenceAcked)
            rows.update(seq, updated)
            updated
          case env => env
        }
      }.toVector
      PeerAckResult.Accepted(newly)
    }
  }

  override def markBusinessConfirmedByExecId(execId: String): Option[OutboundEnvelope] = {
    rows.values.find(_.execId.contains(execId)).map { env =>
      val updated = env.copy(deliveryState = ReportDeliveryState.BusinessConfirmed)
      rows.update(env.seq, updated)
      updated
    }
  }

  override def unconfirmedBusinessReports(
      nowNanos: Long,
      olderThanNanos: Long
  ): Vector[OutboundEnvelope] = {
    rows.values
      .filter(_.deliveryState != ReportDeliveryState.BusinessConfirmed)
      .filter(env => nowNanos - env.createdAtNanos >= olderThanNanos)
      .toVector
      .sortBy(_.seq)
  }
}

object RetransmissionView {
  /** FIX retransmissions keep the business body and add 43=Y plus 122=original 52. */
  def fields(envelope: OutboundEnvelope): Vector[FixField] = {
    val originalSendingTime = envelope.fields
      .collectFirst { case FixField(Tags.SendingTime, v) => v }
      .getOrElse("19700101-00:00:00.000")
    val withoutDupMetadata = envelope.fields.filterNot { f =>
      f.tag == Tags.PossDupFlag || f.tag == Tags.OrigSendingTime || f.tag == Tags.PossResend
    }
    withoutDupMetadata ++ Vector(
      FixField(Tags.PossDupFlag, "Y"),
      FixField(Tags.OrigSendingTime, originalSendingTime)
    )
  }
}
