package com.broker.fixguard

import scala.collection.immutable.SortedMap

sealed trait Phase {
  def name: String = getClass.getSimpleName.stripSuffix("$")
}
object Phase {
  case object Offline extends Phase
  case object AwaitingLogon extends Phase
  case object Active extends Phase
  case object Resending extends Phase
  case object Stalled extends Phase
  case object Fenced extends Phase
}

sealed trait Severity {
  def name: String
}
object Severity {
  case object Info extends Severity { val name = "INFO" }
  case object Warning extends Severity { val name = "WARN" }
  case object Critical extends Severity { val name = "CRITICAL" }
}

final case class SecurityEvent(
    code: String,
    severity: Severity,
    sessionLabel: String,
    seqNum: Option[Long],
    message: String,
    atNanos: Long
)

sealed trait GuardEffect
object GuardEffect {
  final case class SendAdmin(msgType: String, fields: Vector[FixField]) extends GuardEffect
  final case class CloseChannel(channelId: String, reason: String) extends GuardEffect
  final case class PersistSnapshot(state: GuardState) extends GuardEffect
  final case class ScheduleResendTimeout(afterNanos: Long, attempt: Int) extends GuardEffect
  final case class ServeOutboundResend(beginSeq: Long, endSeqInclusiveOrZero: Long, requestSeq: Long)
      extends GuardEffect
  final case class PeerExpectedOutboundChanged(nextExpectedSeq: Long) extends GuardEffect
  final case class RequireReconciliation(code: String, detail: String) extends GuardEffect
}

final case class GuardResult(
    state: GuardState,
    delivered: Vector[FixMessage] = Vector.empty,
    suppressed: Vector[FixMessage] = Vector.empty,
    effects: Vector[GuardEffect] = Vector.empty,
    alerts: Vector[SecurityEvent] = Vector.empty
)

final case class GuardConfig(
    session: SessionKey,
    initialInboundExpected: Long = 1L,
    initialOutboundNext: Long = 1L,
    /** Pin the verified mTLS/certificate identity in production. */
    expectedTlsIdentity: Option[String] = None,
    requireTlsIdentity: Boolean = true,
    /** First-seen pinning is useful for controlled bring-up but weaker than pre-provisioning. */
    allowIdentityOnFirstUse: Boolean = false,
    /** False by default. Plaintext endpoint binding is only suitable for tests/demo. */
    allowPlaintextBinding: Boolean = false,
    maxBufferedOutOfOrder: Int = 10_000,
    maxSequenceJump: Long = 5_000_000L,
    fingerprintRetention: Int = 200_000,
    resendTimeoutNanos: Long = 1_000_000_000L,
    maxResendAttempts: Int = 3,
    requireActiveResendForGapFill: Boolean = true,
    maxAutomaticGapFill: Long = 100_000L,
    fenceOnUnflaggedReplayAfter: Int = 3,
    fenceOnUnverifiableLowSeq: Boolean = false,
    maxInboundResendRequestsPerWindow: Int = 20,
    resendRequestWindowNanos: Long = 1_000_000_000L,
    authTag: Option[Int] = Some(9001)
) {
  require(initialInboundExpected >= 1, "inbound sequence must start at 1 or higher")
  require(maxBufferedOutOfOrder > 0)
  require(maxSequenceJump > 0)
}

final case class FingerprintRecord(
    hash: String,
    msgType: String,
    originalSendingTime: Option[String],
    channelId: String,
    atNanos: Long
)

final case class ResendState(
    beginSeq: Long,
    endSeq: Long,
    attempt: Int,
    requestedAtNanos: Long,
    lastRequestAtNanos: Long
) {
  def coversThrough: Long = endSeq
}

final case class GapFillRange(
    resetSeq: Long,
    fromSeqInclusive: Long,
    toSeqInclusive: Long,
    newSeq: Long,
    atNanos: Long,
    epoch: Long
)

final case class GuardState(
    phase: Phase,
    epoch: Long = 1L,
    inboundExpected: Long,
    outboundNext: Long,
    activeChannelId: Option[String] = None,
    channel: Option[ChannelBinding] = None,
    pinnedIdentity: Option[String] = None,
    pending: SortedMap[Long, FixMessage] = SortedMap.empty,
    history: Map[Long, FingerprintRecord] = Map.empty,
    historyOrder: Vector[Long] = Vector.empty,
    resend: Option[ResendState] = None,
    gapFillAudit: Vector[GapFillRange] = Vector.empty,
    unflaggedReplays: Int = 0,
    inboundResendRequestTimes: Vector[Long] = Vector.empty,
    lastInboundAtNanos: Option[Long] = None,
    peerExpectedOutbound: Option[Long] = None,
    consumedResetNonces: Set[String] = Set.empty,
    closedReason: Option[String] = None
)

final case class ResetAuthorization(
    approver: String,
    ticket: String,
    nonce: String,
    expiresAtNanos: Long,
    signatureValid: Boolean = true
) {
  def validAt(nowNanos: Long): Boolean =
    signatureValid && approver.trim.nonEmpty && ticket.trim.nonEmpty &&
      nonce.trim.nonEmpty && expiresAtNanos > nowNanos
}

/**
 * Deterministic, single-writer session sequence state machine.
 *
 * It performs no blocking I/O and allocates bounded collections, so it is suitable for a
 * per-session event loop. A runtime must call it from one thread/actor per SessionKey and
 * persist the returned snapshot/effects according to its durability target.
 */
final class SequenceGuard(val config: GuardConfig) {

  def initialState: GuardState = GuardState(
    phase = Phase.Offline,
    inboundExpected = config.initialInboundExpected,
    outboundNext = config.initialOutboundNext,
    pinnedIdentity = config.expectedTlsIdentity
  )

  private final class Builder(var state: GuardState) {
    val delivered = Vector.newBuilder[FixMessage]
    val suppressed = Vector.newBuilder[FixMessage]
    val effects = Vector.newBuilder[GuardEffect]
    val alerts = Vector.newBuilder[SecurityEvent]

    def emit(effect: GuardEffect): Unit = effects += effect
    def raise(event: SecurityEvent): Unit = alerts += event

    def finish(): GuardResult =
      GuardResult(
        state,
        delivered.result(),
        suppressed.result(),
        effects.result(),
        alerts.result()
      )
  }

  private def securityEvent(
      code: String,
      severity: Severity,
      atNanos: Long,
      seqNum: Option[Long],
      message: String
  ): SecurityEvent =
    SecurityEvent(code, severity, config.session.label, seqNum, message, atNanos)

  private def persist(b: Builder): Unit = b.emit(GuardEffect.PersistSnapshot(b.state))

  private def fence(
      b: Builder,
      code: String,
      detail: String,
      seqNum: Option[Long],
      atNanos: Long
  ): GuardResult = {
    val event = securityEvent(code, Severity.Critical, atNanos, seqNum, detail)
    b.raise(event)
    val channelToClose = b.state.activeChannelId
    b.state = b.state.copy(
      phase = Phase.Fenced,
      closedReason = Some(code),
      activeChannelId = None,
      resend = None
    )
    persist(b)
    channelToClose.foreach(id => b.emit(GuardEffect.CloseChannel(id, code)))
    b.finish()
  }

  private def alsoClosePreviousChannel(
      result: GuardResult,
      previousChannelId: Option[String]
  ): GuardResult = {
    val additional = previousChannelId
      .filter(oldId => !result.effects.exists {
        case GuardEffect.CloseChannel(id, _) => id == oldId
        case _ => false
      })
      .map(oldId => GuardEffect.CloseChannel(oldId, "IDENTITY_FAILURE_SUPERSEDED_CHANNEL"))
      .toVector
    result.copy(effects = result.effects ++ additional)
  }

  def channelOpened(state: GuardState, binding: ChannelBinding): GuardResult = {
    if (state.phase == Phase.Fenced) {
      val event = securityEvent(
        "RECONNECT_WHILE_FENCED",
        Severity.Critical,
        binding.openedAtNanos,
        None,
        "rejecting new channel because session is fenced pending out-of-band recovery"
      )
      return GuardResult(
        state,
        alerts = Vector(event),
        effects = Vector(GuardEffect.CloseChannel(binding.channelId, "SESSION_FENCED"))
      )
    }

    val provisional = state.copy(
      activeChannelId = Some(binding.channelId),
      channel = Some(binding),
      closedReason = None
    )
    val b = new Builder(provisional)
    val presented = binding.tlsIdentity.map(_.trim).filter(_.nonEmpty)

    if (presented.isEmpty && !config.allowPlaintextBinding) {
      val result = fence(
        b,
        "UNAUTHENTICATED_CHANNEL",
        "no verified TLS identity and plaintext endpoint binding is disabled",
        None,
        binding.openedAtNanos
      )
      return alsoClosePreviousChannel(result, state.activeChannelId)
    }

    val expected = config.expectedTlsIdentity.filter(_.nonEmpty).orElse(state.pinnedIdentity)
    (expected, presented) match {
      case (Some(exp), Some(got)) if exp != got =>
        val result = fence(
          b,
          "CHANNEL_IDENTITY_MISMATCH",
          s"presented identity '$got' does not match pinned identity '$exp'",
          None,
          binding.openedAtNanos
        )
        alsoClosePreviousChannel(result, state.activeChannelId)
      case _ =>
        val pin = expected
          .orElse(if (config.allowIdentityOnFirstUse) presented else None)
          .orElse(if (config.allowPlaintextBinding) Some(s"endpoint:${binding.remoteEndpoint}") else None)

        if (pin.isEmpty) {
          val result = fence(
            b,
            "IDENTITY_NOT_PINNED",
            "no pre-provisioned identity and allowIdentityOnFirstUse=false",
            None,
            binding.openedAtNanos
          )
          alsoClosePreviousChannel(result, state.activeChannelId)
        } else {
          if (presented.isEmpty) {
            b.raise(securityEvent(
              "PLAINTEXT_ENDPOINT_BINDING",
              Severity.Warning,
              binding.openedAtNanos,
              None,
              s"binding session to remote endpoint ${binding.remoteEndpoint}; mTLS/HMAC recommended"
            ))
          } else if (expected.isEmpty && config.allowIdentityOnFirstUse) {
            b.raise(securityEvent(
              "IDENTITY_PINNED_ON_FIRST_USE",
              Severity.Warning,
              binding.openedAtNanos,
              None,
              s"pinned first observed identity '$pin'"
            ))
          }
          b.state = b.state.copy(
            phase = Phase.AwaitingLogon,
            pinnedIdentity = pin,
            activeChannelId = Some(binding.channelId),
            channel = Some(binding),
            // A resend timer/attempt count belongs to the old transport. The sequence hole remains
            // in inboundExpected/pending; a post-Logon future frame creates a fresh request.
            resend = None
          )
          state.activeChannelId.filter(_ != binding.channelId).foreach { oldChannelId =>
            b.raise(securityEvent(
              "AUTHENTICATED_CHANNEL_SUPERSEDES_OLD",
              Severity.Warning,
              binding.openedAtNanos,
              None,
              s"new authenticated channel ${binding.channelId} replaces old channel $oldChannelId"
            ))
            b.emit(GuardEffect.CloseChannel(oldChannelId, "SUPERSEDED_BY_NEW_CHANNEL"))
          }
          persist(b)
          b.finish()
        }
    }
  }

  def channelClosed(
      state: GuardState,
      channelId: String,
      atNanos: Long,
      reason: String
  ): GuardResult = {
    if (!state.activeChannelId.contains(channelId)) {
      return GuardResult(state)
    }
    if (state.phase == Phase.Fenced) {
      return GuardResult(state.copy(activeChannelId = None))
    }
    val next = state.copy(phase = Phase.Offline, activeChannelId = None)
    val event = securityEvent(
      "CHANNEL_CLOSED_RETAIN_SEQUENCE",
      Severity.Info,
      atNanos,
      None,
      s"$reason; sequences and pending replay state retained"
    )
    GuardResult(next, alerts = Vector(event), effects = Vector(GuardEffect.PersistSnapshot(next)))
  }

  def receive(
      state: GuardState,
      message: FixMessage,
      auth: AuthVerdict,
      resetAuthorization: Option[ResetAuthorization] = None
  ): GuardResult = {
    state.phase match {
      case Phase.Fenced =>
        return GuardResult(
          state,
          alerts = Vector(securityEvent(
            "FRAME_AFTER_FENCE",
            Severity.Critical,
            message.receivedAtNanos,
            Some(message.seqNum),
            "frame ignored because session is fenced"
          )),
          effects = Vector(GuardEffect.CloseChannel(message.channelId, "SESSION_FENCED"))
        )
      case Phase.Offline =>
        return GuardResult(
          state,
          alerts = Vector(securityEvent(
            "FRAME_WHILE_OFFLINE",
            Severity.Warning,
            message.receivedAtNanos,
            Some(message.seqNum),
            "frame ignored because no authenticated channel is active"
          )),
          effects = Vector(GuardEffect.CloseChannel(message.channelId, "NO_ACTIVE_CHANNEL"))
        )
      case Phase.AwaitingLogon if message.msgType != MsgTypes.Logon && message.msgType != MsgTypes.Logout =>
        val b = new Builder(state.copy(activeChannelId = Some(message.channelId)))
        return fence(
          b,
          "APP_FRAME_BEFORE_LOGON",
          s"msgType=${message.msgType} arrived before Logon",
          Some(message.seqNum),
          message.receivedAtNanos
        )
      case _ =>
    }

    if (!state.activeChannelId.contains(message.channelId)) {
      val event = securityEvent(
        "STALE_OR_UNBOUND_CHANNEL",
        Severity.Critical,
        message.receivedAtNanos,
        Some(message.seqNum),
        s"frame channel ${message.channelId} is not active channel ${state.activeChannelId.getOrElse("<none>")}"
      )
      return GuardResult(
        state,
        alerts = Vector(event),
        effects = Vector(GuardEffect.CloseChannel(message.channelId, "STALE_CHANNEL"))
      )
    }

    if (!auth.verified) {
      val b = new Builder(state)
      return fence(
        b,
        "MESSAGE_AUTH_FAILED",
        auth match {
          case AuthVerdict.Invalid(reason) => reason
          case _ => "unverified"
        },
        Some(message.seqNum),
        message.receivedAtNanos
      )
    }

    val compIdOk = message.senderCompId == config.session.remoteCompId &&
      message.targetCompId == config.session.localCompId
    if (!compIdOk) {
      val b = new Builder(state)
      return fence(
        b,
        "COMP_ID_MISMATCH",
        s"expected ${config.session.remoteCompId}->${config.session.localCompId}, " +
          s"got ${message.senderCompId}->${message.targetCompId}",
        Some(message.seqNum),
        message.receivedAtNanos
      )
    }

    if (message.msgType == MsgTypes.Logon) {
      handleLogon(state, message, resetAuthorization)
    } else {
      val b = new Builder(state.copy(lastInboundAtNanos = Some(message.receivedAtNanos)))
      routeBySequence(b, message)
      b.finish()
    }
  }

  private def handleLogon(
      state: GuardState,
      message: FixMessage,
      resetAuthorization: Option[ResetAuthorization]
  ): GuardResult = {
    val wantsReset = message.boolean(Tags.ResetSeqNumFlag) || message.seqNum < state.inboundExpected
    if (wantsReset) {
      val approval = resetAuthorization.filter { a =>
        a.validAt(message.receivedAtNanos) && !state.consumedResetNonces.contains(a.nonce)
      }
      if (approval.isEmpty) {
        val b = new Builder(state)
        return fence(
          b,
          "UNAUTHORIZED_SEQUENCE_RESET",
          s"Logon reset/seq=${message.seqNum}, expected=$state.inboundExpected; " +
            "no valid out-of-band control-plane approval",
          Some(message.seqNum),
          message.receivedAtNanos
        )
      }
      val auth = approval.get
      val peerExpected = message.long(Tags.NextExpectedMsgSeqNum)
      if (peerExpected.exists(_ > state.outboundNext)) {
        val b = new Builder(state)
        return fence(
          b,
          "LOGON_789_BEYOND_OUTBOUND_HIGH_WATER",
          s"authorized reset Logon reports 789=${peerExpected.get} but outboundNext=${state.outboundNext}",
          Some(message.seqNum),
          message.receivedAtNanos
        )
      }
      val next = state.copy(
        phase = Phase.Active,
        epoch = state.epoch + 1,
        inboundExpected = message.seqNum + 1,
        pending = SortedMap.empty,
        history = Map.empty,
        historyOrder = Vector.empty,
        resend = None,
        unflaggedReplays = 0,
        consumedResetNonces = state.consumedResetNonces + auth.nonce,
        peerExpectedOutbound = peerExpected.orElse(state.peerExpectedOutbound),
        lastInboundAtNanos = Some(message.receivedAtNanos),
        closedReason = None
      )
      val event = securityEvent(
        "AUTHORIZED_LOGON_RESET",
        Severity.Warning,
        message.receivedAtNanos,
        Some(message.seqNum),
        s"approved by=${auth.approver} ticket=${auth.ticket} nonce=${auth.nonce}; new epoch=${next.epoch}"
      )
      val ack = GuardEffect.SendAdmin(
        MsgTypes.Logon,
        logonAckFields(message, next.inboundExpected)
      )
      val peerEffect = next.peerExpectedOutbound.map(GuardEffect.PeerExpectedOutboundChanged)
      GuardResult(
        next,
        alerts = Vector(event),
        effects = Vector(Some(ack), peerEffect).flatten ++
          Vector(GuardEffect.PersistSnapshot(next))
      )
    } else {
      val b = new Builder(state.copy(lastInboundAtNanos = Some(message.receivedAtNanos)))
      routeBySequence(b, message)
      // If the Logon was accepted contiguously, handleAdmin has already emitted LogonAck.
      b.finish()
    }
  }

  private def logonAckFields(request: FixMessage, nextExpectedInbound: Long): Vector[FixField] = {
    val heartbeat = request.value(Tags.HeartBtInt).getOrElse("30")
    Vector(
      FixField(Tags.HeartBtInt, heartbeat),
      FixField(Tags.NextExpectedMsgSeqNum, nextExpectedInbound.toString)
    )
  }

  private def routeBySequence(b: Builder, message: FixMessage): Unit = {
    val expected = b.state.inboundExpected
    if (message.seqNum <= 0) {
      fence(b, "INVALID_SEQUENCE", s"non-positive seq ${message.seqNum}", Some(message.seqNum), message.receivedAtNanos)
      return
    }

    if (b.state.phase == Phase.AwaitingLogon &&
        message.msgType != MsgTypes.Logon &&
        message.msgType != MsgTypes.Logout) {
      fence(b, "NOT_LOGGED_ON", s"msgType=${message.msgType}", Some(message.seqNum), message.receivedAtNanos)
      return
    }

    if (message.seqNum < expected) {
      handleLowSequence(b, message)
    } else if (message.seqNum > expected) {
      handleFutureSequence(b, message)
    } else {
      acceptContiguous(b, message)
      drainPending(b)
    }
  }

  private def handleLowSequence(b: Builder, message: FixMessage): Unit = {
    b.state.history.get(message.seqNum) match {
      case Some(original) =>
        val hash = MessageFingerprint.businessHash(message, config.authTag)
        if (hash != original.hash) {
          fence(
            b,
            "SAME_SEQUENCE_CONTENT_COLLISION",
            s"seq=${message.seqNum} originalHash=${original.hash} replayedHash=$hash; " +
              "possible price/order mutation or session hijack",
            Some(message.seqNum),
            message.receivedAtNanos
          )
          return
        }

        b.suppressed += message

        if (!message.retransmissionMarked) {
          val count = b.state.unflaggedReplays + 1
          b.state = b.state.copy(unflaggedReplays = count)
          b.raise(securityEvent(
            "UNFLAGGED_REPLAY",
            Severity.Warning,
            message.receivedAtNanos,
            Some(message.seqNum),
            "same content at already-processed sequence without PossDupFlag/PossResend"
          ))
          if (count >= config.fenceOnUnflaggedReplayAfter) {
            fence(
              b,
              "REPEATED_UNFLAGGED_REPLAY",
              s"$count unflagged replays observed",
              Some(message.seqNum),
              message.receivedAtNanos
            )
            return
          }
        } else {
          b.raise(securityEvent(
            "LEGAL_RETRANSMISSION_SUPPRESSED",
            Severity.Info,
            message.receivedAtNanos,
            Some(message.seqNum),
            "duplicate sequence and identical business fingerprint; not delivered to orders"
          ))
        }

        reanswerIdempotentAdmin(b, message)

      case None =>
        val event = securityEvent(
          "UNVERIFIABLE_LOW_SEQUENCE",
          Severity.Warning,
          message.receivedAtNanos,
          Some(message.seqNum),
          "sequence is below durable high-water but fingerprint is unavailable; suppressing as duplicate"
        )
        b.raise(event)
        b.emit(GuardEffect.RequireReconciliation(
          "UNVERIFIABLE_LOW_SEQUENCE",
          s"seq=${message.seqNum} must not be applied as a new request; verify ClOrdID/ExecID in ledger"
        ))
        if (config.fenceOnUnverifiableLowSeq) {
          fence(b, "UNVERIFIABLE_LOW_SEQUENCE_FENCED", "fingerprint history unavailable", Some(message.seqNum), message.receivedAtNanos)
        }
    }
  }

  private def handleFutureSequence(b: Builder, message: FixMessage): Unit = {
    val expected = b.state.inboundExpected
    val jump = message.seqNum - expected
    if (jump > config.maxSequenceJump) {
      fence(
        b,
        "SEQUENCE_JUMP_TOO_LARGE",
        s"seq=${message.seqNum} expected=$expected jump=$jump limit=${config.maxSequenceJump}",
        Some(message.seqNum),
        message.receivedAtNanos
      )
      return
    }

    b.state.pending.get(message.seqNum) match {
      case Some(existing) =>
        val oldHash = MessageFingerprint.businessHash(existing, config.authTag)
        val newHash = MessageFingerprint.businessHash(message, config.authTag)
        if (oldHash != newHash) {
          fence(
            b,
            "BUFFERED_SEQUENCE_CONTENT_COLLISION",
            s"two different frames claim future seq=${message.seqNum}",
            Some(message.seqNum),
            message.receivedAtNanos
          )
          return
        }
        b.raise(securityEvent(
          "DUPLICATE_OUT_OF_ORDER_FRAME",
          Severity.Info,
          message.receivedAtNanos,
          Some(message.seqNum),
          "duplicate frame already present in bounded replay buffer"
        ))
        return
      case None if b.state.pending.size >= config.maxBufferedOutOfOrder =>
        fence(
          b,
          "OUT_OF_ORDER_BUFFER_OVERFLOW",
          s"buffered=${b.state.pending.size} limit=${config.maxBufferedOutOfOrder}",
          Some(message.seqNum),
          message.receivedAtNanos
        )
        return
      case None =>
        b.state = b.state.copy(pending = b.state.pending.updated(message.seqNum, message))
    }

    // An in-flight request already covers the current hole; do not amplify it for every frame.
    val coveredByActiveRequest = b.state.resend.exists { r =>
      b.state.inboundExpected >= r.beginSeq && b.state.inboundExpected <= r.endSeq
    }
    if (coveredByActiveRequest) {
      if (b.state.phase != Phase.Resending) b.state = b.state.copy(phase = Phase.Resending)
      return
    }

    val end = message.seqNum - 1L
    val resend = ResendState(
      beginSeq = expected,
      endSeq = end,
      attempt = 1,
      requestedAtNanos = message.receivedAtNanos,
      lastRequestAtNanos = message.receivedAtNanos
    )
    b.state = b.state.copy(phase = Phase.Resending, resend = Some(resend))
    b.emit(GuardEffect.SendAdmin(
      MsgTypes.ResendRequest,
      Vector(FixField(Tags.BeginSeqNo, expected.toString), FixField(Tags.EndSeqNo, end.toString))
    ))
    b.emit(GuardEffect.ScheduleResendTimeout(config.resendTimeoutNanos, 1))
    persist(b)
  }

  private def rememberHistory(b: Builder, seq: Long, record: FingerprintRecord): Unit = {
    val withRecord = b.state.history.updated(seq, record)
    val order = if (b.state.history.contains(seq)) b.state.historyOrder else b.state.historyOrder :+ seq
    val overflow = order.size - config.fingerprintRetention
    val (evictedOrder, evicted) =
      if (overflow <= 0) (order, Vector.empty[Long])
      else {
        val old = order.take(overflow)
        (order.drop(overflow), old)
      }
    val evictedHistory = evicted.foldLeft(withRecord) { (h, s) => h - s }
    b.state = b.state.copy(history = evictedHistory, historyOrder = evictedOrder)
  }

  private def acceptContiguous(b: Builder, message: FixMessage): Unit = {
    if (message.msgType == MsgTypes.SequenceReset) {
      acceptSequenceReset(b, message)
      return
    }

    val hash = MessageFingerprint.businessHash(message, config.authTag)
    rememberHistory(
      b,
      message.seqNum,
      FingerprintRecord(
        hash = hash,
        msgType = message.msgType,
        originalSendingTime = message.origSendingTime.orElse(message.sendingTime),
        channelId = message.channelId,
        atNanos = message.receivedAtNanos
      )
    )

    b.state = b.state.copy(inboundExpected = message.seqNum + 1L)
    clearCompletedResend(b)
    handleAdminAndDelivery(b, message)
    persist(b)
  }

  private def clearCompletedResend(b: Builder): Unit = {
    b.state.resend match {
      case Some(r) if b.state.inboundExpected > r.endSeq =>
        b.state = b.state.copy(resend = None, phase = Phase.Active)
      case Some(_) =>
        b.state = b.state.copy(phase = Phase.Resending)
      case None if b.state.phase == Phase.Resending =>
        b.state = b.state.copy(phase = Phase.Active)
      case None =>
    }
  }

  private def acceptSequenceReset(b: Builder, message: FixMessage): Unit = {
    message.long(Tags.NewSeqNo) match {
      case None =>
        fence(b, "MALFORMED_SEQUENCE_RESET", "SequenceReset lacks numeric NewSeqNo", Some(message.seqNum), message.receivedAtNanos)
      case Some(newSeq) if newSeq <= 0 =>
        fence(b, "MALFORMED_SEQUENCE_RESET", s"non-positive NewSeqNo=$newSeq", Some(message.seqNum), message.receivedAtNanos)
      case Some(newSeq) if !message.boolean(Tags.GapFillFlag) =>
        fence(
          b,
          "UNAUTHORIZED_PLAIN_SEQUENCE_RESET",
          s"GapFillFlag!=Y NewSeqNo=$newSeq; mid-session resets require control-plane recovery and fresh Logon",
          Some(message.seqNum),
          message.receivedAtNanos
        )
      case Some(newSeq) if newSeq <= message.seqNum =>
        fence(
          b,
          "INVALID_GAP_FILL",
          s"NewSeqNo=$newSeq must be greater than SequenceReset MsgSeqNum=${message.seqNum}",
          Some(message.seqNum),
          message.receivedAtNanos
        )
      case Some(newSeq) =>
        val skippedFrom = message.seqNum + 1L
        val skippedTo = newSeq - 1L
        val activeResendOk = !config.requireActiveResendForGapFill ||
          b.state.resend.exists(r => message.seqNum >= r.beginSeq && message.seqNum <= r.endSeq + 1)

        if (!activeResendOk) {
          fence(
            b,
            "UNSOLICITED_GAP_FILL",
            s"gap fill seq=${message.seqNum}->$newSeq does not correspond to an active ResendRequest",
            Some(message.seqNum),
            message.receivedAtNanos
          )
          return
        }

        if (skippedTo - skippedFrom + 1L > config.maxAutomaticGapFill) {
          b.emit(GuardEffect.RequireReconciliation(
            "LARGE_GAP_FILL",
            s"refusing automatic skip of ${skippedTo - skippedFrom + 1} sequences; obtain signed checkpoint/reconciliation"
          ))
          fence(
            b,
            "GAP_FILL_TOO_LARGE",
            s"skipped=${skippedTo - skippedFrom + 1} limit=${config.maxAutomaticGapFill}",
            Some(message.seqNum),
            message.receivedAtNanos
          )
          return
        }

        val conflict = b.state.pending.keys.exists(seq => seq >= skippedFrom && seq <= skippedTo)
        if (conflict) {
          fence(
            b,
            "GAP_FILL_CONFLICTS_WITH_BUFFERED_FRAME",
            s"peer claims $skippedFrom..$skippedTo are skippable but we received a frame in that range",
            Some(message.seqNum),
            message.receivedAtNanos
          )
          return
        }

        val hash = MessageFingerprint.businessHash(message, config.authTag)
        rememberHistory(
          b,
          message.seqNum,
          FingerprintRecord(hash, message.msgType, message.sendingTime, message.channelId, message.receivedAtNanos)
        )
        val audit = GapFillRange(
          resetSeq = message.seqNum,
          fromSeqInclusive = skippedFrom,
          toSeqInclusive = skippedTo,
          newSeq = newSeq,
          atNanos = message.receivedAtNanos,
          epoch = b.state.epoch
        )
        b.state = b.state.copy(
          inboundExpected = newSeq,
          gapFillAudit = (b.state.gapFillAudit :+ audit).takeRight(100)
        )
        b.raise(securityEvent(
          "GAP_FILL_APPLIED",
          Severity.Warning,
          message.receivedAtNanos,
          Some(message.seqNum),
          s"advanced to $newSeq; range ${audit.fromSeqInclusive}..${audit.toSeqInclusive} recorded for reconciliation"
        ))
        clearCompletedResend(b)
        persist(b)
    }
  }

  @annotation.tailrec
  private def drainPending(b: Builder): Unit = {
    // An admin handler may fence the session after its own sequence was accepted; never drain
    // additional business frames in the same call once that happens.
    if (b.state.phase == Phase.Fenced || b.state.phase == Phase.Stalled) return
    val expected = b.state.inboundExpected
    b.state.pending.get(expected) match {
      case Some(nextMessage) =>
        b.state = b.state.copy(pending = b.state.pending - expected)
        acceptContiguous(b, nextMessage)
        drainPending(b)
      case None =>
    }
  }

  private def handleAdminAndDelivery(b: Builder, message: FixMessage): Unit = {
    message.msgType match {
      case MsgTypes.Logon =>
        message.long(Tags.NextExpectedMsgSeqNum) match {
          case Some(n) if n > b.state.outboundNext =>
            fence(
              b,
              "LOGON_789_BEYOND_OUTBOUND_HIGH_WATER",
              s"peer Logon reports NextExpectedMsgSeqNum=$n but local outboundNext=${b.state.outboundNext}",
              Some(message.seqNum),
              message.receivedAtNanos
            )
          case maybeExpected =>
            b.state = b.state.copy(phase = Phase.Active, peerExpectedOutbound = maybeExpected)
            b.emit(GuardEffect.SendAdmin(
              MsgTypes.Logon,
              logonAckFields(message, b.state.inboundExpected)
            ))
            maybeExpected.foreach(n => b.emit(GuardEffect.PeerExpectedOutboundChanged(n)))
        }

      case MsgTypes.Heartbeat =>
      // Liveness is handled by the runtime's timer; no business delivery.

      case MsgTypes.TestRequest =>
        val testReqId = message.value(Tags.TestReqID).getOrElse("ping")
        b.emit(GuardEffect.SendAdmin(
          MsgTypes.Heartbeat,
          Vector(FixField(Tags.TestReqID, testReqId))
        ))

      case MsgTypes.ResendRequest =>
        handleResendRequest(b, message)

      case MsgTypes.Logout =>
        b.emit(GuardEffect.SendAdmin(
          MsgTypes.Logout,
          message.value(58).map(v => Vector(FixField(58, v))).getOrElse(Vector.empty)
        ))
        b.state = b.state.copy(phase = Phase.Offline, activeChannelId = None)
        b.emit(GuardEffect.CloseChannel(message.channelId, "LOGOUT"))

      case MsgTypes.Reject | MsgTypes.BusinessMessageReject =>
        // The order gateway must see session/business rejects and reconcile client requests.
        b.delivered += message

      case other if MsgTypes.isSessionAdmin(other) =>
      // Other admin messages are consumed by the session layer.

      case _ =>
        b.delivered += message
    }
  }

  /**
   * A duplicated admin request may mean our previous idempotent response was lost during a
   * failover. Re-answer it from state/journal without advancing inbound sequence or routing it.
   */
  private def reanswerIdempotentAdmin(b: Builder, message: FixMessage): Unit = {
    message.msgType match {
      case MsgTypes.TestRequest =>
        val testReqId = message.value(Tags.TestReqID).getOrElse("ping")
        b.emit(GuardEffect.SendAdmin(
          MsgTypes.Heartbeat,
          Vector(FixField(Tags.TestReqID, testReqId))
        ))
      case MsgTypes.ResendRequest =>
        message.long(Tags.BeginSeqNo).foreach { begin =>
          val end = message.long(Tags.EndSeqNo).getOrElse(0L)
          val valid = begin >= 1L && begin <= b.state.outboundNext && (end == 0L || end >= begin)
          if (valid) b.emit(GuardEffect.ServeOutboundResend(begin, end, message.seqNum))
        }
      case _ =>
    }
  }

  private def handleResendRequest(b: Builder, message: FixMessage): Unit = {
    val now = message.receivedAtNanos
    val windowStart = now - config.resendRequestWindowNanos
    val recent = b.state.inboundResendRequestTimes.filter(_ >= windowStart) :+ now
    b.state = b.state.copy(inboundResendRequestTimes = recent)
    if (recent.size > config.maxInboundResendRequestsPerWindow) {
      fence(
        b,
        "RESEND_REQUEST_FLOOD",
        s"${recent.size} resend requests within window; possible abuse/desynchronization loop",
        Some(message.seqNum),
        now
      )
      return
    }

    message.long(Tags.BeginSeqNo) match {
      case None =>
        b.emit(GuardEffect.SendAdmin(
          MsgTypes.Reject,
          Vector(FixField(Tags.RefSeqNo, message.seqNum.toString), FixField(58, "ResendRequest missing BeginSeqNo"))
        ))
      case Some(begin) if begin < 1 =>
        fence(b, "INVALID_RESEND_RANGE", s"BeginSeqNo=$begin", Some(message.seqNum), now)
      case Some(begin) if begin > b.state.outboundNext =>
        fence(
          b,
          "RESEND_BEYOND_OUTBOUND_HIGH_WATER",
          s"peer requests begin=$begin but next outbound seq=${b.state.outboundNext}",
          Some(message.seqNum),
          now
        )
      case Some(begin) =>
        val end = message.long(Tags.EndSeqNo).getOrElse(0L)
        if (end != 0L && end < begin) {
          fence(b, "INVALID_RESEND_RANGE", s"begin=$begin end=$end", Some(message.seqNum), now)
        } else {
          b.emit(GuardEffect.ServeOutboundResend(begin, end, message.seqNum))
        }
    }
  }

  def onResendTimeout(state: GuardState, nowNanos: Long): GuardResult = {
    // Timers from a dead/not-yet-logged-on transport must not write through a stale channel.
    // Reconnect clears resend state and starts a fresh bounded request.
    if (state.phase == Phase.Offline ||
        state.phase == Phase.AwaitingLogon ||
        state.phase == Phase.Stalled ||
        state.phase == Phase.Fenced) {
      return GuardResult(state)
    }

    state.resend match {
      case None => GuardResult(state)
      case Some(r) if nowNanos - r.lastRequestAtNanos < config.resendTimeoutNanos =>
        GuardResult(state)
      case Some(r) if r.attempt >= config.maxResendAttempts =>
        val event = securityEvent(
          "RESEND_EXHAUSTED",
          Severity.Critical,
          nowNanos,
          Some(r.beginSeq),
          s"missing ${r.beginSeq}..${r.endSeq} after ${r.attempt} attempts; close/reconnect and reconcile, never reset silently"
        )
        val next = state.copy(phase = Phase.Stalled, activeChannelId = None)
        val closeEffect = state.activeChannelId
          .map(id => GuardEffect.CloseChannel(id, "RESEND_EXHAUSTED"))
          .toVector
        GuardResult(
          next,
          alerts = Vector(event),
          effects = closeEffect ++ Vector(
            GuardEffect.RequireReconciliation(
              "RESEND_EXHAUSTED",
              s"missing inbound sequence range ${r.beginSeq}..${r.endSeq}"
            ),
            GuardEffect.PersistSnapshot(next)
          )
        )
      case Some(r) =>
        val nextResend = r.copy(attempt = r.attempt + 1, lastRequestAtNanos = nowNanos)
        val next = state.copy(resend = Some(nextResend), phase = Phase.Resending)
        GuardResult(
          next,
          effects = Vector(
            GuardEffect.SendAdmin(
              MsgTypes.ResendRequest,
              Vector(
                FixField(Tags.BeginSeqNo, r.beginSeq.toString),
                FixField(Tags.EndSeqNo, r.endSeq.toString)
              )
            ),
            GuardEffect.ScheduleResendTimeout(config.resendTimeoutNanos, nextResend.attempt),
            GuardEffect.PersistSnapshot(next)
          )
        )
    }
  }

  /** Authenticated control-plane recovery. Production callers must verify the approval signature. */
  def authorizeForceReset(
      state: GuardState,
      approval: ResetAuthorization,
      newInboundExpected: Long,
      newOutboundNext: Long,
      nowNanos: Long
  ): GuardResult = {
    if (!approval.validAt(nowNanos)) {
      val event = securityEvent(
        "INVALID_RESET_AUTHORIZATION",
        Severity.Critical,
        nowNanos,
        None,
        "reset approval is missing fields, expired, or failed signature verification"
      )
      return GuardResult(state, alerts = Vector(event))
    }
    if (state.consumedResetNonces.contains(approval.nonce)) {
      return GuardResult(
        state,
        alerts = Vector(securityEvent(
          "RESET_AUTHORIZATION_REPLAY",
          Severity.Critical,
          nowNanos,
          None,
          s"reset nonce ${approval.nonce} has already been consumed"
        ))
      )
    }
    if (newInboundExpected < 1 || newOutboundNext < 1) {
      return GuardResult(
        state,
        alerts = Vector(securityEvent("INVALID_RESET_SEQUENCE", Severity.Critical, nowNanos, None, "sequences must be positive"))
      )
    }
    if (state.phase != Phase.Fenced && state.phase != Phase.Stalled && state.phase != Phase.Offline) {
      return GuardResult(
        state,
        alerts = Vector(securityEvent(
          "RESET_REJECTED_ACTIVE_SESSION",
          Severity.Critical,
          nowNanos,
          None,
          "force reset is only allowed from Fenced/Stalled/Offline; use ordered logout for healthy sessions"
        ))
      )
    }

    val next = state.copy(
      phase = Phase.Offline,
      epoch = state.epoch + 1,
      inboundExpected = newInboundExpected,
      outboundNext = newOutboundNext,
      activeChannelId = None,
      pending = SortedMap.empty,
      history = Map.empty,
      historyOrder = Vector.empty,
      resend = None,
      unflaggedReplays = 0,
      consumedResetNonces = state.consumedResetNonces + approval.nonce,
      closedReason = Some(s"authorized:${approval.ticket}")
    )
    val event = securityEvent(
      "FORCE_RESET_AUTHORIZED",
      Severity.Warning,
      nowNanos,
      None,
      s"approver=${approval.approver} ticket=${approval.ticket}; inboundExpected=$newInboundExpected outboundNext=$newOutboundNext"
    )
    GuardResult(next, alerts = Vector(event), effects = Vector(GuardEffect.PersistSnapshot(next)))
  }

  /** Update outbound high-water after durable journal append. */
  def outboundAssigned(state: GuardState, seq: Long): GuardState =
    state.copy(outboundNext = math.max(state.outboundNext, seq + 1L))

  /**
   * Record an authenticated peer's 789 NextExpectedMsgSeqNum. This proves session-layer receipt
   * only; it must never be used alone to mark an order/report as business-accepted.
   */
  def notePeerExpectedOutbound(state: GuardState, nextExpected: Long, atNanos: Long): GuardResult = {
    if (nextExpected > state.outboundNext) {
      val b = new Builder(state)
      fence(
        b,
        "PEER_EXPECTS_UNSENT_OUTBOUND_SEQ",
        s"peer reports 789=$nextExpected but local outboundNext=${state.outboundNext}; possible desync or injected acknowledgement",
        None,
        atNanos
      )
    } else {
      val next = state.copy(peerExpectedOutbound = Some(nextExpected))
      GuardResult(
        next,
        effects = Vector(GuardEffect.PeerExpectedOutboundChanged(nextExpected), GuardEffect.PersistSnapshot(next))
      )
    }
  }
}
