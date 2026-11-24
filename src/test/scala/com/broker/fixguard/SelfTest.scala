package com.broker.fixguard

import scala.collection.mutable.ListBuffer

object SelfTest {
  private val session = SessionKey(localCompId = "BROKER", remoteCompId = "CLIENT_A")
  private val pinnedIdentity = "spki:client-a-certificate-pin"

  private var passed = 0
  private val failures = ListBuffer.empty[String]

  def main(args: Array[String]): Unit = {
    run("accepts Logon and advertises next expected inbound sequence") {
      val g = newGuard()
      var s = g.initialState
      s = open(g, s).state
      val result = g.receive(s, logon(), AuthVerdict.Verified)
      s = result.state

      assert(s.phase == Phase.Active, s"expected Active, got ${s.phase}")
      assert(s.inboundExpected == 2L)
      val ack = result.effects.collectFirst {
        case GuardEffect.SendAdmin(MsgTypes.Logon, fields) => fields
      }.getOrElse(fail("missing Logon ack"))
      assert(ack.exists(f => f.tag == Tags.NextExpectedMsgSeqNum && f.value == "2"))
    }

    run("fences Logon whose 789 points beyond our durable outbound high-water") {
      val g = newGuard()
      val opened = open(g, g.initialState)
      val result = g.receive(
        opened.state,
        logon(seq = 1, nextExpectedOutbound = 99),
        AuthVerdict.Verified
      )
      assert(result.state.phase == Phase.Fenced)
      assert(result.alerts.exists(_.code == "LOGON_789_BEYOND_OUTBOUND_HIGH_WATER"))
      assert(!result.effects.exists {
        case GuardEffect.SendAdmin(MsgTypes.Logon, _) => true
        case _ => false
      })
    }

    run("suppresses a legal same-sequence retransmission and deduplicates by ClOrdID") {
      val g = newGuard()
      val ledger = new InMemoryInboundRequestLedger(session)
      var s = loggedOn(g)

      val original = order(2, price = "100.00")
      val first = g.receive(s, original, AuthVerdict.Verified)
      s = first.state
      assert(first.delivered.map(_.seqNum) == Vector(2L))

      val firstHash = MessageFingerprint.businessHash(original, g.config.authTag)
      assert(ledger.register(original, firstHash, original.receivedAtNanos).isInstanceOf[LedgerOutcome.FirstSeen])

      val duplicate = order(2, price = "100.00", duplicate = true)
      val second = g.receive(s, duplicate, AuthVerdict.Verified)
      s = second.state
      assert(second.delivered.isEmpty)
      assert(s.inboundExpected == 3L)
      assert(second.alerts.exists(_.code == "LEGAL_RETRANSMISSION_SUPPRESSED"))

      val duplicateHash = MessageFingerprint.businessHash(duplicate, g.config.authTag)
      ledger.register(duplicate, duplicateHash, duplicate.receivedAtNanos) match {
        case LedgerOutcome.DuplicateSameRequest(_) => // expected
        case other => fail(s"expected ledger duplicate, got $other")
      }

      val refreshedSendingTime = duplicate.copy(fields = duplicate.fields.map {
        case FixField(Tags.SendingTime, _) => FixField(Tags.SendingTime, "20261125-10:30:05.000")
        case other => other
      })
      val refreshedResult = g.receive(s, refreshedSendingTime, AuthVerdict.Verified)
      assert(refreshedResult.delivered.isEmpty)
      assert(refreshedResult.state.phase == Phase.Active)
    }

    run("fences same-sequence price mutation and reports business-key conflict") {
      val g = newGuard()
      val ledger = new InMemoryInboundRequestLedger(session)
      var s = loggedOn(g)

      val original = order(2, price = "100.00")
      s = g.receive(s, original, AuthVerdict.Verified).state
      ledger.register(original, MessageFingerprint.businessHash(original, None), 1)

      val forged = order(2, price = "0.01")
      val result = g.receive(s, forged, AuthVerdict.Verified)
      assert(result.state.phase == Phase.Fenced)
      assert(result.alerts.exists(_.code == "SAME_SEQUENCE_CONTENT_COLLISION"))
      assert(result.effects.exists(_.isInstanceOf[GuardEffect.CloseChannel]))

      ledger.register(forged, MessageFingerprint.businessHash(forged, None), 2) match {
        case LedgerOutcome.ConflictingRequest(_, _) => // expected
        case other => fail(s"expected business conflict, got $other")
      }
    }

    run("buffers future frames, sends one bounded ResendRequest, and drains in order") {
      val g = newGuard()
      var s = loggedOn(g)

      val future = g.receive(s, order(4), AuthVerdict.Verified)
      s = future.state
      assert(future.delivered.isEmpty)
      assert(s.phase == Phase.Resending)
      val rr = future.effects.collectFirst {
        case GuardEffect.SendAdmin(MsgTypes.ResendRequest, fields) => fields
      }.getOrElse(fail("missing ResendRequest"))
      assert(field(rr, Tags.BeginSeqNo).contains("2"))
      assert(field(rr, Tags.EndSeqNo).contains("3"))

      val two = g.receive(s, order(2), AuthVerdict.Verified)
      s = two.state
      assert(two.delivered.map(_.seqNum) == Vector(2L))

      val three = g.receive(s, order(3), AuthVerdict.Verified)
      s = three.state
      assert(three.delivered.map(_.seqNum) == Vector(3L, 4L))
      assert(s.phase == Phase.Active)
      assert(s.pending.isEmpty)
    }

    run("reconnect from same pinned identity retains sequence and accepts flagged replay") {
      val g = newGuard()
      var s = loggedOn(g)
      s = g.receive(s, order(2), AuthVerdict.Verified).state
      assert(s.inboundExpected == 3L)

      s = g.channelClosed(s, "ch-1", 20_000L, "tcp-rst").state
      assert(s.phase == Phase.Offline)
      assert(s.inboundExpected == 3L)

      val reopened = g.channelOpened(
        s,
        ChannelBinding("ch-2", "10.0.0.1:5201", Some(pinnedIdentity), 21_000L)
      )
      s = reopened.state
      assert(s.phase == Phase.AwaitingLogon)

      val logonResult = g.receive(s, logon(seq = 3, channel = "ch-2", at = 22_000L), AuthVerdict.Verified)
      s = logonResult.state
      assert(s.phase == Phase.Active)
      assert(s.inboundExpected == 4L)

      val replay = order(2, duplicate = true, channel = "ch-2", at = 23_000L)
      val replayResult = g.receive(s, replay, AuthVerdict.Verified)
      assert(replayResult.delivered.isEmpty)
      assert(replayResult.state.phase == Phase.Active)
    }

    run("rejects reconnect presenting a different certificate identity") {
      val g = newGuard()
      val s = loggedOn(g)
      val closed = g.channelClosed(s, "ch-1", 20_000L, "network blip").state
      val mismatch = g.channelOpened(
        closed,
        ChannelBinding("ch-evil", "198.51.100.7:4444", Some("spki:attacker"), 21_000L)
      )
      assert(mismatch.state.phase == Phase.Fenced)
      assert(mismatch.alerts.exists(_.code == "CHANNEL_IDENTITY_MISMATCH"))
      assert(mismatch.effects.exists {
        case GuardEffect.CloseChannel("ch-evil", _) => true
        case _ => false
      })
    }

    run("same identity replacement closes old channel; wrong identity closes both channels") {
      val g = newGuard()
      val active = loggedOn(g)

      val replacement = g.channelOpened(
        active,
        ChannelBinding("ch-2", "10.0.0.1:5202", Some(pinnedIdentity), 21_000L)
      )
      assert(replacement.state.phase == Phase.AwaitingLogon)
      assert(replacement.alerts.exists(_.code == "AUTHENTICATED_CHANNEL_SUPERSEDES_OLD"))
      assert(replacement.effects.exists {
        case GuardEffect.CloseChannel("ch-1", "SUPERSEDED_BY_NEW_CHANNEL") => true
        case _ => false
      })

      val attacker = g.channelOpened(
        active,
        ChannelBinding("ch-evil", "198.51.100.9:443", Some("spki:attacker"), 22_000L)
      )
      assert(attacker.state.phase == Phase.Fenced)
      assert(attacker.effects.exists {
        case GuardEffect.CloseChannel("ch-evil", "CHANNEL_IDENTITY_MISMATCH") => true
        case _ => false
      })
      assert(attacker.effects.exists {
        case GuardEffect.CloseChannel("ch-1", "IDENTITY_FAILURE_SUPERSEDED_CHANNEL") => true
        case _ => false
      })
    }

    run("fences unauthorized mid-session SequenceReset and recovers only after approval") {
      val g = newGuard()
      val active = loggedOn(g)
      val reset = sequenceReset(seq = 2, newSeq = 1, gapFill = false)
      val attacked = g.receive(active, reset, AuthVerdict.Verified)
      assert(attacked.state.phase == Phase.Fenced)
      assert(attacked.alerts.exists(_.code == "UNAUTHORIZED_PLAIN_SEQUENCE_RESET"))

      val expired = ResetAuthorization("alice", "CHG-1", "n1", expiresAtNanos = 10L)
      val denied = g.authorizeForceReset(attacked.state, expired, 1, 1, nowNanos = 100L)
      assert(denied.state.phase == Phase.Fenced)

      val approval = ResetAuthorization("alice", "CHG-42", "nonce-42", expiresAtNanos = 1_000_000L)
      val recovered = g.authorizeForceReset(attacked.state, approval, 1, 1, nowNanos = 100L)
      assert(recovered.state.phase == Phase.Offline)
      assert(recovered.state.epoch == attacked.state.epoch + 1L)
      assert(recovered.state.inboundExpected == 1L)

      val replayedApproval = g.authorizeForceReset(recovered.state, approval, 1, 1, nowNanos = 101L)
      assert(replayedApproval.alerts.exists(_.code == "RESET_AUTHORIZATION_REPLAY"))
      assert(replayedApproval.state.epoch == recovered.state.epoch)

      val opened = open(g, recovered.state, channel = "ch-dr", at = 200L)
      val logonResult = g.receive(
        opened.state,
        logon(seq = 1, channel = "ch-dr", at = 300L),
        AuthVerdict.Verified
      )
      assert(logonResult.state.phase == Phase.Active)
      assert(logonResult.state.inboundExpected == 2L)
    }

    run("accepts active-request GapFill but rejects GapFill that contradicts buffered frames") {
      val g = newGuard()
      var s = loggedOn(g)

      val future5 = g.receive(s, order(5), AuthVerdict.Verified)
      s = future5.state
      assert(s.resend.exists(r => r.beginSeq == 2L && r.endSeq == 4L))

      val gapFill = sequenceReset(seq = 2, newSeq = 5, gapFill = true)
      val applied = g.receive(s, gapFill, AuthVerdict.Verified)
      // NewSeqNo=5 makes seq 5 valid; the guard immediately drains the buffered order at seq 5.
      assert(applied.state.inboundExpected == 6L)
      assert(applied.delivered.map(_.seqNum) == Vector(5L))
      assert(applied.alerts.exists(_.code == "GAP_FILL_APPLIED"))
      s = applied.state

      // Now demonstrate the contradiction detector on a fresh session.
      val g2 = newGuard()
      var s2 = loggedOn(g2)
      s2 = g2.receive(s2, order(5), AuthVerdict.Verified).state
      s2 = g2.receive(s2, order(3), AuthVerdict.Verified).state
      val contradictory = g2.receive(s2, sequenceReset(2, 5, gapFill = true), AuthVerdict.Verified)
      assert(contradictory.state.phase == Phase.Fenced)
      assert(contradictory.alerts.exists(_.code == "GAP_FILL_CONFLICTS_WITH_BUFFERED_FRAME"))
    }

    run("retries ResendRequest then stalls/fences business progress without resetting sequence") {
      val g = newGuard(resendTimeoutNanos = 10L, maxResendAttempts = 2)
      var s = loggedOn(g)
      val gap = g.receive(s, order(4, at = 1_000L), AuthVerdict.Verified)
      s = gap.state

      val retry = g.onResendTimeout(s, 1_020L)
      assert(retry.state.resend.exists(_.attempt == 2))
      assert(retry.effects.count(_.isInstanceOf[GuardEffect.SendAdmin]) == 1)
      s = retry.state

      val exhausted = g.onResendTimeout(s, 1_040L)
      assert(exhausted.state.phase == Phase.Stalled)
      assert(exhausted.alerts.exists(_.code == "RESEND_EXHAUSTED"))
      assert(exhausted.effects.exists(_.isInstanceOf[GuardEffect.RequireReconciliation]))

      val reopened = open(g, exhausted.state, channel = "ch-2", at = 1_050L).state
      assert(reopened.resend.isEmpty)
      val reconnectLogon = g.receive(
        reopened,
        logon(seq = 5L, channel = "ch-2", at = 1_060L),
        AuthVerdict.Verified
      )
      assert(reconnectLogon.state.resend.exists(_.attempt == 1))
      assert(reconnectLogon.effects.collectFirst {
        case GuardEffect.SendAdmin(MsgTypes.ResendRequest, fields) => field(fields, Tags.BeginSeqNo)
      }.flatten.contains("2"))
    }

    run("duplicate ResendRequest is suppressed from business but answered again") {
      val g = newGuard()
      var s = loggedOn(g)
      s = g.outboundAssigned(s, 3L)

      val request = resendRequest(seq = 2L, begin = 1L, end = 0L, at = 10_000L)
      val first = g.receive(s, request, AuthVerdict.Verified)
      s = first.state
      assert(first.effects.exists(_.isInstanceOf[GuardEffect.ServeOutboundResend]))

      val duplicate = request.copy(fields = request.fields :+ FixField(Tags.PossDupFlag, "Y"))
      val repeated = g.receive(s, duplicate, AuthVerdict.Verified)
      assert(repeated.delivered.isEmpty)
      assert(repeated.state.phase == Phase.Active)
      assert(repeated.effects.exists(_.isInstanceOf[GuardEffect.ServeOutboundResend]))
    }

    run("rate-limits abusive inbound ResendRequest loops") {
      val g = newGuard(maxResendRequests = 3)
      var s = loggedOn(g)
      s = g.outboundAssigned(s, 10L)

      var last: GuardResult = null
      for (seq <- 2L to 5L) {
        val req = resendRequest(seq = seq, begin = 1, end = 0, at = 10_000L + seq)
        last = g.receive(s, req, AuthVerdict.Verified)
        s = last.state
      }
      assert(last.state.phase == Phase.Fenced)
      assert(last.alerts.exists(_.code == "RESEND_REQUEST_FLOOD"))
    }

    run("journal serves identical resends and sequence ack never implies business confirmation") {
      val journal = new InMemoryOutboundJournal(startNextSeq = 1L)
      val e1 = journal.append(
        MsgTypes.ExecutionReport,
        Vector(FixField(Tags.ExecID, "EXEC-1"), FixField(Tags.ClOrdID, "C-1"), FixField(Tags.Price, "100")),
        10L,
        clOrdId = Some("C-1"),
        execId = Some("EXEC-1")
      )
      val e2 = journal.append(
        MsgTypes.ExecutionReport,
        Vector(FixField(Tags.ExecID, "EXEC-2"), FixField(Tags.ClOrdID, "C-2")),
        20L,
        clOrdId = Some("C-2"),
        execId = Some("EXEC-2")
      )

      val served = journal.resend(1, 0)
      assert(served.map(_.seq) == Vector(e1.seq, e2.seq))
      val retransmitFields = RetransmissionView.fields(e1)
      assert(field(retransmitFields, Tags.PossDupFlag).contains("Y"))
      assert(retransmitFields.exists(_.tag == Tags.OrigSendingTime))

      journal.markPeerExpected(3L) match {
        case PeerAckResult.Accepted(acked) => assert(acked.map(_.seq) == Vector(1L, 2L))
        case other => fail(s"unexpected ack result $other")
      }
      assert(journal.get(1).exists(_.deliveryState == ReportDeliveryState.PeerSequenceAcked))
      assert(journal.get(1).exists(_.deliveryState != ReportDeliveryState.BusinessConfirmed))

      journal.markBusinessConfirmedByExecId("EXEC-1")
      assert(journal.get(1).exists(_.deliveryState == ReportDeliveryState.BusinessConfirmed))

      val g = newGuard()
      var s = loggedOn(g)
      s = g.outboundAssigned(s, 3L)
      val impossible = g.notePeerExpectedOutbound(s, 99L, 123L)
      assert(impossible.state.phase == Phase.Fenced)
      assert(impossible.alerts.exists(_.code == "PEER_EXPECTS_UNSENT_OUTBOUND_SEQ"))
    }

    run("HMAC detects price tampering before the order is delivered") {
      val key = "unit-test-session-key".getBytes("UTF-8")
      val hmac = new HmacMessageAuthenticator(session, key)
      val g = newGuard()
      val s = loggedOn(g)

      val unsigned = order(2, price = "100.00")
      val signed = unsigned.copy(fields = unsigned.fields :+ FixField(g.config.authTag.get, hmac.sign(unsigned.fields)))
      assert(hmac.verify(signed).verified)

      val tamperedFields = signed.fields.map {
        case FixField(Tags.Price, _) => FixField(Tags.Price, "0.01")
        case other => other
      }
      val tampered = signed.copy(fields = tamperedFields)
      assert(hmac.verify(tampered).isInstanceOf[AuthVerdict.Invalid])

      val result = g.receive(s, tampered, hmac.verify(tampered))
      assert(result.state.phase == Phase.Fenced)
      assert(result.alerts.exists(_.code == "MESSAGE_AUTH_FAILED"))
      assert(result.delivered.isEmpty)
    }

    run("runtime retransmits outbound suffix when Logon 789 is behind journal high-water") {
      val guard = newGuard()
      val transport = new RecordingSessionTransport
      val journal = new InMemoryOutboundJournal(startNextSeq = 1L)
      journal.append(MsgTypes.ExecutionReport, Vector(FixField(Tags.ExecID, "E1")), 1L, execId = Some("E1"))
      journal.append(MsgTypes.ExecutionReport, Vector(FixField(Tags.ExecID, "E2")), 2L, execId = Some("E2"))
      val runtime = new SessionRuntime(
        guard,
        new InMemoryInboundRequestLedger(session),
        journal,
        transport
      )

      runtime.open(ChannelBinding("ch-1", "10.0.0.1:1", Some(pinnedIdentity), 1L))
      runtime.receive(logon(seq = 1L, nextExpectedOutbound = 1L))

      val retransmitted = transport.sent.filter(_.retransmission).map(_.seq)
      assert(retransmitted == Vector(1L, 2L))
      assert(transport.sent.exists(f => !f.retransmission && f.msgType == MsgTypes.Logon && f.seq == 3L))
    }

    run("parses and checksum-validates a minimal FIX frame") {
      val soh = FixWire.Sofh
      val prefix =
        s"8=FIX.4.4${soh}9=5${soh}35=0${soh}34=1${soh}49=${session.remoteCompId}" +
          s"${soh}56=${session.localCompId}${soh}"
      val raw = prefix + s"10=${FixWire.checksum(prefix)}${soh}"
      FixWire.parse(raw, "ch-1", 1L) match {
        case Right(msg) =>
          assert(msg.seqNum == 1L)
          assert(msg.msgType == MsgTypes.Heartbeat)
        case Left(err) => fail(s"parse failed: ${err.message}")
      }
    }

    if (failures.nonEmpty) {
      failures.foreach(println)
      throw new AssertionError(s"${failures.size} self-test(s) failed")
    }
    println(s"com.broker.fixguard.SelfTest: $passed tests passed")
  }

  private def run(name: String)(body: => Unit): Unit = {
    try {
      body
      passed += 1
      println(s"PASS $name")
    } catch {
      case t: Throwable =>
        failures += s"FAIL $name: ${t.getClass.getSimpleName}: ${t.getMessage}"
        println(s"FAIL $name")
        t.printStackTrace()
    }
  }

  private def fail(message: String): Nothing = throw new AssertionError(message)

  private def field(fields: Seq[FixField], tag: Int): Option[String] =
    fields.collectFirst { case FixField(`tag`, value) => value }

  private def newGuard(
      maxReplay: Int = 3,
      maxResendRequests: Int = 20,
      resendTimeoutNanos: Long = 1_000_000_000L,
      maxResendAttempts: Int = 3
  ): SequenceGuard = {
    new SequenceGuard(GuardConfig(
      session = session,
      expectedTlsIdentity = Some(pinnedIdentity),
      requireTlsIdentity = true,
      allowIdentityOnFirstUse = false,
      fenceOnUnflaggedReplayAfter = maxReplay,
      maxInboundResendRequestsPerWindow = maxResendRequests,
      resendTimeoutNanos = resendTimeoutNanos,
      maxResendAttempts = maxResendAttempts
    ))
  }

  private def open(
      guard: SequenceGuard,
      state: GuardState,
      channel: String = "ch-1",
      tls: Option[String] = Some(pinnedIdentity),
      at: Long = 1_000L
  ): GuardResult = {
    guard.channelOpened(state, ChannelBinding(channel, "10.0.0.1:5100", tls, at))
  }

  private def loggedOn(guard: SequenceGuard): GuardState = {
    val opened = open(guard, guard.initialState)
    val result = guard.receive(opened.state, logon(), AuthVerdict.Verified)
    require(result.state.phase == Phase.Active, s"test setup failed: ${result.alerts.map(_.code)}")
    result.state
  }

  private def logon(
      seq: Long = 1L,
      reset: Boolean = false,
      nextExpectedOutbound: Long = 1L,
      channel: String = "ch-1",
      at: Long = 2_000L
  ): FixMessage = {
    val fields = Vector.newBuilder[FixField]
    fields += FixField(Tags.HeartBtInt, "10")
    fields += FixField(Tags.NextExpectedMsgSeqNum, nextExpectedOutbound.toString)
    if (reset) fields += FixField(Tags.ResetSeqNumFlag, "Y")
    FixMessage(seq, MsgTypes.Logon, session, channel, at, fields.result())
  }

  private def order(
      seq: Long,
      price: String = "100.00",
      clOrdId: String = "",
      duplicate: Boolean = false,
      channel: String = "ch-1",
      at: Long = 10_000L
  ): FixMessage = {
    val id = if (clOrdId.isEmpty) s"CLIENT-CLORD-$seq" else clOrdId
    val business = Vector(
      FixField(Tags.ClOrdID, id),
      FixField(Tags.Side, "1"),
      FixField(Tags.OrderQty, "100"),
      FixField(Tags.Price, price),
      FixField(Tags.SendingTime, "20261125-10:30:00.000")
    )
    val dupMetadata =
      if (duplicate)
        Vector(FixField(Tags.PossDupFlag, "Y"), FixField(Tags.OrigSendingTime, "20261125-10:30:00.000"))
      else Vector.empty
    FixMessage(seq, MsgTypes.NewOrderSingle, session, channel, at, business ++ dupMetadata)
  }

  private def sequenceReset(seq: Long, newSeq: Long, gapFill: Boolean): FixMessage = {
    val flag = if (gapFill) Vector(FixField(Tags.GapFillFlag, "Y")) else Vector.empty
    FixMessage(
      seq,
      MsgTypes.SequenceReset,
      session,
      "ch-1",
      11_000L,
      Vector(FixField(Tags.NewSeqNo, newSeq.toString)) ++ flag
    )
  }

  private def resendRequest(seq: Long, begin: Long, end: Long, at: Long): FixMessage = {
    FixMessage(
      seq,
      MsgTypes.ResendRequest,
      session,
      "ch-1",
      at,
      Vector(FixField(Tags.BeginSeqNo, begin.toString), FixField(Tags.EndSeqNo, end.toString))
    )
  }
}
