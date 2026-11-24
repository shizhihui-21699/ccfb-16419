package com.broker.fixguard

/**
 * Runnable, network-free walkthrough of the safe path and an attack/fence/recovery path.
 *
 * Run with: sbt runMain com.broker.fixguard.Demo
 */
object Demo {
  private val session = SessionKey("BROKER", "HEDGE_A")
  private val identity = "spki:hedge-a-pinned-certificate"

  private final class CountingBusinessSink extends BusinessDeduplicationSink {
    @volatile var firstSeen = 0
    @volatile var duplicates = 0
    @volatile var conflicts = 0

    override def onFirstSeen(message: FixMessage, record: InboundRequestRecord): Unit = {
      firstSeen += 1
      println(s"  [order-gateway] first seen seq=${message.seqNum} clOrdId=${record.key.clOrdId} -> route once")
    }

    override def onDuplicate(message: FixMessage, record: InboundRequestRecord): Unit = {
      duplicates += 1
      println(s"  [order-gateway] duplicate seq=${message.seqNum} clOrdId=${record.key.clOrdId} -> do not route again")
    }

    override def onConflict(message: FixMessage, outcome: LedgerOutcome.ConflictingRequest): Unit = {
      conflicts += 1
      println(s"  [order-gateway] CONFLICT clOrdId=${outcome.existing.key.clOrdId}; reject and investigate")
    }
  }

  def main(args: Array[String]): Unit = {
    val guard = new SequenceGuard(GuardConfig(
      session = session,
      expectedTlsIdentity = Some(identity),
      requireTlsIdentity = true,
      resendTimeoutNanos = 5_000_000_000L
    ))
    val ledger = new InMemoryInboundRequestLedger(session)
    val journal = new InMemoryOutboundJournal(startNextSeq = 1L)
    val transport = new RecordingSessionTransport
    val sink = new CountingBusinessSink
    val runtime = new SessionRuntime(guard, ledger, journal, transport, AllowAllAuthenticator, sink)

    println("1) mTLS-bound connect and Logon")
    runtime.open(ChannelBinding("tcp-1", "10.20.0.8:51001", Some(identity), 1L))
    runtime.receive(logon(seq = 1, channel = "tcp-1", at = 2L))
    println(s"  phase=${runtime.state.phase}, inboundExpected=${runtime.state.inboundExpected}")

    println("2) genuine order and durable ExecutionReport")
    runtime.receive(order(seq = 2, price = "100.25", channel = "tcp-1", at = 3L))
    val report = runtime.sendBusinessMessage(
      MsgTypes.ExecutionReport,
      clOrdId = Some("ORD-1"),
      execId = Some("EXEC-1"),
      fields = Vector(
        FixField(Tags.ClOrdID, "ORD-1"),
        FixField(Tags.ExecID, "EXEC-1"),
        FixField(Tags.OrderID, "BROKER-O-1"),
        FixField(Tags.ExecType, "0"),
        FixField(Tags.SendingTime, "20261125-01:00:00.000")
      )
    )

    println("3) millisecond network blip: same certificate reconnects and replays seq=2")
    runtime.channelClosed("tcp-1", "tcp-reset")
    runtime.open(ChannelBinding("tcp-2", "10.20.0.8:51002", Some(identity), 10L))
    runtime.receive(logon(seq = 3, nextExpectedOutbound = 2, channel = "tcp-2", at = 11L))
    runtime.receive(order(seq = 2, price = "100.25", duplicate = true, channel = "tcp-2", at = 12L))
    println(s"  phase=${runtime.state.phase}, routed=${sink.firstSeen}, ledgerDuplicates=${sink.duplicates}")

    println("4) attacker injects a different price at the next sequence")
    runtime.receive(order(seq = 4, price = "100.25", channel = "tcp-2", at = 13L))
    val attack = runtime.receive(order(seq = 4, price = "0.01", channel = "tcp-2", at = 14L))
    println(s"  phase=${attack.state.phase}, alerts=${attack.alerts.map(_.code).mkString(",")}")
    println(s"  transport closed=${transport.closed.lastOption}")

    println("5) while fenced, even a new channel claiming another identity is refused")
    val fakeOpen = runtime.guard.channelOpened(
      runtime.state,
      ChannelBinding("tcp-evil", "203.0.113.9:443", Some("spki:attacker"), 15L)
    )
    println(s"  fake phase=${fakeOpen.state.phase}, alert=${fakeOpen.alerts.headOption.map(_.code)}")

    println("6) out-of-band approved recovery, then authenticated Logon at sequence 1")
    val approval = ResetAuthorization(
      approver = "oncall-lead",
      ticket = "OPS-7781",
      nonce = "vault-signed-nonce",
      expiresAtNanos = 1_000L
    )
    val recovered = guard.authorizeForceReset(
      runtime.state,
      approval,
      newInboundExpected = 1L,
      newOutboundNext = journal.nextSeq,
      nowNanos = 20L
    )
    runtime.restore(recovered.state)
    runtime.open(ChannelBinding("tcp-dr", "10.20.0.8:51003", Some(identity), 21L))
    runtime.receive(logon(seq = 1, channel = "tcp-dr", at = 22L))
    println(s"  phase=${runtime.state.phase}, epoch=${runtime.state.epoch}, inboundExpected=${runtime.state.inboundExpected}")

    println("7) outbound receipt distinction")
    journal.markPeerExpected(journal.nextSeq)
    println(s"  EXEC-1 seq=${report.seq} state=${journal.get(report.seq).map(_.deliveryState.name)} (session ack only)")
    journal.markBusinessConfirmedByExecId("EXEC-1")
    println(s"  EXEC-1 seq=${report.seq} state=${journal.get(report.seq).map(_.deliveryState.name)} after reconciliation")

    println(s"Demo complete: firstSeen=${sink.firstSeen}, duplicates=${sink.duplicates}, conflicts=${sink.conflicts}")
  }

  private def logon(
      seq: Long,
      nextExpectedOutbound: Long = 1L,
      channel: String,
      at: Long
  ): FixMessage = FixMessage(
    seq,
    MsgTypes.Logon,
    session,
    channel,
    at,
    Vector(
      FixField(Tags.HeartBtInt, "1"),
      FixField(Tags.NextExpectedMsgSeqNum, nextExpectedOutbound.toString)
    )
  )

  private def order(
      seq: Long,
      price: String,
      channel: String,
      at: Long,
      duplicate: Boolean = false
  ): FixMessage = {
    val dup =
      if (duplicate) Vector(FixField(Tags.PossDupFlag, "Y"), FixField(Tags.OrigSendingTime, "20261125-01:00:00.000"))
      else Vector.empty
    FixMessage(
      seq,
      MsgTypes.NewOrderSingle,
      session,
      channel,
      at,
      Vector(
        FixField(Tags.ClOrdID, s"ORD-$seq"),
        FixField(Tags.Side, "1"),
        FixField(Tags.OrderQty, "10"),
        FixField(Tags.Price, price),
        FixField(Tags.SendingTime, "20261125-01:00:00.000")
      ) ++ dup
    )
  }
}
