# FIXGuard — 会话层序列号异常与会话劫持防护（Scala）

面向券商与机构客户之间的 FIX 长连接，提供一个**单会话、单写者、纯状态机**的序列号异常识别、会话劫持熔断和安全恢复参考实现。

> 重要前提：FIX 的 `MsgSeqNum(34)` 和 `CheckSum(10)` 只能发现丢包/损坏，**不是身份认证或完整性保护**。能够在网络中间注入报文的攻击者可以重算校验和，也可以利用 `ResendRequest(2)`、`SequenceReset(4)`、`ResetSeqNumFlag(141)`、`NextExpectedMsgSeqNum(789)` 制造错位。生产环境必须同时使用：
>
> 1. **双向 TLS / 专线 + 证书 SPKI 固定或机构身份白名单**；
> 2. 建议增加**每会话 HMAC/签名**（本项目给出参考实现）；
> 3. **业务层幂等账本**：入站用 `ClOrdID(11)` / `OrigClOrdID(41)` + 业务正文哈希，出站用 `ExecID(17)` + 出站序列号日志；
> 4. 序列号重置必须经过控制面授权，不能由一条网络报文自行触发。

## 运行

需要 JDK 17+ 和 sbt。

```bash
sbt test
sbt "runMain com.broker.fixguard.Demo"
```

测试不依赖 ScalaTest/JUnit，而是零外部依赖的 `SelfTest`，并在 `build.sbt` 中接到了 `sbt test`。当前覆盖：

- 正常 Logon 与 `789` 通告；
- 合法 `PossDupFlag=Y` 重传抑制和 `ClOrdID` 幂等；
- 同序列号、不同价格/正文的碰撞熔断；
- 序列号缺口、有界 `ResendRequest`、缓存排序和按序投递；
- 相同证书闪断重连、保留序列；
- 相同身份的第二条活连接接管并关闭旧连接，错误身份同时关闭新旧通道；
- 不同证书身份重连被拒绝；
- 未授权 `SequenceReset` 熔断及授权后恢复；
- 合法 GapFill，以及 GapFill 与已缓存报文冲突；
- Resend 超时重试、耗尽后 Stall/对账；
- 恶意 ResendRequest 频率限制和越界检测；
- 出站日志重发、`789` 仅表示会话层收到、业务确认需 `ExecID` 对账；
- HMAC 改价检测；
- 最小 FIX SOH 报文解析和校验和验证。

## 代码结构

| 文件 | 内容 |
|---|---|
| `Protocol.scala` | FIX 字段/消息模型、SOH 解析、校验和、规范正文哈希、HMAC 认证器 |
| `SequenceGuard.scala` | 核心不可变状态与纯状态机；所有序列号、GapFill、重置、劫持判定 |
| `Safety.scala` | 入站委托幂等账本、出站报告日志、重传视图、会话层 ACK 与业务确认分离 |
| `SessionRuntime.scala` | 将 Guard、账本、日志和传输 SPI 串起来的参考运行时 |
| `Demo.scala` | 无网络的攻击/熔断/恢复演示 |
| `SelfTest.scala` | 17 个场景自检 |

## 核心判定矩阵

对每个已通过通道认证和报文认证的会话：

| 情况 | 处理 |
|---|---|
| `seq == inboundExpected` | 计算业务正文指纹，保存指纹，推进序列；管理消息立即处理，委托消息交给业务幂等账本 |
| `seq > inboundExpected` | 有界缓存；只对当前缺口发一次 `ResendRequest(BeginSeqNo=expected, EndSeqNo=seq-1)`；缺口补齐后按序排空 |
| `seq < expected`，指纹相同且有 `43=Y/97=Y` | 判定为合法重传，**不再投递委托**，只做幂等记录 |
| `seq < expected`，指纹相同但没有重传标记 | 抑制并告警；重复多次后熔断，防止重放/异常客户端循环 |
| 同序列号但指纹不同 | `SAME_SEQUENCE_CONTENT_COLLISION`，立即 Fenced、关闭通道、高优告警和对账 |
| 新 TCP/TLS 身份与固定身份不同 | `CHANNEL_IDENTITY_MISMATCH`，拒绝并熔断 |
| Logon `141=Y` 或低序列号 Logon 要求重置 | 无控制面授权时 `UNAUTHORIZED_SEQUENCE_RESET` 并熔断 |
| `35=4, 123=N` 的普通序列号重置 | 默认不接受会话中自动重置，直接熔断；恢复走授权工单/控制面签名 |
| `35=4, 123=Y` GapFill | 必须匹配活动 ResendRequest；跳过范围不能与已缓存报文冲突；大范围 GapFill 需检查点/对账 |
| `35=2` ResendRequest | 频率窗口限制；`BeginSeqNo` 不得大于本端出站高水位；由持久化出站日志提供相同正文并置 `43=Y/122` |
| Logon `789` 超过本端 `outboundNext` | `PEER_EXPECTS_UNSENT_OUTBOUND_SEQ`，可能是错位或伪造 ACK，熔断 |
| Resend 超时 | 有界重试；耗尽后进入 `Stalled`，关连接、重连/对账，**绝不静默跳号或重置** |

## 推荐恢复流程

### 1. 普通网络闪断（最高频）

这是最常见路径，必须最快、最自动化：

1. TCP 断开后保留 `inboundExpected`、`outboundNext`、指纹历史、待排序缓存和出站日志；
2. 客户从相同 mTLS 身份重连；
3. 双方 Logon 携带持久化的 `789(NextExpectedMsgSeqNum)`；
4. 对缺口发送/服务 ResendRequest；
5. 重传报文必须保持原业务正文并设置 `43=Y`、`122=OrigSendingTime`；
6. Guard 按序列号排空缓存；
7. 业务账本再用 `ClOrdID + OrigClOrdID + 正文哈希` 做第二道幂等。

这条路径不重置序列号，也不需要人工介入。

### 2. Resend 拿不到缺口

不要用 `SequenceReset` 快速“恢复”。状态机会：

1. 按配置重试 ResendRequest；
2. 超过次数后进入 `Stalled`；
3. 关闭当前 socket；
4. 触发订单/成交对账：客户委托状态、交易所/柜台委托号、成交号、本端出站 `ExecID` 日志；
5. 确认缺口只是心跳/管理消息，或完成委托状态核对后，再决定 GapFill 或授权重置。

### 3. 疑似劫持或序列号碰撞

状态进入终态 `Fenced`：

- 关闭当前通道；
- 拒绝该 SessionKey 的任何新连接，即使来源声称是“重连”；
- 保留内存快照、指纹、待排序报文和安全事件；
- 触发安全事件、电话/IM 应急流程和双方对账；
- 只有经过控制面认证的 `ResetAuthorization(approver, ticket, nonce, expiry, signatureValid)` 才能执行 `authorizeForceReset`；
- 重置后 epoch 加一，清理不可信待排序状态，从持久化账本/日志恢复正确高水位，再接受新的认证 Logon。

日终正常重置也应走同一个**预授权、可审计、带 epoch**的流程，而不是信任网络中的 `141=Y` 或 `35=4`。

## 委托不丢、不重复成交的边界

序列号只能保证会话层字节缺口可被发现，不能单独保证业务 exactly-once。

### 入站委托

幂等键建议：

```text
SessionKey + MsgType + ClOrdID(11) + OrigClOrdID(41)
```

并保存业务字段的规范哈希：价格 `44`、数量 `38`、方向 `54`、合约、账户等。

- 相同键 + 相同哈希：返回首次处理结果，不再路由报盘；
- 相同键 + 不同哈希：业务冲突，拒绝并告警；这可能是客户端改单复用 ID、配置错误或攻击；
- 序列号重置后，序列号可能从 1 重新开始，但 `ClOrdID` 幂等仍能防止重复委托。

真正安全的实现应把“插入幂等记录 + 写入待报盘意图”放在同一个持久化事务/复制日志中，然后再异步报交易所。

### 出站回报

- 分配出站序列号前先 durable append 到 `OutboundJournal`；
- 网络写失败时保留同一序列号，重连后从日志重发；
- 重发保持原 `ExecID(17)` 和业务正文，增加 `43=Y/122`；
- 对端认证 Logon 中的 `789 <= outboundNext` 只能把序列号之前的报告标为 `PeerSequenceAcked`；若 `789` 落后于高水位，Runtime 会自动从持久化日志重发缺失后缀；
- 这只说明对端 FIX 会话层可能收到字节，**不说明其订单系统已处理回报**；
- 业务确认必须通过 `ExecID`、Order Status Request、日终文件或成交对账完成，并调用 `markBusinessConfirmedByExecId`。

## 性能与线程模型

- 每个 `SessionKey` 一个 actor/event-loop/单写者；不要让多线程同时改同一个 GuardState；
- Guard 本身没有阻塞 I/O，集合均有界；
- 缺口缓存使用不可变 `SortedMap`，查询/更新为 `O(log n)`；
- 指纹历史按条数淘汰，生产上建议从持久化账本读取更久的指纹，而不是只依赖内存；
- HMAC/SHA-256 通常是微秒级，不应成为毫秒交易路径的主要延迟；
- 真正的延迟关键是持久化。建议使用同机房低延迟复制日志或组提交，把序列号、幂等键和委托意图一起落盘；不要在序列号处理路径中同步调用多个外部系统；
- 不同机构会话彼此隔离，一个会话 Fenced 不影响其他几十条会话。

## 接入 Netty / MINA / QuickFIX 风格管道

核心不依赖具体网络框架。Netty 中典型接入方式：

```scala
// 1. TLS handshake 完成后，从证书得到 verifiedSpkiOrSubject
val binding = ChannelBinding(
  channelId = ctx.channel().id().asLongText(),
  remoteEndpoint = ctx.channel().remoteAddress().toString,
  tlsIdentity = Some(verifiedSpkiOrSubject),
  openedAtNanos = System.nanoTime()
)
runtime.open(binding)

// 2. 收到一个完整 FIX framing（处理好 TCP 粘包/半包）后
FixWire.parse(rawFix, channelId, System.nanoTime()) match {
  case Right(msg) => runtime.receive(msg) // Runtime 内调用 HmacMessageAuthenticator
  case Left(err)  => metrics.invalidFix(err.message); ctx.close()
}

// 3. Runtime 的 SessionTransport 实现里调用 ctx.writeAndFlush(...)
```

如果使用 QuickFIX/J，可保留其 framing 和标准字段解析，但应在自定义 `Application/fromAdmin/fromApp` 或 IoHandler 中接入同一套判定，并确保 QuickFIX/J 的内存序列号不是唯一事实源。

## 安全边界与诚实声明

本实现显著提高攻击门槛并能阻止大量错位/重放/重置攻击，但以下情况不能仅靠会话层彻底解决：

- 攻击者已经持有合法 mTLS 私钥或每会话 HMAC 密钥；
- 合法机构账号本身被入侵并签发内容合法但欺诈的委托；
- 第一条伪造报文在真实报文之前到达，且部署没有启用报文认证——状态机只能在后续指纹碰撞时 Fenced，已经路由的委托需要撤单/对账；
- 持久化实现错误或幂等键未与委托意图原子提交。

因此，高安全等级部署应在 mTLS 之上启用 HMAC/签名，并对关键改价、大额委托、异常重置增加独立风险控制。
