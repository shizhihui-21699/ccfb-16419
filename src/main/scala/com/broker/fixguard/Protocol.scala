package com.broker.fixguard

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.Try

/** Minimal FIX tag dictionary used by the session guard. */
object Tags {
  val BeginString = 8
  val BodyLength = 9
  val MsgType = 35
  val SenderCompID = 49
  val TargetCompID = 56
  val MsgSeqNum = 34
  val SendingTime = 52
  val OrigSendingTime = 122
  val PossDupFlag = 43
  val PossResend = 97
  val EncryptMethod = 98
  val HeartBtInt = 108
  val ResetSeqNumFlag = 141
  val NextExpectedMsgSeqNum = 789
  val BeginSeqNo = 7
  val EndSeqNo = 16
  val NewSeqNo = 36
  val RefSeqNo = 45
  val GapFillFlag = 123
  val TestReqID = 112
  val CheckSum = 10
  val ClOrdID = 11
  val OrigClOrdID = 41
  val OrderID = 37
  val ExecID = 17
  val ExecType = 150
  val Side = 54
  val OrderQty = 38
  val Price = 44
}

object MsgTypes {
  val Heartbeat = "0"
  val TestRequest = "1"
  val ResendRequest = "2"
  val Reject = "3"
  val SequenceReset = "4"
  val Logout = "5"
  val Logon = "A"
  val NewOrderSingle = "D"
  val ExecutionReport = "8"
  val BusinessMessageReject = "j"

  def isSessionAdmin(msgType: String): Boolean =
    msgType == Heartbeat || msgType == TestRequest || msgType == ResendRequest ||
      msgType == SequenceReset || msgType == Logout || msgType == Logon
}

/** Logical FIX session. Unlike tag 49/56, this orientation is stable on both directions. */
final case class SessionKey(localCompId: String, remoteCompId: String, qualifier: String = "") {
  def label: String = s"$localCompId<->$remoteCompId" + (if (qualifier.isEmpty) "" else s"/$qualifier")
}

final case class FixField(tag: Int, value: String) {
  def wire: String = s"$tag=$value"
}

final case class ChannelBinding(
    channelId: String,
    remoteEndpoint: String,
    /** Verified mTLS SPI pin / subject+issuer identity. Never trust an unverified header here. */
    tlsIdentity: Option[String],
    openedAtNanos: Long
)

final case class FixMessage(
    seqNum: Long,
    msgType: String,
    senderCompId: String,
    targetCompId: String,
    fields: Vector[FixField],
    channelId: String,
    receivedAtNanos: Long
) {
  def value(tag: Int): Option[String] = fields.collectFirst {
    case FixField(`tag`, v) => v
  }

  def requireValue(tag: Int): Either[String, String] =
    value(tag).filter(_.nonEmpty).toRight(s"missing tag $tag")

  def long(tag: Int): Option[Long] = value(tag).flatMap(v => Try(v.toLong).toOption)

  def boolean(tag: Int): Boolean =
    value(tag).exists(v => v.equalsIgnoreCase("Y") || v == "true" || v == "1")

  def possDup: Boolean = boolean(Tags.PossDupFlag)

  def possResend: Boolean = boolean(Tags.PossResend)

  def retransmissionMarked: Boolean = possDup || possResend

  def sendingTime: Option[String] = value(Tags.SendingTime)

  def origSendingTime: Option[String] = value(Tags.OrigSendingTime)

  def clOrdId: Option[String] = value(Tags.ClOrdID)

  def execId: Option[String] = value(Tags.ExecID)
}

object FixMessage {
  def apply(
      seqNum: Long,
      msgType: String,
      session: SessionKey,
      channelId: String,
      receivedAtNanos: Long,
      extra: Seq[FixField] = Vector.empty
  ): FixMessage = {
    val standard = Vector(
      FixField(Tags.MsgSeqNum, seqNum.toString),
      FixField(Tags.MsgType, msgType),
      FixField(Tags.SenderCompID, session.remoteCompId),
      FixField(Tags.TargetCompID, session.localCompId)
    )
    FixMessage(
      seqNum = seqNum,
      msgType = msgType,
      senderCompId = session.remoteCompId,
      targetCompId = session.localCompId,
      fields = standard ++ extra,
      channelId = channelId,
      receivedAtNanos = receivedAtNanos
    )
  }
}

sealed trait AuthVerdict {
  def verified: Boolean
}
object AuthVerdict {
  case object Verified extends AuthVerdict { val verified = true }
  final case class Invalid(reason: String) extends AuthVerdict { val verified = false }
}

trait MessageAuthenticator {
  def verify(message: FixMessage): AuthVerdict
}

/** Use only in tests or behind an already authenticated, integrity-protecting tunnel. */
object AllowAllAuthenticator extends MessageAuthenticator {
  override def verify(message: FixMessage): AuthVerdict = AuthVerdict.Verified
}

/**
 * HMAC-SHA256 over the canonical FIX fields, excluding the authentication tag itself and
 * transport recomputed tags. In production distribute independent keys per SessionKey and keep
 * them in an HSM/secret manager; mTLS remains necessary for endpoint identity.
 */
final class HmacMessageAuthenticator(
    session: SessionKey,
    secret: Array[Byte],
    authTag: Int = 9001
) extends MessageAuthenticator {
  def sign(fields: Seq[FixField]): String = {
    val canonical = MessageFingerprint.canonicalForAuthentication(fields, authTag)
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(secret, "HmacSHA256"))
    val bytes = mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8))
    bytes.map("%02x".format(_)).mkString
  }

  override def verify(message: FixMessage): AuthVerdict = {
    val sessionOk = message.senderCompId == session.remoteCompId &&
      message.targetCompId == session.localCompId
    if (!sessionOk) {
      AuthVerdict.Invalid("comp-id mismatch for HMAC session")
    } else {
      message.value(authTag) match {
        case None => AuthVerdict.Invalid(s"missing authentication tag $authTag")
        case Some(supplied) =>
          val expected = sign(message.fields)
          if (constantTimeEquals(supplied, expected)) AuthVerdict.Verified
          else AuthVerdict.Invalid("HMAC mismatch")
      }
    }
  }

  private def constantTimeEquals(a: String, b: String): Boolean = {
    val ab = a.getBytes(StandardCharsets.US_ASCII)
    val bb = b.getBytes(StandardCharsets.US_ASCII)
    MessageDigest.isEqual(ab, bb)
  }
}

/**
 * Content fingerprint used to distinguish a safe retransmission from a same-sequence
 * forgery/price mutation. Retransmission-only tags are normalized rather than hashed literally.
 */
object MessageFingerprint {
  private val AlwaysExcluded = Set(
    Tags.BodyLength,
    Tags.CheckSum,
    Tags.PossDupFlag,
    Tags.PossResend,
    Tags.SendingTime,
    Tags.OrigSendingTime
  )

  def canonicalFields(fields: Seq[FixField], extraExcluded: Set[Int] = Set.empty): String =
    canonical(fields, AlwaysExcluded ++ extraExcluded)

  /** HMAC covers timestamps/retransmission flags too; only framing and the auth tag are excluded. */
  def canonicalForAuthentication(fields: Seq[FixField], authTag: Int): String =
    canonical(fields, Set(Tags.BodyLength, Tags.CheckSum, authTag))

  private def canonical(fields: Seq[FixField], excluded: Set[Int]): String = {
    fields
      .filterNot(f => excluded.contains(f.tag))
      .groupBy(_.tag)
      .toVector
      .sortBy(_._1)
      .flatMap { case (_, fs) => fs.sortBy(_.value).map(f => s"${f.tag}=${f.value}") }
      .mkString("\u0001")
  }

  def sha256Hex(value: String): String = {
    val digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))
    digest.map("%02x".format(_)).mkString
  }

  def businessHash(message: FixMessage, authTag: Option[Int] = Some(9001)): String = {
    val excluded = authTag.toSet
    sha256Hex(canonicalFields(message.fields, excluded))
  }
}

/**
 * Small FIX tag=value SOH parser/checksum validator. It intentionally does not pretend to be a
 * full FIX dictionary; session logic only needs standard header/admin tags.
 */
object FixWire {
  val Sofh: Char = '\u0001'

  final case class ParseError(message: String)

  def parseReadable(text: String, channelId: String, receivedAtNanos: Long): Either[ParseError, FixMessage] =
    parse(text.replace('|', Sofh), channelId, receivedAtNanos)

  def parse(raw: String, channelId: String, receivedAtNanos: Long): Either[ParseError, FixMessage] = {
    if (raw == null || raw.isEmpty) return Left(ParseError("empty FIX message"))
    if (!raw.startsWith("8=")) return Left(ParseError("missing BeginString"))

    val checksumError = validateChecksum(raw)
    if (checksumError.nonEmpty) return Left(ParseError(checksumError.get))

    val parts = raw.split(Sofh).iterator.filter(_.nonEmpty).toVector
    val fields = Vector.newBuilder[FixField]
    var seq: Option[Long] = None
    var msgType: Option[String] = None
    var sender: Option[String] = None
    var target: Option[String] = None

    parts.foreach { part =>
      val eq = part.indexOf('=')
      if (eq <= 0) return Left(ParseError(s"malformed field: $part"))
      val tagText = part.substring(0, eq)
      val value = part.substring(eq + 1)
      val tag = tagText.toIntOption.getOrElse(return Left(ParseError(s"non-integer tag: $tagText")))
      fields += FixField(tag, value)
      tag match {
        case Tags.MsgSeqNum => seq = value.toLongOption
        case Tags.MsgType => msgType = Some(value)
        case Tags.SenderCompID => sender = Some(value)
        case Tags.TargetCompID => target = Some(value)
        case _ =>
      }
    }

    for {
      s <- seq.filter(_ > 0).toRight(ParseError("missing/invalid MsgSeqNum"))
      mt <- msgType.filter(_.nonEmpty).toRight(ParseError("missing MsgType"))
      sc <- sender.filter(_.nonEmpty).toRight(ParseError("missing SenderCompID"))
      tc <- target.filter(_.nonEmpty).toRight(ParseError("missing TargetCompID"))
    } yield FixMessage(s, mt, sc, tc, fields.result(), channelId, receivedAtNanos)
  }

  /** FIX checksum is (sum of all bytes before the 10= field) mod 256, rendered as 3 digits. */
  def validateChecksum(raw: String): Option[String] = {
    val marker = s"${Sofh}10="
    val markerIndex = raw.lastIndexOf(marker)
    if (markerIndex < 0) return Some("missing checksum")

    val checksumStart = markerIndex + 1 // points at '1' in 10=
    val prefix = raw.substring(0, checksumStart) // includes the SOH immediately before 10=
    val expectedText = raw.substring(checksumStart + 3).takeWhile(_.isDigit)
    if (expectedText.length != 3) return Some("checksum must be three digits")
    val expected = expectedText.toInt
    val actual = prefix.getBytes(StandardCharsets.ISO_8859_1).map(_ & 0xff).sum % 256
    if (actual != expected) Some(s"checksum mismatch expected=$expected actual=$actual") else None
  }

  def checksum(bodyBeforeTrailer: String): String = {
    val value = bodyBeforeTrailer.getBytes(StandardCharsets.ISO_8859_1).map(_ & 0xff).sum % 256
    f"$value%03d"
  }
}
