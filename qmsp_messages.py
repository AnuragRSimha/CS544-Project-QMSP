# qmsp_messages.py
# QMSP: QUIC Media Streaming Protocol - shared PDU serialization and constants
# Author: Anurag R Simha
# Drexel ID: 14763701
# 
# This module is the single source of truth for every on-wire format used by
# both the client and the server. All message construction (pack*) and parsing
# (parse*) functions live here so neither side hard-codes field offsets.
#
# Wire layout for all messages:
#   [16-byte common header] + [message-type-specific payload]
#
# All multi-byte integers are big-endian (network byte order), matching the
# struct format character "!". Strings are UTF-8 without null terminators,
# every variable-length field is preceded by an explicit length prefix.

import os
import struct
from enum import IntEnum
from typing import Optional, Tuple

# Protocol-wide constants

QMSP_VERSION: int = 0x01   # Current protocol version advertised in every HELLO
HEADER_SIZE: int  = 16     # Fixed size (bytes) of the common header
QMSP_PORT: int    = 4544   # Default UDP port the server binds to

# Enumerated types

class MsgType(IntEnum):
    # Message type codes carried in the msg_type field of the common header.
    # The value 0xFF (ERROR) is special: after sending or receiving ERROR both
    # sides must close the QUIC connection immediately.
    HELLO          = 0x01   # Client initiates session
    HELLO_ACK      = 0x02   # Server accepts, assigns session_id
    HELLO_NACK     = 0x03   # Server rejects (e.g. version mismatch)
    AUTH           = 0x04   # Client submits credentials
    AUTH_ACK       = 0x05   # Server confirms auth, issues bearer token
    AUTH_NACK      = 0x06   # Server rejects credentials
    CATALOG_REQ    = 0x07   # Client requests stream listing
    CATALOG_RESP   = 0x08   # Server returns catalog entries
    PLAY           = 0x09   # Client requests playback of a stream
    PLAY_ACK       = 0x0A   # Server confirms playback and opens media stream
    PLAY_NACK      = 0x0B   # Server rejects PLAY (stream/tier not found)
    MEDIA_DATA     = 0x0C   # Server delivers encoded media segments
    PAUSE          = 0x0D   # Client requests delivery halt
    PAUSE_ACK      = 0x0E   # Server confirms halt, reports last byte offset
    SEEK           = 0x0F   # Client requests repositioning within stream
    SEEK_ACK       = 0x10   # Server confirms seek offset and new media stream ID
    QUALITY_CHANGE = 0x11   # Client requests mid-stream ABR tier switch
    QUALITY_ACK    = 0x12   # Server confirms new quality tier
    STOP           = 0x13   # Client ends playback, returns to BROWSING state
    STOP_ACK       = 0x14   # Server confirms stop, reports final byte offset
    PING           = 0x15   # Keepalive probe, valid in any non-CLOSED state
    PONG           = 0x16   # Keepalive reply, echoes the ping_id
    ERROR          = 0xFF   # Unrecoverable error, connection closes after send


class ErrorCode(IntEnum):
    # Application-level error codes included in NACK and ERROR messages.
    # These allow the receiving side to log or display a machine-readable reason
    # in addition to the human-readable reason string.
    NONE               = 0x00  # No error (informational placeholder)
    VERSION_MISMATCH   = 0x01  # Client version too old for this server
    AUTH_FAILED        = 0x02  # Bad username or password/token
    STREAM_NOT_FOUND   = 0x03  # Requested stream_id absent from catalog
    QUALITY_UNAVAIL    = 0x04  # Requested quality tier index out of range
    SEEK_OUT_OF_RANGE  = 0x05  # Seek offset exceeds stream total_bytes
    PROTO_VIOLATION    = 0x06  # Message received in an illegal DFA state
    RESOURCE_EXHAUSTED = 0x07  # Server cannot allocate resources for session
    INTERNAL           = 0xFF  # Catch-all server-side failure


class MediaType(IntEnum):
    # Identifies the content category of each MEDIA_DATA segment.
    # Clients use this to route bytes to the appropriate decoder pipeline.
    AUDIO    = 0x01  # Audio-only segment (e.g. AAC)
    VIDEO    = 0x02  # Video-only segment (e.g. H.264)
    MUXED    = 0x03  # Interleaved audio+video (most common for VOD)
    SUBTITLE = 0x04  # Subtitle/caption track

# Header flags

# Bit 0 of the common header flags byte. Set on the last MEDIA_DATA frame of a
# VOD stream so the client knows delivery is complete. Live streams never set
# this bit because they have no defined end point.
FLAG_FINAL = 0x01

# Capability bitmask constants (HELLO/HELLO_ACK)

# Each bit represents an optional feature. The client advertises what it
# supports, the server ANDs this with its own mask and echoes the result.
# Unrecognized bits must be cleared, receivers must ignore them.
CAP_0RTT_RESUME  = 0x0001  # Fast reconnect using a previously issued bearer token
CAP_ABR_SUPPORT  = 0x0002  # Client supports adaptive-bitrate quality tier changes
CAP_LIVE_SUPPORT = 0x0004  # Client supports live streams (no FINAL flag, no duration)

# Codec identifier constants

# Used in quality tier descriptors and MEDIA_DATA frames so the client knows
# which decoder to invoke. The 16-bit namespace is registry-extensible.
CODEC_H264  = 0x0001   # H.264 / AVC
CODEC_H265  = 0x0002   # H.265 / HEVC
CODEC_VP9   = 0x0003   # VP9
CODEC_AV1   = 0x0004   # AV1
CODEC_AAC   = 0x0010   # AAC audio
CODEC_OPUS  = 0x0011   # Opus audio

# Authentication method constants (AUTH)

AUTH_HMAC_SHA256 = 0x01  # Token = HMAC-SHA-256(password, nonce)
AUTH_PSK         = 0x02  # Token = SHA-256(password), prototype-only shortcut

# Stream type constants (catalog entries)

STREAM_VOD  = 0x01  # On-demand, has known total_bytes and duration_ms
STREAM_LIVE = 0x02  # Live, total_bytes = 0xFFFF…, duration_ms = 0

# Common header packing

# Struct format for the 16-byte common header (network/big-endian):
#   B  version       1 byte
#   B  msg_type      1 byte
#   B  flags         1 byte  (bit 0 = FINAL, bits 1-7 reserved/zero)
#   B  reserved      1 byte  (must be 0x00 on send, ignored on receive)
#   I  session_id    4 bytes (assigned by server in HELLO_ACK, 0 in HELLO)
#   I  sequence_num  4 bytes (monotonically increasing per-stream counter)
#   I  payload_len   4 bytes (byte length of the payload following the header)
HDR_FMT = "!BBBBIII"


def packHeader(msgType: MsgType, flags: int, sessionId: int,
                sequenceNum: int, payloadLen: int) -> bytes:
    # Serialize the 16-byte common header into wire bytes.
    # The reserved byte is always set to 0x00 here, future versions may use it.
    return struct.pack(
        HDR_FMT,
        QMSP_VERSION,
        int(msgType),
        flags,
        0,           # reserved, must remain 0x00
        sessionId,
        sequenceNum,
        payloadLen,
    )


def unpackHeader(data: bytes) -> Optional[dict]:
    # Deserialize the first HEADER_SIZE bytes into a header dict.
    # Returns None if the buffer is too short, letting callers implement
    # a "read more and retry" loop without raising exceptions.
    if len(data) < HEADER_SIZE:
        return None
    version, msgType, flags, reserved, sessionId, seqNum, payloadLen = \
        struct.unpack(HDR_FMT, data[:HEADER_SIZE])
    return {
        "version":      version,
        "msgType":     msgType,
        "flags":        flags,
        "sessionId":   sessionId,
        "sequenceNum": seqNum,
        "payloadLen":  payloadLen,
    }

# Catalog sub-structure packers

def packQualityTier(bitrateBps: int, width: int, height: int,
                      fps: int, codecId: int, name: str) -> bytes:
    # Serialize one quality tier descriptor (variable length due to tier name).
    # Layout: bitrate(4) width(2) height(2) fps(1) codec_id(2) name_len(1) name(N)
    nameB = name.encode("utf-8")
    fixed = struct.pack("!IHHBHB",
                        bitrateBps,
                        width, height,
                        fps,
                        codecId,
                        len(nameB))
    return fixed + nameB


def packCatalogEntry(streamId: int, streamType: int, totalBytes: int,
                       durationMs: int, tiersBytes: list[bytes],
                       title: str) -> bytes:
    # Serialize one catalog entry including all of its quality tier descriptors.
    # The title is appended last (with a uint16 length prefix) because the
    # variable-length tiers array comes before it.
    packedTiers = b"".join(tiersBytes)
    # Fixed portion: stream_id(4) stream_type(1) total_bytes(8) duration_ms(8) num_tiers(1)
    base = struct.pack("!IBQQB",
                       streamId,
                       streamType,
                       totalBytes,
                       durationMs,
                       len(tiersBytes))
    titleB = title.encode("utf-8")
    # Tail: title_len(2) title(N)
    tail = struct.pack("!H", len(titleB)) + titleB
    return base + packedTiers + tail

# Server → Client message builders

def buildHelloAck(sessionId: int, seq: int,
                    capabilities: int = CAP_ABR_SUPPORT) -> bytes:
    # Build HELLO_ACK: assigns the session_id the client will echo in all
    # subsequent messages and confirms the negotiated capability bitmask.
    serverId = b"QMSPServer/1.0"
    payload = (struct.pack("!BHI", QMSP_VERSION, capabilities, sessionId)
               + struct.pack("!B", len(serverId))
               + serverId)
    return packHeader(MsgType.HELLO_ACK, 0, sessionId, seq, len(payload)) + payload


def buildHelloNack(errorCode: ErrorCode, reason: str, seq: int) -> bytes:
    # Build HELLO_NACK: sent when the server cannot accept the HELLO
    # (e.g. the client's proto_version is below the server's minimum).
    # The server closes the QUIC connection immediately after sending this.
    reasonB = reason.encode("utf-8")
    payload = struct.pack("!BBH", int(errorCode), QMSP_VERSION, len(reasonB)) + reasonB
    return packHeader(MsgType.HELLO_NACK, 0, 0, seq, len(payload)) + payload


def buildAuthAck(sessionId: int, seq: int) -> Tuple[bytes, bytes]:
    # Build AUTH_ACK and generate a random 32-byte bearer token.
    # Returns a (wire_bytes, bearer_token) tuple so the server can store the
    # token in its session table for future 0-RTT resumption validation.
    bearer = os.urandom(32)
    tokenTtl = 3600  # Token lifetime in seconds (1 hour)
    payload = struct.pack("!H", 32) + bearer + struct.pack("!I", tokenTtl)
    wire = packHeader(MsgType.AUTH_ACK, 0, sessionId, seq, len(payload)) + payload
    return wire, bearer


def buildAuthNack(sessionId: int, seq: int,
                    reason: str = "Invalid credentials") -> bytes:
    # Build AUTH_NACK: sent on credential failure. The server closes the
    # QUIC connection after sending this to prevent brute-force retries.
    reasonB = reason.encode("utf-8")
    payload = struct.pack("!BH", int(ErrorCode.AUTH_FAILED), len(reasonB)) + reasonB
    return packHeader(MsgType.AUTH_NACK, 0, sessionId, seq, len(payload)) + payload


def buildCatalogResp(sessionId: int, seq: int,
                       allEntries: list[bytes],
                       totalEntries: int,
                       offset: int,
                       maxEntries: int) -> bytes:
    # Build CATALOG_RESP: slices allEntries according to pagination parameters.
    # maxEntries = 0 means "return all remaining entries" (no limit).
    # total_entries reflects the full unfiltered count so clients can detect
    # whether additional pages are available.
    if maxEntries > 0:
        page = allEntries[offset: offset + maxEntries]
    else:
        page = allEntries[offset:]
    packed = b"".join(page)
    payload = struct.pack("!IH", totalEntries, len(page)) + packed
    return packHeader(MsgType.CATALOG_RESP, 0, sessionId, seq, len(payload)) + payload


def buildPlayAck(sessionId: int, seq: int,
                   streamId: int, qualityTier: int,
                   confirmedOffset: int, mediaQuicStreamId: int,
                   bitrateBps: int) -> bytes:
    # Build PLAY_ACK: confirms the quality tier and byte offset the server will
    # deliver from. The media_quic_stream_id tells the client which QUIC
    # unidirectional stream to expect MEDIA_DATA frames on.
    payload = (struct.pack("!IB", streamId, qualityTier)
               + struct.pack("!Q", confirmedOffset)
               + struct.pack("!Q", mediaQuicStreamId)
               + struct.pack("!I", bitrateBps))
    return packHeader(MsgType.PLAY_ACK, 0, sessionId, seq, len(payload)) + payload


def buildPlayNack(sessionId: int, seq: int,
                    errorCode: ErrorCode, reason: str) -> bytes:
    # Build PLAY_NACK: the client remains in BROWSING state and may retry
    # with a different stream_id or quality_tier.
    reasonB = reason.encode("utf-8")
    payload = struct.pack("!BH", int(errorCode), len(reasonB)) + reasonB
    return packHeader(MsgType.PLAY_NACK, 0, sessionId, seq, len(payload)) + payload


def buildMediaData(sessionId: int, seq: int,
                     streamId: int, segmentSeq: int,
                     byteOffset: int, mediaType: MediaType,
                     codecId: int, qualityTier: int,
                     data: bytes, isFinal: bool) -> bytes:
    # Build one MEDIA_DATA frame carrying a single encoded media segment.
    # isFinal=True sets FLAG_FINAL in the header, signaling the last segment of
    # a VOD stream. The segmentSeq is independent from the header sequence_num:
    # it counts segments within the media stream, mirroring QUIC's own per-stream
    # packet number spaces.
    flags = FLAG_FINAL if isFinal else 0
    payload = (struct.pack("!IQQ", streamId, segmentSeq, byteOffset)
               + struct.pack("!BHBBI", int(mediaType), codecId,
                             qualityTier, 0, len(data))  # reserved byte = 0
               + data)
    return packHeader(MsgType.MEDIA_DATA, flags, sessionId, seq, len(payload)) + payload


def buildPauseAck(sessionId: int, seq: int, lastOffset: int) -> bytes:
    # Build PAUSE_ACK: last_offset is authoritative, the client must use it
    # as the start_offset in the next PLAY (resume) request.
    payload = struct.pack("!Q", lastOffset)
    return packHeader(MsgType.PAUSE_ACK, 0, sessionId, seq, len(payload)) + payload


def buildSeekAck(sessionId: int, seq: int,
                   confirmedOffset: int,
                   newMediaQuicStreamId: int) -> bytes:
    # Build SEEK_ACK: the server snaps the requested offset to the nearest
    # decodable segment boundary (I-frame or audio sync point) and reports the
    # actual offset it will deliver from. A brand-new QUIC unidirectional stream
    # is opened to flush in-flight segments from the old position.
    payload = struct.pack("!QQ", confirmedOffset, newMediaQuicStreamId)
    return packHeader(MsgType.SEEK_ACK, 0, sessionId, seq, len(payload)) + payload


def buildQualityAck(sessionId: int, seq: int,
                      confirmedTier: int, bitrateBps: int) -> bytes:
    # Build QUALITY_ACK: the tier switch takes effect at the next segment
    # boundary so the client receives contiguous decodable content.
    # Three padding bytes keep the payload 4-byte aligned.
    payload = struct.pack("!BI", confirmedTier, bitrateBps) + b"\x00\x00\x00"
    return packHeader(MsgType.QUALITY_ACK, 0, sessionId, seq, len(payload)) + payload


def buildStopAck(sessionId: int, seq: int, finalOffset: int) -> bytes:
    # Build STOP_ACK: reports where delivery stopped so the client can track
    # the playhead position. The session returns to BROWSING state after this.
    payload = struct.pack("!Q", finalOffset)
    return packHeader(MsgType.STOP_ACK, 0, sessionId, seq, len(payload)) + payload


def buildPong(sessionId: int, seq: int,
               pingId: int, timestamp: int) -> bytes:
    # Build PONG: echoes the ping_id and original timestamp from the matching
    # PING so the sender can compute round-trip time without clock sync.
    payload = struct.pack("!IQ", pingId, timestamp)
    return packHeader(MsgType.PONG, 0, sessionId, seq, len(payload)) + payload


def buildError(sessionId: int, seq: int,
                errorCode: ErrorCode, reason: str) -> bytes:
    # Build ERROR (0xFF): after sending this the sender must close the QUIC
    # connection. The receiver must not send any further messages.
    reasonB = reason.encode("utf-8")
    payload = struct.pack("!BH", int(errorCode), len(reasonB)) + reasonB
    return packHeader(MsgType.ERROR, 0, sessionId, seq, len(payload)) + payload

# ─── Client → Server payload parsers ──────────────────────────────────────────
# Each parser returns None on a short or malformed buffer so callers can
# respond with ERR_PROTO_VIOLATION rather than raising an exception.

def parseHello(payload: bytes) -> Optional[dict]:
    # Parse a HELLO payload sent by the client.
    # Fields: proto_version(1) capabilities(2) client_id_len(1) client_id(N)
    if len(payload) < 4:
        return None
    protoVersion, capabilities, clientIdLen = struct.unpack("!BHB", payload[:4])
    if len(payload) < 4 + clientIdLen:
        return None
    clientId = payload[4: 4 + clientIdLen].decode("utf-8", errors="replace")
    return {
        "protoVersion": protoVersion,
        "capabilities":  capabilities,
        "clientId":     clientId,
    }


def parseAuth(payload: bytes) -> Optional[dict]:
    # Parse an AUTH payload.
    # Fields: auth_method(1) username_len(1) username(N) token_len(2) token(N)
    # Note the split-struct layout: username_len prefixes the username, and
    # token_len immediately follows, with no alignment padding between them.
    if len(payload) < 2:
        return None
    authMethod  = payload[0]
    usernameLen = payload[1]
    if len(payload) < 2 + usernameLen + 2:
        return None
    username = payload[2: 2 + usernameLen].decode("utf-8", errors="replace")
    off = 2 + usernameLen
    (tokenLen,) = struct.unpack("!H", payload[off: off + 2])
    off += 2
    if len(payload) < off + tokenLen:
        return None
    token = payload[off: off + tokenLen]
    return {
        "authMethod": authMethod,
        "username":    username,
        "token":       token,
    }


def parseCatalogReq(payload: bytes) -> Optional[dict]:
    # Parse a CATALOG_REQ payload.
    # Fields: offset(2) max_entries(2) filter_len(2) filter(N)
    # An empty filter string (filter_len = 0) means "return all streams".
    if len(payload) < 6:
        return None
    pgOffset, maxEntries, filterLen = struct.unpack("!HHH", payload[:6])
    filterStr = ""
    if filterLen > 0:
        if len(payload) < 6 + filterLen:
            return None
        filterStr = payload[6: 6 + filterLen].decode("utf-8", errors="replace")
    return {
        "offset":      pgOffset,
        "maxEntries": maxEntries,
        "filter":      filterStr,
    }


def parsePlay(payload: bytes) -> Optional[dict]:
    # Parse a PLAY payload.
    # Fields: stream_id(4) quality_tier(1) start_offset(8)
    # start_offset = 0 means start from the beginning, resuming after PAUSE
    # uses the last_offset value reported in PAUSE_ACK.
    if len(payload) < 13:
        return None
    streamId, qualityTier = struct.unpack("!IB", payload[:5])
    (startOffset,) = struct.unpack("!Q", payload[5:13])
    return {
        "streamId":    streamId,
        "qualityTier": qualityTier,
        "startOffset": startOffset,
    }


def parseSeek(payload: bytes) -> Optional[dict]:
    # Parse a SEEK payload.
    # Fields: target_offset(8)
    # The server snaps the target to the nearest decodable boundary before
    # delivering from it, so the confirmed_offset in SEEK_ACK may differ.
    if len(payload) < 8:
        return None
    (targetOffset,) = struct.unpack("!Q", payload[:8])
    return {"targetOffset": targetOffset}


def parseQualityChange(payload: bytes) -> Optional[dict]:
    # Parse a QUALITY_CHANGE payload.
    # Fields: new_quality_tier(1) padding(3)
    # The tier index must be valid for the currently active stream or the server
    # responds with an ERROR (ERR_QUALITY_UNAVAIL).
    if len(payload) < 1:
        return None
    return {"newQualityTier": payload[0]}


def parsePing(payload: bytes) -> Optional[dict]:
    # Parse a PING payload.
    # Fields: ping_id(4) timestamp(8, microseconds since Unix epoch)
    # PING is valid in any non-CLOSED state, the receiver must echo both fields
    # in the corresponding PONG without modifying them.
    if len(payload) < 12:
        return None
    pingId, timestamp = struct.unpack("!IQ", payload[:12])
    return {"pingId": pingId, "timestamp": timestamp}