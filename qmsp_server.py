# qmsp_server.py
# QMSP: QUIC Media Streaming Protocol - async multi-client server
# Author: Anurag R Simha
# Drexel ID: 14763701
#
# This module implements the server side of the QMSP DFA. Each incoming QUIC
# connection gets its own QMSPServerProtocol instance (and therefore its own
# QMSPSession), so multiple clients can stream concurrently without shared state.
#
# Session lifecycle:
#   IDLE -> CONNECTED -> AUTHENTICATED -> BROWSING <-> STREAMING <-> PAUSED
#                                                          ↕
#                                                       SEEKING
#
# Stream architecture:
#   Control stream (QUIC stream 0): bidirectional, carries all signaling.
#   Media stream: server-initiated unidirectional stream, opened per PLAY/SEEK,
#   closed on STOP, end-of-stream (FLAG_FINAL), or error. A new media stream ID
#   is allocated on each PLAY and SEEK so in-flight segments from the previous
#   delivery are naturally flushed without explicit cancellation.

import asyncio
import hashlib
import logging
import os
import sys
import argparse
from typing import Dict, Optional
import hmac

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated

from qmsp_messages import (
    QMSP_VERSION, QMSP_PORT, HEADER_SIZE,
    CAP_ABR_SUPPORT, CAP_LIVE_SUPPORT,
    CODEC_H264, CODEC_AAC,
    AUTH_PSK, AUTH_HMAC_SHA256,
    STREAM_VOD, STREAM_LIVE,
    FLAG_FINAL,
    MsgType, ErrorCode, MediaType,
    packHeader, unpackHeader,
    packQualityTier, packCatalogEntry,
    buildHelloAck, buildHelloNack,
    buildAuthAck, buildAuthNack,
    buildCatalogResp,
    buildPlayAck, buildPlayNack,
    buildMediaData,
    buildPauseAck,
    buildSeekAck,
    buildQualityAck,
    buildStopAck,
    buildPong,
    buildError,
    parseHello, parseAuth, parseCatalogReq,
    parsePlay, parseSeek, parseQualityChange, parsePing,
)

# User database
# -------------------
# Credentials stored as SHA-256(password) digests so the plaintext password
# never appears in source or memory after startup. In a production system this
# would be backed by a database with per-user salted hashes.
USER_DB: Dict[str, bytes] = {
    "alice": hashlib.sha256(b"alicepass").digest(),
    "admin": hashlib.sha256(b"adminpass").digest(),
    "bob":   hashlib.sha256(b"bobpass").digest(),
}

# Hardcoded stream catalog
# ------------------------------
# Three on-demand (VOD) entries with two quality tiers each. total_bytes is set
# to 1 MiB for all entries so the simulated delivery completes in a predictable
# amount of time during testing. A real server would read these values from a
# media manifest or database.
RAW_CATALOG = [
    {
        "streamId":   1,
        "streamType": STREAM_VOD,
        "title":       "Big Buck Bunny",
        "durationMs": 596_000,          # 9 minutes 56 seconds
        "totalBytes": 1_048_576,        # 1 MiB simulated payload
        "tiers": [
            {"bitrateBps": 500_000,   "width": 640,  "height": 360,
             "fps": 24, "codecId": CODEC_H264, "name": "360p24"},
            {"bitrateBps": 2_000_000, "width": 1920, "height": 1080,
             "fps": 24, "codecId": CODEC_H264, "name": "1080p24"},
        ],
    },
    {
        "streamId":   2,
        "streamType": STREAM_VOD,
        "title":       "Elephants Dream",
        "durationMs": 654_000,          # 10 minutes 54 seconds
        "totalBytes": 1_048_576,
        "tiers": [
            {"bitrateBps": 500_000,   "width": 640,  "height": 360,
             "fps": 24, "codecId": CODEC_H264, "name": "360p24"},
            {"bitrateBps": 3_000_000, "width": 1920, "height": 1080,
             "fps": 60, "codecId": CODEC_H264, "name": "1080p60"},
        ],
    },
    {
        "streamId":   3,
        "streamType": STREAM_VOD,
        "title":       "Cosmos Laundromat",
        "durationMs": 765_000,          # 12 minutes 45 seconds
        "totalBytes": 1_048_576,
        "tiers": [
            {"bitrateBps": 1_000_000, "width": 1280, "height": 720,
             "fps": 30, "codecId": CODEC_H264, "name": "720p30"},
            {"bitrateBps": 4_000_000, "width": 3840, "height": 2160,
             "fps": 30, "codecId": CODEC_H264, "name": "4K30"},
        ],
    },
]

# Pre-serialize every catalog entry at startup so CATALOG_RESP construction is a
# simple slice-and-join operation rather than re-packing on every request. This
# also ensures the wire format is consistent across all responses.
CATALOG_WIRE: list[bytes] = []
for e in RAW_CATALOG:
    tiersB = [
        packQualityTier(
            t["bitrateBps"], t["width"], t["height"],
            t["fps"], t["codecId"], t["name"]
        )
        for t in e["tiers"]
    ]
    CATALOG_WIRE.append(packCatalogEntry(
        e["streamId"], e["streamType"],
        e["totalBytes"], e["durationMs"],
        tiersB, e["title"],
    ))

# Simulated media delivery constants
# ---------------------------------------
# Each MEDIA_DATA frame carries exactly SEGMENT_SIZE bytes of (zeroed) payload.
# Segment boundaries also serve as the snap points for SEEK. Any requested offset
# is rounded down to the nearest multiple of SEGMENT_SIZE before delivery starts.
SEGMENT_SIZE = 4096

# DFA state labels
class State:
    # String labels mirror qmsp_client.py for consistent log output.
    IDLE          = "IDLE"
    CONNECTED     = "CONNECTED"
    AUTHENTICATED = "AUTHENTICATED"
    BROWSING      = "BROWSING"
    STREAMING     = "STREAMING"
    PAUSED        = "PAUSED"
    SEEKING       = "SEEKING"   # Transient, ends when first post-seek MEDIA_DATA is sent
    CLOSED        = "CLOSED"

# Per-connection session state

class QMSPSession:
    # Holds all mutable per-client state. One instance lives inside each
    # QMSPServerProtocol and is consulted by every handler method.

    def __init__(self) -> None:
        # DFA state tracking.
        self.state: str      = State.IDLE
        self.sessionId: int = 0         # Assigned randomly in _handleHello
        self.seq: int       = 0         # Monotonically increasing outbound sequence number

        # Bearer token issued after AUTH_ACK would be used for 0-RTT resumption.
        self.bearerToken: Optional[bytes] = None

        # Active playback context reset or updated on PLAY, SEEK, and STOP.
        self.activeStreamId: Optional[int]        = None   # stream_id being delivered
        self.qualityTier: int                       = 0      # Current ABR tier index
        self.currentOffset: int                     = 0      # Byte cursor for delivery
        self.segmentSeq: int                        = 0      # MEDIA_DATA segment counter
        self.mediaQuicStreamId: Optional[int]     = None  # QUIC stream carrying media
        self.mediaTask: Optional[asyncio.Task]      = None   # Running _deliverMedia coroutine

    def nextSeq(self) -> int:
        # Return and advance the sequence counter. Called before every outbound
        # message to ensure monotonically increasing sequence_num values.
        s = self.seq
        self.seq += 1
        return s

# Per-connection protocol handler

class QMSPServerProtocol(QuicConnectionProtocol):
    # One instance per QUIC connection. Inherits the aioquic event loop
    # integration, this class adds the QMSP framing and state machine on top.

    def __init__(self, *args, noDelay: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.session   = QMSPSession()
        # noDelay skips the inter-segment sleep in _deliverMedia, allowing
        # the full stream to be sent as fast as QUIC allows. Useful for local
        # testing where realistic pacing is not needed.
        self.noDelay  = noDelay
        # Per-QUIC-stream reassembly buffers. Only stream 0 (control) is
        # populated by clients, media streams are server-initiated (write-only).
        self.buf: Dict[int, bytes] = {}
        self.log = logging.getLogger("QMSPServer")

    def quic_event_received(self, event: QuicEvent) -> None:
        # Entry point for all QUIC-level events delivered by aioquic.
        # The server only reads from stream 0 (control), all other streams
        # are write-only (media delivery).
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            self.buf[sid] = self.buf.get(sid, b"") + event.data
            if sid == 0:
                self._drainControlBuffer()

        elif isinstance(event, ConnectionTerminated):
            self.log.info(
                "Connection closed  error=%s  reason=%r",
                event.error_code, event.reason_phrase,
            )
            # Cancel any in-progress media delivery task to free resources.
            self._cancelMediaTask()

    def _drainControlBuffer(self) -> None:
        # Process all complete QMSP frames available in the stream 0 buffer.
        # A frame is complete when the buffer holds HEADER_SIZE bytes and the
        # full payload declared in payload_len. Incomplete frames stay buffered.
        buf = self.buf.get(0, b"")
        while True:
            if len(buf) < HEADER_SIZE:
                break
            hdr = unpackHeader(buf)
            if hdr is None:
                break
            total = HEADER_SIZE + hdr["payloadLen"]
            if len(buf) < total:
                break
            payload = buf[HEADER_SIZE:total]
            buf = buf[total:]
            self._dispatch(hdr, payload)
        self.buf[0] = buf

    def _dispatch(self, hdr: dict, payload: bytes) -> None:
        # Route a complete QMSP frame to the appropriate handler.
        # Guards applied before routing:
        # 1. PING is always handled regardless of DFA state.
        # 2. Messages after CLOSED are silently dropped.
        # 3. All non-HELLO messages must carry the correct session_id.
        mt  = hdr["msgType"]
        sess = self.session

        # PING is the only message accepted in any state including CLOSED.
        if mt == MsgType.PING:
            if sess.state != State.CLOSED:
                self._handlePing(hdr, payload)
            return

        if sess.state == State.CLOSED:
            return

        # Validate session_id on every message except HELLO, which uses 0x00000000
        # because the server hasn't assigned an ID yet.
        if mt != MsgType.HELLO and hdr["sessionId"] != sess.sessionId:
            self._sendProtoError(
                f"sessionId mismatch: got {hdr['sessionId']:#010x}, "
                f"expected {sess.sessionId:#010x}"
            )
            return

        # Dispatch table: maps message type to handler method.
        handlers = {
            MsgType.HELLO:          self._handleHello,
            MsgType.AUTH:           self._handleAuth,
            MsgType.CATALOG_REQ:    self._handleCatalogReq,
            MsgType.PLAY:           self._handlePlay,
            MsgType.PAUSE:          self._handlePause,
            MsgType.SEEK:           self._handleSeek,
            MsgType.QUALITY_CHANGE: self._handleQualityChange,
            MsgType.STOP:           self._handleStop,
        }
        handler = handlers.get(mt)
        if handler is None:
            # Unrecognized message type, protocol violation.
            self._sendProtoError(f"Unrecognized message type 0x{mt:02X}")
            return
        handler(hdr, payload)

    # Handler methods
    # Each handler:
    # 1. Validates the current DFA state.
    # 2. Parses and validates the payload.
    # 3. Performs the required action.
    # 4. Advances the DFA state.
    # 5. Sends the appropriate ACK or NACK.

    def _handleHello(self, hdr: dict, payload: bytes) -> None:
        # IDLE -> CONNECTED
        # Validates the client's protocol version, assigns a random session_id,
        # and negotiates the capability bitmask (server ANDs client's mask with
        # its own supported capabilities).
        if self.session.state != State.IDLE:
            self._sendProtoError(
                f"HELLO received in unexpected state {self.session.state}"
            )
            return

        parsed = parseHello(payload)
        if parsed is None:
            self._sendProtoError("Malformed HELLO payload")
            return

        clientVer = parsed["protoVersion"]
        self.log.info(
            "HELLO  clientVersion=%d  capabilities=0x%04x  clientId=%r",
            clientVer, parsed["capabilities"], parsed["clientId"],
        )

        # Reject clients running a version older than the server's minimum.
        if clientVer < QMSP_VERSION:
            wire = buildHelloNack(
                ErrorCode.VERSION_MISMATCH,
                f"Minimum version required: {QMSP_VERSION}",
                self.session.nextSeq(),
            )
            self._sendControl(wire)
            self._closeConnection()
            return

        # Generate a cryptographically random 4-byte session identifier.
        self.session.sessionId = int.from_bytes(os.urandom(4), "big")
        serverCaps   = CAP_ABR_SUPPORT | CAP_LIVE_SUPPORT
        # Negotiated capabilities = intersection of client offer and server support.
        agreedCaps   = parsed["capabilities"] & serverCaps

        wire = buildHelloAck(self.session.sessionId,
                               self.session.nextSeq(),
                               agreedCaps)
        self._sendControl(wire)
        self.session.state = State.CONNECTED
        self.log.info(
            "HELLO_ACK  sessionId=%#010x  negotiatedCaps=0x%04x",
            self.session.sessionId, agreedCaps,
        )

    def _handleAuth(self, hdr: dict, payload: bytes) -> None:
        # CONNECTED -> AUTHENTICATED (on success)
        # CONNECTED -> CLOSED (on failure, connection is torn down)
        # Supports two authentication methods:
        #   AUTH_PSK: token = SHA-256(password) compared with USER_DB entry
        #   AUTH_HMAC_SHA256: token = HMAC-SHA-256(stored_hash, nonce), timing-safe
        if self.session.state != State.CONNECTED:
            self._sendProtoError(
                f"AUTH received in unexpected state {self.session.state}"
            )
            return

        parsed = parseAuth(payload)
        if parsed is None:
            self._sendProtoError("Malformed AUTH payload")
            return

        username = parsed["username"]
        token    = parsed["token"]
        method   = parsed["authMethod"]

        self.log.info("AUTH  user=%r  method=0x%02x", username, method)

        expectedHash = USER_DB.get(username)

        authOk = False
        if expectedHash is not None:
            if method == AUTH_PSK:
                # Direct comparison of SHA-256(password) digests.
                authOk = (token == expectedHash)
            elif method == AUTH_HMAC_SHA256:
                # Prototype nonce: production would use TLS exported keying
                # material (RFC 5705) to bind the token to this connection.
                NONCE = b"qmsp-prototype-nonce-v1"
                expectedHmac = hmac.new(
                    expectedHash, NONCE, hashlib.sha256
                ).digest()
                # hmac.compare_digest prevents timing-based side-channel attacks.
                authOk = hmac.compare_digest(token, expectedHmac)

        if authOk:
            wire, bearer = buildAuthAck(self.session.sessionId,
                                          self.session.nextSeq())
            # Store the bearer token for future 0-RTT resumption validation.
            self.session.bearerToken = bearer
            self._sendControl(wire)
            self.session.state = State.AUTHENTICATED
            self.log.info("AUTH_ACK  user=%r  session=%#010x",
                           username, self.session.sessionId)
        else:
            self.log.warning("AUTH_NACK  user=%r  reason=bad credentials", username)
            wire = buildAuthNack(self.session.sessionId,
                                   self.session.nextSeq())
            self._sendControl(wire)
            # Tear down the connection immediately on auth failure to prevent
            # brute-force attempts on the same QUIC connection.
            self._closeConnection()

    def _handleCatalogReq(self, hdr: dict, payload: bytes) -> None:
        # AUTHENTICATED/BROWSING/PAUSED -> BROWSING
        # Returns a paginated, optionally filtered slice of CATALOG_WIRE.
        # The filter is a case-insensitive substring match on the stream title.
        allowed = {State.AUTHENTICATED, State.BROWSING, State.PAUSED}
        if self.session.state not in allowed:
            self._sendProtoError(
                f"CATALOG_REQ received in unexpected state {self.session.state}"
            )
            return

        parsed = parseCatalogReq(payload)
        if parsed is None:
            self._sendProtoError("Malformed CATALOG_REQ payload")
            return

        pgOffset   = parsed["offset"]
        maxEntries = parsed["maxEntries"]
        filterStr  = parsed["filter"].lower()

        # Apply the optional title filter, then paginate.
        if filterStr:
            filtered = [
                wire
                for raw, wire in zip(RAW_CATALOG, CATALOG_WIRE)
                if filterStr in raw["title"].lower()
            ]
        else:
            filtered = list(CATALOG_WIRE)

        wire = buildCatalogResp(
            self.session.sessionId,
            self.session.nextSeq(),
            filtered,
            len(filtered),
            pgOffset,
            maxEntries,
        )
        self._sendControl(wire)
        self.session.state = State.BROWSING
        self.log.info(
            "CATALOG_RESP  total=%d  offset=%d  max=%d  filter=%r",
            len(filtered), pgOffset, maxEntries, filterStr or "(none)",
        )

    def _handlePlay(self, hdr: dict, payload: bytes) -> None:
        # BROWSING/PAUSED -> STREAMING
        # Validates stream_id and quality_tier, cancels any existing media task,
        # allocates a new QUIC unidirectional stream for media delivery, sends
        # PLAY_ACK, then launches the _deliverMedia coroutine.
        allowed = {State.BROWSING, State.PAUSED}
        if self.session.state not in allowed:
            self._sendProtoError(
                f"PLAY received in unexpected state {self.session.state}"
            )
            return

        parsed = parsePlay(payload)
        if parsed is None:
            self._sendProtoError("Malformed PLAY payload")
            return

        streamId    = parsed["streamId"]
        qualityTier = parsed["qualityTier"]
        startOffset = parsed["startOffset"]

        entry = self._lookupStream(streamId)
        if entry is None:
            # Unknown stream_id, send NACK but stay in BROWSING so the client
            # can select a different stream without reconnecting.
            wire = buildPlayNack(
                self.session.sessionId, self.session.nextSeq(),
                ErrorCode.STREAM_NOT_FOUND,
                f"Stream {streamId} not found in catalog",
            )
            self._sendControl(wire)
            return

        if qualityTier >= len(entry["tiers"]):
            wire = buildPlayNack(
                self.session.sessionId, self.session.nextSeq(),
                ErrorCode.QUALITY_UNAVAIL,
                f"Quality tier {qualityTier} not available for stream {streamId}",
            )
            self._sendControl(wire)
            return

        # Cancel any previous media delivery before starting the new one.
        self._cancelMediaTask()

        # Allocate the next available server-initiated unidirectional stream ID.
        # Each PLAY and SEEK gets a fresh stream so old frames in flight are not
        # confused with new delivery.
        mediaQuicSid = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self.session.mediaQuicStreamId = mediaQuicSid
        self.session.activeStreamId     = streamId
        self.session.qualityTier         = qualityTier
        self.session.currentOffset       = startOffset
        # Compute the segment sequence number from the starting byte offset.
        self.session.segmentSeq          = startOffset // SEGMENT_SIZE

        bitrate = entry["tiers"][qualityTier]["bitrateBps"]

        wire = buildPlayAck(
            self.session.sessionId, self.session.nextSeq(),
            streamId, qualityTier, startOffset, mediaQuicSid, bitrate,
        )
        self._sendControl(wire)
        self.session.state = State.STREAMING

        # Launch the media delivery coroutine as a background asyncio task so
        # the control stream remains responsive to PAUSE, SEEK, and STOP.
        self.session.mediaTask = asyncio.ensure_future(
            self._deliverMedia(streamId, entry, qualityTier,
                                startOffset, mediaQuicSid)
        )
        self.log.info(
            "PLAY  stream=%d  tier=%d  offset=%d  mediaQuicStream=%d",
            streamId, qualityTier, startOffset, mediaQuicSid,
        )

    def _handlePause(self, hdr: dict, payload: bytes) -> None:
        # STREAMING -> PAUSED
        # Cancels the media delivery task and sends PAUSE_ACK with the current
        # byte offset so the client knows where to resume from.
        if self.session.state != State.STREAMING:
            self._sendProtoError(
                f"PAUSE received in unexpected state {self.session.state}"
            )
            return

        self._cancelMediaTask()

        lastOffset = self.session.currentOffset
        wire = buildPauseAck(self.session.sessionId,
                               self.session.nextSeq(),
                               lastOffset)
        self._sendControl(wire)
        self.session.state = State.PAUSED
        self.log.info("PAUSE_ACK  lastOffset=%d", lastOffset)

    def _handleSeek(self, hdr: dict, payload: bytes) -> None:
        # STREAMING/PAUSED -> SEEKING
        # Snaps the requested offset to the nearest SEGMENT_SIZE boundary
        # (simulating I-frame alignment), opens a new media stream, and begins
        # delivery from the snapped position. The protocol auto-transitions from
        # SEEKING to STREAMING when the first MEDIA_DATA of the new stream is sent.
        allowed = {State.STREAMING, State.PAUSED}
        if self.session.state not in allowed:
            self._sendProtoError(
                f"SEEK received in unexpected state {self.session.state}"
            )
            return

        parsed = parseSeek(payload)
        if parsed is None:
            self._sendProtoError("Malformed SEEK payload")
            return

        target = parsed["targetOffset"]
        entry  = self._lookupStream(self.session.activeStreamId)

        # Reject seeks beyond the stream's total size with an ERROR (unrecoverable).
        if entry and target >= entry["totalBytes"]:
            wire = buildError(
                self.session.sessionId, self.session.nextSeq(),
                ErrorCode.SEEK_OUT_OF_RANGE,
                f"Offset {target} exceeds stream size {entry['totalBytes']}",
            )
            self._sendControl(wire)
            self._closeConnection()
            return

        # Round down to the nearest segment boundary for decodable delivery.
        snapped = (target // SEGMENT_SIZE) * SEGMENT_SIZE

        self._cancelMediaTask()

        # Fresh QUIC stream flushes any buffered frames from the old position.
        newMediaSid = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self.session.mediaQuicStreamId = newMediaSid
        self.session.currentOffset       = snapped
        self.session.segmentSeq          = snapped // SEGMENT_SIZE

        wire = buildSeekAck(self.session.sessionId, self.session.nextSeq(),
                              snapped, newMediaSid)
        self._sendControl(wire)
        self.session.state = State.SEEKING

        # Restart delivery from the snapped position on the new media stream.
        self.session.mediaTask = asyncio.ensure_future(
            self._deliverMedia(
                self.session.activeStreamId,
                entry,
                self.session.qualityTier,
                snapped,
                newMediaSid,
            )
        )
        self.log.info(
            "SEEK  requested=%d  snapped=%d  newMediaStream=%d",
            target, snapped, newMediaSid,
        )

    def _handleQualityChange(self, hdr: dict, payload: bytes) -> None:
        # STREAMING -> STREAMING (no state change, delivery continues at new tier)
        # The running _deliverMedia coroutine reads self.session.qualityTier on
        # every segment, so updating it here takes effect at the next loop iteration
        # without interrupting delivery or requiring a new media stream.
        if self.session.state != State.STREAMING:
            self._sendProtoError(
                f"QUALITY_CHANGE received in unexpected state {self.session.state}"
            )
            return

        parsed = parseQualityChange(payload)
        if parsed is None:
            self._sendProtoError("Malformed QUALITY_CHANGE payload")
            return

        newTier = parsed["newQualityTier"]
        entry    = self._lookupStream(self.session.activeStreamId)

        if entry is None or newTier >= len(entry["tiers"]):
            wire = buildError(
                self.session.sessionId, self.session.nextSeq(),
                ErrorCode.QUALITY_UNAVAIL,
                f"Quality tier {newTier} not available",
            )
            self._sendControl(wire)
            self._closeConnection()
            return

        # Update in place, the delivery coroutine picks this up on its next segment.
        self.session.qualityTier = newTier
        bitrate = entry["tiers"][newTier]["bitrateBps"]

        wire = buildQualityAck(self.session.sessionId,
                                 self.session.nextSeq(),
                                 newTier, bitrate)
        self._sendControl(wire)
        self.log.info("QUALITY_ACK  tier=%d  bitrate=%d bps", newTier, bitrate)

    def _handleStop(self, hdr: dict, payload: bytes) -> None:
        # STREAMING/PAUSED/SEEKING -> BROWSING
        # Cancels delivery, closes the media QUIC stream (FIN), and sends
        # STOP_ACK with the final byte offset. The QMSP session remains active,
        # only the media sub-session is terminated.
        allowed = {State.STREAMING, State.PAUSED, State.SEEKING}
        if self.session.state not in allowed:
            self._sendProtoError(
                f"STOP received in unexpected state {self.session.state}"
            )
            return

        self._cancelMediaTask()

        # Send FIN on the media stream to signal end-of-stream to any buffering
        # layer. Wrapped in try/except in case the stream was already closed.
        if self.session.mediaQuicStreamId is not None:
            try:
                self._quic.send_stream_data(
                    self.session.mediaQuicStreamId, b"", end_stream=True
                )
            except Exception:
                pass

        finalOffset = self.session.currentOffset
        wire = buildStopAck(self.session.sessionId,
                              self.session.nextSeq(),
                              finalOffset)
        self._sendControl(wire)

        # Reset the media sub-session, keep the session alive for further browsing.
        self.session.state                = State.BROWSING
        self.session.activeStreamId     = None
        self.session.mediaQuicStreamId = None
        self.log.info("STOP_ACK  finalOffset=%d", finalOffset)

    def _handlePing(self, hdr: dict, payload: bytes) -> None:
        # Respond to a PING with a PONG echoing the ping_id and timestamp.
        # Accepted in any non-CLOSED state, serves both keepalive and RTT probing.
        parsed = parsePing(payload)
        if parsed is None:
            return
        wire = buildPong(
            self.session.sessionId,
            self.session.nextSeq(),
            parsed["pingId"],
            parsed["timestamp"],
        )
        self._sendControl(wire)
        self.log.debug("PONG  pingId=%d", parsed["pingId"])

    # Media delivery coroutine

    async def _deliverMedia(
        self,
        streamId: int,
        entry: dict,
        qualityTier: int,
        startOffset: int,
        mediaQuicSid: int,
    ) -> None:
        # Delivers simulated media segments until the stream is exhausted, the
        # task is cancelled (PAUSE / SEEK / STOP), or an exception occurs.
        #
        # Each iteration:
        #   1. Reads the current quality tier (may have been changed mid-stream).
        #   2. Computes the segment size (clamped at the end of the stream).
        #   3. Builds and sends a MEDIA_DATA frame with zeroed payload bytes.
        #   4. Sets FLAG_FINAL on the last segment and closes the QUIC stream.
        #   5. Sleeps for the simulated transmission duration (unless noDelay).
        totalBytes = entry["totalBytes"]
        offset      = startOffset
        segSeq     = self.session.segmentSeq

        try:
            while offset < totalBytes:
                # Re-read qualityTier each iteration so a QUALITY_CHANGE received
                # on the control stream takes effect without restarting delivery.
                qualityTier = self.session.qualityTier
                tierInfo    = entry["tiers"][qualityTier]
                codecId     = tierInfo["codecId"]
                bitrateBps  = tierInfo["bitrateBps"]

                remaining = totalBytes - offset
                segSize  = min(SEGMENT_SIZE, remaining)
                isFinal  = (offset + segSize >= totalBytes)

                # Payload is zeroed bytes (simulated, real implementation would
                # read from a media file or network cache).
                frame = buildMediaData(
                    self.session.sessionId,
                    self.session.nextSeq(),
                    streamId,
                    segSeq,
                    offset,
                    MediaType.MUXED,
                    codecId,
                    qualityTier,
                    bytes(segSize),    # simulated media payload
                    isFinal,
                )
                # end_stream=True on the final frame closes the QUIC stream, which
                # signals to the client that delivery is complete at the QUIC level.
                self._quic.send_stream_data(mediaQuicSid, frame,
                                            end_stream=isFinal)
                self.transmit()

                offset     += segSize
                segSeq    += 1
                # Update the session cursor so PAUSE and STOP can report accurate
                # byte offsets even while delivery is in progress.
                self.session.currentOffset = offset
                self.session.segmentSeq    = segSeq

                # The SEEKING state ends as soon as delivery begins from the new
                # position (first MEDIA_DATA sent after a SEEK).
                if self.session.state == State.SEEKING:
                    self.session.state = State.STREAMING
                    self.log.debug("SEEK complete - transitioned to STREAMING")

                if isFinal:
                    self.log.info(
                        "Stream %d complete  totalBytes=%d", streamId, totalBytes
                    )
                    # Return to BROWSING so the client can start a new PLAY
                    # without an explicit STOP.
                    self.session.state                = State.BROWSING
                    self.session.activeStreamId     = None
                    self.session.mediaQuicStreamId = None
                    break

                if not self.noDelay:
                    # Simulate realistic pacing: sleep for the time it would take
                    # to transmit segSize bytes at the tier's target bitrate.
                    segmentDuration = (segSize * 8) / bitrateBps
                    await asyncio.sleep(segmentDuration)
                else:
                    # Yield to the event loop without sleeping so control messages
                    # are processed between segments even in no-delay mode.
                    await asyncio.sleep(0)

        except asyncio.CancelledError:
            # Normal cancellation path triggered by PAUSE, SEEK, or STOP.
            # The session.currentOffset was updated on every segment so PAUSE_ACK
            # and STOP_ACK can report an accurate final position.
            self.log.debug(
                "Media delivery cancelled  offset=%d", self.session.currentOffset
            )

    # Internal helpers

    def _sendControl(self, data: bytes) -> None:
        # Write bytes to QUIC stream 0 (bidirectional control stream) and flush.
        self._quic.send_stream_data(0, data)
        self.transmit()

    def _sendProtoError(self, reason: str) -> None:
        # Log a protocol violation, send ERROR (0xFF), then close the connection.
        # This is the server's response to any message received in an illegal state
        # or with a malformed payload.
        self.log.error("Protocol violation: %s", reason)
        wire = buildError(
            self.session.sessionId,
            self.session.nextSeq(),
            ErrorCode.PROTO_VIOLATION,
            reason,
        )
        self._sendControl(wire)
        self._closeConnection()

    def _cancelMediaTask(self) -> None:
        # Cancel the running media delivery coroutine if one exists.
        # Called before starting a new PLAY, on PAUSE, SEEK, and STOP.
        if self.session.mediaTask and not self.session.mediaTask.done():
            self.session.mediaTask.cancel()
        self.session.mediaTask = None

    def _closeConnection(self) -> None:
        # Transition to CLOSED, cancel media delivery, and ask QUIC to initiate
        # a clean CONNECTION_CLOSE exchange with the peer.
        self.session.state = State.CLOSED
        self._cancelMediaTask()
        self._quic.close()
        self.transmit()

    @staticmethod
    def _lookupStream(streamId: Optional[int]) -> Optional[dict]:
        # Return the RAW_CATALOG entry for streamId, or None if not found.
        # The linear scan is fine for a three-entry catalog, a production
        # implementation would use a dict keyed by stream_id.
        if streamId is None:
            return None
        return next(
            (e for e in RAW_CATALOG if e["streamId"] == streamId), None
        )

# Server startup

async def runServer(args: argparse.Namespace) -> None:
    # Load TLS credentials and start the aioquic server. The noDelay flag is
    # captured in a closure so the protocol factory can forward it to each
    # new QMSPServerProtocol instance.
    config = QuicConfiguration(is_client=False)
    try:
        config.load_cert_chain(args.cert, args.key)
    except FileNotFoundError as exc:
        logging.critical(
            "TLS certificate/key not found: %s\n"
            "Generate a self-signed cert with:\n"
            "  openssl req -x509 -newkey rsa:2048 -keyout server.key "
            "-out server.crt -days 365 -nodes -subj '/CN=localhost'",
            exc,
        )
        sys.exit(1)

    noDelay = args.noDelay

    # Protocol factory: aioquic calls this once per incoming connection.
    # noDelay is captured from the outer scope via the closure.
    def makeProtocol(*a, **kw) -> QMSPServerProtocol:
        return QMSPServerProtocol(*a, noDelay=noDelay, **kw)

    logging.info(
        "QMSP server starting on %s:%d  (noDelay=%s)",
        args.host, args.port, noDelay,
    )
    logging.info("Catalog: %d entries", len(RAW_CATALOG))
    for entry in RAW_CATALOG:
        logging.info(
            "  streamId=%-3d  tiers=%-2d  title=%r",
            entry["streamId"], len(entry["tiers"]), entry["title"],
        )

    await serve(
        host=args.host,
        port=args.port,
        configuration=config,
        create_protocol=makeProtocol,
    )
    # Run forever, Ctrl+C raises KeyboardInterrupt in main() which exits cleanly.
    await asyncio.Future()

# Entry point

def main() -> None:
    parser = argparse.ArgumentParser(
        description="QMSP Server - QUIC Media Streaming Protocol",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host",      default="0.0.0.0",    help="Bind address")
    parser.add_argument("--port",      type=int, default=QMSP_PORT, help="UDP port")
    parser.add_argument("--cert",      default="server.crt", help="TLS certificate (PEM)")
    parser.add_argument("--key",       default="server.key", help="TLS private key (PEM)")
    parser.add_argument(
        "--log-level",
        dest="logLevel",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    parser.add_argument(
        "--no-delay",
        dest="noDelay",
        action="store_true",
        help="Skip inter-segment sleep (faster for local testing)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.logLevel),
        format="%(asctime)s  [%(levelname)-8s]  %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        asyncio.run(runServer(args))
    except KeyboardInterrupt:
        logging.info("Server stopped.")


if __name__ == "__main__":
    main()