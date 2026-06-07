# qmsp_client.py
# QMSP: QUIC Media Streaming Protocol - interactive command-line client
# Author: Anurag R Simha
# Drexel ID: 14763701
#
# This module implements the client side of the QMSP DFA:
#
#   IDLE -> CONNECTED -> AUTHENTICATED -> BROWSING <-> STREAMING <-> PAUSED
#                                                          ↕
#                                                       SEEKING
#
# The client connects over QUIC (TLS 1.3), completes the HELLO/AUTH handshake,
# then hands control to an async CLI loop where the user can browse the catalog,
# start and control playback, and disconnect cleanly.
#
# Concurrency model:
#   - QMSPClientProtocol runs inside aioquic's event loop and dispatches
#     incoming bytes to one of two internal asyncio.Queues:
#       * ctrlQueue: All control messages (HELLO_ACK, AUTH_ACK, ...)
#       * pongQueue: PONG replies (separated so ping doesn't block other reads)
#   - The CLI coroutine (runCli) awaits from these queues with timeouts.
#   - An optional keepalive coroutine fires PING at a configurable interval.
#   - A background eventListener coroutine prints stream-completion notices
#     without blocking the prompt.

import asyncio
import hashlib
import logging
import ssl
import struct
import sys
import time
import argparse
from typing import Optional

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated

from qmsp_messages import (
    QMSP_VERSION, QMSP_PORT, HEADER_SIZE,
    CAP_ABR_SUPPORT,
    AUTH_PSK,
    FLAG_FINAL,
    MsgType, ErrorCode, MediaType,
    packHeader, unpackHeader,
    buildPong, buildError,
    parsePing,
)

# DFA state labels

class State:
    # String constants for each DFA state. Using strings rather than an IntEnum
    # makes log messages self-explanatory without an extra lookup.
    IDLE          = "IDLE"           # Before the QUIC connection is established
    CONNECTED     = "CONNECTED"      # HELLO_ACK received, session_id assigned
    AUTHENTICATED = "AUTHENTICATED"  # AUTH_ACK received, may browse catalog
    BROWSING      = "BROWSING"       # Catalog fetched, may issue PLAY
    STREAMING     = "STREAMING"      # MEDIA_DATA delivery in progress
    PAUSED        = "PAUSED"         # Delivery halted, PAUSE_ACK received
    SEEKING       = "SEEKING"        # Transient, entered on SEEK, exited on first MEDIA_DATA
    CLOSED        = "CLOSED"         # Terminal, QUIC connection is being torn down

# Client-side PDU builders
# ------------------------------
# These functions mirror the server-side builders in qmsp_messages.py but are
# only needed by the client, so they live here to keep the shared module lean.

def buildHello(seq: int, capabilities: int = CAP_ABR_SUPPORT) -> bytes:
    # Build HELLO: the first message sent on the control stream.
    # session_id is 0x00000000 until the server assigns one in HELLO_ACK.
    # capabilities advertises which optional features the client supports.
    clientId = b"QMSPClient/1.0"
    payload   = (struct.pack("!BHB", QMSP_VERSION, capabilities, len(clientId))
                 + clientId)
    return packHeader(MsgType.HELLO, 0, 0, seq, len(payload)) + payload


def buildAuthPsk(sessionId: int, seq: int,
                 username: str, password: str) -> bytes:
    # Build AUTH using the PSK (Pre-Shared Key) method (auth_method = 0x02).
    # The token is SHA-256(password), matching the server's USER_DB entries.
    # In a production deployment this would be HMAC-SHA-256 with a TLS-derived
    # nonce, but PSK is sufficient for prototype testing.
    unameB = username.encode("utf-8")
    token   = hashlib.sha256(password.encode("utf-8")).digest()
    payload = (struct.pack("!BB", AUTH_PSK, len(unameB))
               + unameB
               + struct.pack("!H", len(token))
               + token)
    return packHeader(MsgType.AUTH, 0, sessionId, seq, len(payload)) + payload


def buildCatalogReq(sessionId: int, seq: int,
                    offset: int = 0, maxEntries: int = 0,
                    filterStr: str = "") -> bytes:
    # Build CATALOG_REQ with optional pagination and substring filtering.
    # maxEntries = 0 requests all entries, offset = 0 starts from the beginning.
    filterB = filterStr.encode("utf-8")
    payload  = struct.pack("!HHH", offset, maxEntries, len(filterB)) + filterB
    return packHeader(MsgType.CATALOG_REQ, 0, sessionId, seq, len(payload)) + payload


def buildPlay(sessionId: int, seq: int,
              streamId: int, qualityTier: int = 0,
              startOffset: int = 0) -> bytes:
    # Build PLAY: starts a new playback session or resumes after PAUSE.
    # For a resume, startOffset should be the last_offset from PAUSE_ACK.
    payload = struct.pack("!IB", streamId, qualityTier) + struct.pack("!Q", startOffset)
    return packHeader(MsgType.PLAY, 0, sessionId, seq, len(payload)) + payload


def buildPause(sessionId: int, seq: int) -> bytes:
    # Build PAUSE: zero-payload message, the header alone is the entire PDU.
    # Only valid in STREAMING state.
    return packHeader(MsgType.PAUSE, 0, sessionId, seq, 0)


def buildSeek(sessionId: int, seq: int, targetOffset: int) -> bytes:
    # Build SEEK: requests repositioning to targetOffset within the active stream.
    # The server snaps to the nearest decodable boundary and reports the actual
    # confirmed_offset in SEEK_ACK.
    payload = struct.pack("!Q", targetOffset)
    return packHeader(MsgType.SEEK, 0, sessionId, seq, len(payload)) + payload


def buildQualityChange(sessionId: int, seq: int, newTier: int) -> bytes:
    # Build QUALITY_CHANGE: requests an ABR tier switch mid-stream.
    # Three padding bytes follow the tier byte to keep the payload 4-byte aligned.
    payload = struct.pack("!B", newTier) + b"\x00\x00\x00"
    return packHeader(MsgType.QUALITY_CHANGE, 0, sessionId, seq, len(payload)) + payload


def buildStop(sessionId: int, seq: int) -> bytes:
    # Build STOP: zero-payload message, ends the active stream and returns the
    # protocol to BROWSING state. Valid in STREAMING, PAUSED, and SEEKING states.
    return packHeader(MsgType.STOP, 0, sessionId, seq, 0)


def buildPing(sessionId: int, seq: int, pingId: int) -> bytes:
    # Build PING: a keepalive probe valid in any non-CLOSED state.
    # The microsecond timestamp lets the receiver compute RTT by comparing the
    # echoed value with the current time when PONG arrives.
    ts      = int(time.time() * 1_000_000)
    payload = struct.pack("!IQ", pingId, ts)
    return packHeader(MsgType.PING, 0, sessionId, seq, len(payload)) + payload

# Server -> Client payload parsers
# ---------------------------------------
# Each function returns None on a short buffer so the caller can log an error
# and move on rather than raising an IndexError or struct.error.

def parseHelloAck(payload: bytes) -> Optional[dict]:
    # Parse HELLO_ACK payload.
    # Fields: negotiated_version(1) capabilities(2) session_id(4) server_id_len(1) server_id(N)
    if len(payload) < 8:
        return None
    negVer, caps, sessionId, sidLen = struct.unpack("!BHIB", payload[:8])
    serverId = payload[8: 8 + sidLen].decode("utf-8", errors="replace")
    return {"negotiatedVersion": negVer, "capabilities": caps,
            "sessionId": sessionId, "serverId": serverId}


def parseHelloNack(payload: bytes) -> Optional[dict]:
    # Parse HELLO_NACK payload.
    # Fields: error_code(1) min_version(1) reason_len(2) reason(N)
    if len(payload) < 4:
        return None
    errorCode, minVer, reasonLen = struct.unpack("!BBH", payload[:4])
    reason = payload[4: 4 + reasonLen].decode("utf-8", errors="replace")
    return {"errorCode": errorCode, "minVersion": minVer, "reason": reason}


def parseAuthAck(payload: bytes) -> Optional[dict]:
    # Parse AUTH_ACK payload.
    # Fields: token_len(2) bearer_token(32) token_ttl(4)
    # The 38-byte minimum = 2 (token_len) + 32 (bearer) + 4 (ttl).
    if len(payload) < 38:
        return None
    (tokenLen,) = struct.unpack("!H", payload[:2])
    bearer       = payload[2: 2 + tokenLen]
    (tokenTtl,) = struct.unpack("!I", payload[2 + tokenLen: 2 + tokenLen + 4])
    return {"bearerToken": bearer, "tokenTtl": tokenTtl}


def parseAuthNack(payload: bytes) -> Optional[dict]:
    # Parse AUTH_NACK payload.
    # Fields: error_code(1) reason_len(2) reason(N)
    if len(payload) < 3:
        return None
    errorCode, reasonLen = struct.unpack("!BH", payload[:3])
    reason = payload[3: 3 + reasonLen].decode("utf-8", errors="replace")
    return {"errorCode": errorCode, "reason": reason}


def parseCatalogResp(payload: bytes) -> Optional[dict]:
    # Parse CATALOG_RESP payload, including all variable-length catalog entries
    # and their nested quality tier arrays.
    # Top-level fields: total_entries(4) returned_count(2) entries(variable)
    if len(payload) < 6:
        return None
    totalEntries, returnedCount = struct.unpack("!IH", payload[:6])
    pos     = 6
    entries = []

    for _ in range(returnedCount):
        # Each catalog entry starts with a 22-byte fixed block:
        # stream_id(4) stream_type(1) total_bytes(8) duration_ms(8) num_tiers(1)
        if len(payload) - pos < 22:
            break
        streamId, streamType, totalBytes, durationMs, numTiers = struct.unpack("!IBQQB", payload[pos: pos + 22])
        pos += 22

        tiers = []
        for _ in range(numTiers):
            # Each quality tier has a 12-byte fixed block:
            # bitrate(4) width(2) height(2) fps(1) codec_id(2) name_len(1) name(N)
            if len(payload) - pos < 12:
                break
            bitrate, w, h, fps, codecId, nameLen = struct.unpack("!IHHBHB", payload[pos: pos + 12])
            pos += 12
            name = payload[pos: pos + nameLen].decode("utf-8", errors="replace")
            pos += nameLen
            tiers.append({"bitrateBps": bitrate, "width": w, "height": h,
                          "fps": fps, "codecId": codecId, "name": name})

        # Title is appended after the tiers array: title_len(2) title(N)
        if len(payload) - pos < 2:
            break
        (titleLen,) = struct.unpack("!H", payload[pos: pos + 2])
        pos += 2
        title = payload[pos: pos + titleLen].decode("utf-8", errors="replace")
        pos  += titleLen

        entries.append({
            "streamId":   streamId,  "streamType": streamType,
            "totalBytes": totalBytes, "durationMs": durationMs,
            "tiers":       tiers,       "title":       title,
        })

    return {"totalEntries": totalEntries, "entries": entries}


def parsePlayAck(payload: bytes) -> Optional[dict]:
    # Parse PLAY_ACK payload.
    # Fields: stream_id(4) quality_tier(1) confirmed_offset(8)
    #         media_quic_stream_id(8) bitrate_bps(4)  -> 25 bytes total
    if len(payload) < 25:
        return None
    streamId, qualityTier = struct.unpack("!IB", payload[:5])
    confirmedOffset        = struct.unpack("!Q", payload[5:13])[0]
    mediaQuicStreamId      = struct.unpack("!Q", payload[13:21])[0]
    bitrateBps             = struct.unpack("!I", payload[21:25])[0]
    return {"streamId": streamId, "qualityTier": qualityTier,
            "confirmedOffset": confirmedOffset,
            "mediaQuicStreamId": mediaQuicStreamId,
            "bitrateBps": bitrateBps}


def parsePlayNack(payload: bytes) -> Optional[dict]:
    # Parse PLAY_NACK payload.
    # Fields: error_code(1) reason_len(2) reason(N)
    if len(payload) < 3:
        return None
    errorCode, reasonLen = struct.unpack("!BH", payload[:3])
    reason = payload[3: 3 + reasonLen].decode("utf-8", errors="replace")
    return {"errorCode": errorCode, "reason": reason}


def parsePauseAck(payload: bytes) -> Optional[dict]:
    # Parse PAUSE_ACK payload.
    # Fields: last_offset(8), the byte the server stopped at, used as
    # start_offset in the subsequent PLAY (resume) request.
    if len(payload) < 8:
        return None
    return {"lastOffset": struct.unpack("!Q", payload[:8])[0]}


def parseSeekAck(payload: bytes) -> Optional[dict]:
    # Parse SEEK_ACK payload.
    # Fields: confirmed_offset(8) new_media_quic_stream_id(8)
    # The new stream ID is needed because the server opens a fresh QUIC
    # unidirectional stream for post-seek delivery to flush in-flight segments.
    if len(payload) < 16:
        return None
    confirmedOffset, newSid = struct.unpack("!QQ", payload[:16])
    return {"confirmedOffset": confirmedOffset, "newMediaQuicStreamId": newSid}


def parseQualityAck(payload: bytes) -> Optional[dict]:
    # Parse QUALITY_ACK payload.
    # Fields: confirmed_tier(1) bitrate_bps(4) padding(3)
    if len(payload) < 5:
        return None
    confirmedTier = payload[0]
    (bitrateBps,) = struct.unpack("!I", payload[1:5])
    return {"confirmedTier": confirmedTier, "bitrateBps": bitrateBps}


def parseStopAck(payload: bytes) -> Optional[dict]:
    # Parse STOP_ACK payload.
    # Fields: final_offset(8), where the server's delivery cursor was when
    # it received STOP, useful for logging and resumption bookkeeping.
    if len(payload) < 8:
        return None
    return {"finalOffset": struct.unpack("!Q", payload[:8])[0]}


def parsePong(payload: bytes) -> Optional[dict]:
    # Parse PONG payload.
    # Fields: ping_id(4) timestamp(8, echoed from PING)
    # The client uses the echoed ping_id to match the PONG to the correct PING
    # when multiple pings may be in flight (e.g. from the keepalive loop and
    # a manual "ping" CLI command simultaneously).
    if len(payload) < 12:
        return None
    pingId, timestamp = struct.unpack("!IQ", payload[:12])
    return {"pingId": pingId, "timestamp": timestamp}


def parseMediaData(payload: bytes) -> Optional[dict]:
    # Parse the fixed header portion of a MEDIA_DATA payload (29 bytes).
    # The raw media bytes follow immediately after and are not returned here,
    # the caller only needs the metadata to update progress counters.
    # Fields: stream_id(4) sequence(8) byte_offset(8) media_type(1)
    #         codec_id(2) quality_tier(1) reserved(1) data_len(4)
    if len(payload) < 29:
        return None
    streamId, seq, byteOffset = struct.unpack("!IQQ",   payload[:20])
    mediaType, codecId, qualityTier, res, dataLen = struct.unpack("!BHBBI", payload[20:29])
    return {"streamId": streamId, "sequence": seq, "byteOffset": byteOffset,
            "mediaType": mediaType, "codecId": codecId,
            "qualityTier": qualityTier, "dataLen": dataLen}


def parseErrorResp(payload: bytes) -> Optional[dict]:
    # Parse ERROR (0xFF) payload.
    # Fields: error_code(1) reason_len(2) reason(N)
    if len(payload) < 3:
        return None
    errorCode, reasonLen = struct.unpack("!BH", payload[:3])
    reason = payload[3: 3 + reasonLen].decode("utf-8", errors="replace")
    return {"errorCode": errorCode, "reason": reason}

# Internal event tokens
# --------------------------
# Sentinel strings placed on eventQueue to decouple background events from
# the synchronous CLI prompt. These let the background listener print notices
# (e.g. "stream complete") without blocking the user input coroutine.
EVT_STREAM_COMPLETE = "STREAM_COMPLETE"
EVT_DISCONNECTED    = "DISCONNECTED"

# Protocol handler (aioquic integration)

class QMSPClientProtocol(QuicConnectionProtocol):
    # Bridges aioquic's event-driven model with the QMSP message layer.
    #
    # aioquic delivers raw bytes via quic_event_received, this class:
    #   1. Reassembles complete QMSP frames from the byte stream (per stream ID).
    #   2. Dispatches PING automatically (no CLI interaction needed).
    #   3. Routes PONG to pongQueue for the CLI ping command and keepalive loop.
    #   4. Routes all other control messages to ctrlQueue for the CLI coroutine.
    #   5. Processes MEDIA_DATA frames in _drainMedia and fires EVT_STREAM_COMPLETE.

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Per-QUIC-stream reassembly buffers. Stream 0 = control, others = media.
        self.buf: dict[int, bytes]      = {}

        # ctrlQueue holds (msgType, header_dict, payload_bytes) tuples for all
        # control messages other than PING/PONG. The CLI coroutine awaits here.
        self.ctrlQueue: asyncio.Queue   = asyncio.Queue()

        # eventQueue holds (event_token, data_dict) for background notifications.
        # A separate listener coroutine consumes these and prints to stdout.
        self.eventQueue: asyncio.Queue  = asyncio.Queue()

        # pongQueue is isolated from ctrlQueue so that an in-flight CLI "ping"
        # does not accidentally consume a PONG intended for the keepalive loop.
        self.pongQueue: asyncio.Queue   = asyncio.Queue()

        # DFA tracking, kept in sync with server state via protocol exchanges.
        self.state:      str = State.IDLE
        self.sessionId: int  = 0
        self.seq:       int  = 0   # Monotonically increasing control-stream counter

        # Media stream tracking, reset on each PLAY/SEEK.
        self.mediaQuicSid:   Optional[int] = None  # QUIC stream ID for MEDIA_DATA
        self.mediaSegsRecv:  int           = 0     # Number of segments received
        self.mediaBytesRecv: int           = 0     # Total media bytes received
        self.mediaComplete:  bool          = False # Set when FLAG_FINAL is seen

        self.log = logging.getLogger("QMSPClient")

    def nextSeq(self) -> int:
        # Return the current sequence number and increment for the next call.
        # Called before every outbound control message to ensure monotonicity.
        s        = self.seq
        self.seq += 1
        return s

    def quic_event_received(self, event: QuicEvent) -> None:
        # Entry point for all QUIC-level events delivered by aioquic.
        # Only two event types are meaningful at the QMSP level:
        #   StreamDataReceived: New bytes arrived on a QUIC stream
        #   ConnectionTerminated: The QUIC connection was closed
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            # Append incoming bytes to the stream's reassembly buffer.
            self.buf[sid] = self.buf.get(sid, b"") + event.data
            if sid == 0:
                # Stream 0 is the bidirectional control stream.
                self._drainControl()
            else:
                # Any other stream ID carries MEDIA_DATA frames.
                self._drainMedia(sid)

        elif isinstance(event, ConnectionTerminated):
            self.log.info("Connection terminated  code=%s  reason=%r",
                          event.error_code, event.reason_phrase)
            self.state = State.CLOSED
            # Unblock any coroutine awaiting ctrlQueue with a sentinel tuple.
            self.ctrlQueue.put_nowait((None, None, None))
            self.eventQueue.put_nowait((EVT_DISCONNECTED, {}))

    def _drainControl(self) -> None:
        # Consume as many complete QMSP frames as possible from stream 0's buffer.
        # A frame is complete when the buffer holds at least HEADER_SIZE bytes
        # and the full (header + payload) length declared in payload_len is available.
        # Partial frames are left in the buffer for the next call.
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
            buf     = buf[total:]
            self._dispatchCtrl(hdr, payload)
        self.buf[0] = buf

    def _dispatchCtrl(self, hdr: dict, payload: bytes) -> None:
        # Route a complete control frame to the appropriate queue or handler.
        # PING is handled inline (auto-PONG) so the CLI loop never sees it.
        # PONG is separated from other messages to keep pongQueue dedicated.
        mt = hdr["msgType"]

        if mt == MsgType.PING:
            # Server-initiated PING: respond immediately without CLI involvement.
            parsed = parsePing(payload)
            if parsed:
                wire = buildPong(self.sessionId, self.nextSeq(),
                                 parsed["pingId"], parsed["timestamp"])
                self.sendControl(wire)
                self.log.debug("Auto-PONG for server PING  pingId=%d",
                               parsed["pingId"])
            return

        if mt == MsgType.PONG:
            # PONG responses go to their own queue, not ctrlQueue, so the
            # keepalive loop and the manual "ping" CLI command don't compete.
            parsed = parsePong(payload)
            self.pongQueue.put_nowait(parsed or {})
            return

        # All other control messages are queued for the CLI coroutine.
        self.ctrlQueue.put_nowait((mt, hdr, payload))

    def _drainMedia(self, sid: int) -> None:
        # Consume complete MEDIA_DATA frames from a media stream's buffer.
        # Updates progress counters and handles the SEEKING -> STREAMING auto-
        # transition when the first post-seek segment arrives. Fires
        # EVT_STREAM_COMPLETE when FLAG_FINAL is seen on a VOD stream.
        buf = self.buf.get(sid, b"")
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
            buf     = buf[total:]

            if hdr["msgType"] != MsgType.MEDIA_DATA:
                # Unexpected message type on a media stream, log and skip.
                self.log.warning("Unexpected message type 0x%02x on media stream %d",
                                 hdr["msgType"], sid)
                continue

            parsed = parseMediaData(payload)
            if parsed is None:
                continue

            self.mediaSegsRecv  += 1
            self.mediaBytesRecv += parsed["dataLen"]

            # The SEEKING state ends automatically when the first MEDIA_DATA
            # from the new stream arrives, consistent with the DFA specification.
            if self.state == State.SEEKING:
                self.state = State.STREAMING
                self.log.debug("SEEK complete - auto-transitioned to STREAMING")

            # FLAG_FINAL marks the last segment of a VOD stream, live streams
            # never set this bit because they have no defined end.
            isFinal = bool(hdr["flags"] & FLAG_FINAL)
            if isFinal:
                self.mediaComplete = True
                self.state          = State.BROWSING
                self.log.info("Stream complete  segs=%d  bytes=%d",
                              self.mediaSegsRecv, self.mediaBytesRecv)
                # Notify the background event listener without blocking here.
                self.eventQueue.put_nowait((EVT_STREAM_COMPLETE, {
                    "segs":  self.mediaSegsRecv,
                    "bytes": self.mediaBytesRecv,
                }))

        self.buf[sid] = buf

    def sendControl(self, data: bytes) -> None:
        # Write bytes to QUIC stream 0 (the bidirectional control stream) and
        # flush the QUIC send buffer via transmit().
        self._quic.send_stream_data(0, data)
        self.transmit()

    def resetMediaStats(self) -> None:
        # Clear per-stream counters before starting a new PLAY or SEEK so that
        # progress displayed to the user reflects only the current delivery.
        self.mediaSegsRecv  = 0
        self.mediaBytesRecv = 0
        self.mediaComplete   = False

    async def _keepaliveLoop(self, intervalSecs: float) -> None:
        # Send a PING every intervalSecs and await the PONG within pongTimeout.
        # If no PONG arrives in time, emit ERROR and close the connection rather
        # than silently hanging, dead session detection is a safety requirement.
        pongTimeoutSecs = min(intervalSecs, 10.0)
        pingIdCtr = 0
        self.log.info("Keepalive started  interval=%.1fs  pongTimeout=%.1fs",
                      intervalSecs, pongTimeoutSecs)
        try:
            while self.state != State.CLOSED:
                await asyncio.sleep(intervalSecs)
                if self.state == State.CLOSED:
                    break

                pingIdCtr += 1
                wire = buildPing(self.sessionId, self.nextSeq(), pingIdCtr)
                self.sendControl(wire)
                self.log.debug("Keepalive PING sent  pingId=%d", pingIdCtr)

                try:
                    pong = await asyncio.wait_for(
                        self.pongQueue.get(), pongTimeoutSecs
                    )
                    self.log.debug("Keepalive PONG received  pingId=%s",
                                   pong.get("pingId") if pong else "?")
                except asyncio.TimeoutError:
                    # Server did not reply within the timeout window, treat as
                    # an unrecoverable failure and close the connection cleanly.
                    self.log.error(
                        "Keepalive PONG timeout after %.1fs - closing connection",
                        pongTimeoutSecs,
                    )
                    print(
                        f"\n  [!] Keepalive timeout ({pongTimeoutSecs:.0f}s) "
                        "- server unreachable, disconnecting."
                    )
                    errWire = buildError(
                        self.sessionId, self.nextSeq(),
                        ErrorCode.INTERNAL, "Keepalive PONG timeout",
                    )
                    self._closeConnection(errWire)
                    break

        except asyncio.CancelledError:
            # Normal shutdown path when the CLI coroutine cancels this task.
            self.log.debug("Keepalive loop cancelled")

    def _closeConnection(self, errorWire: Optional[bytes] = None) -> None:
        # Transition to CLOSED, optionally send an ERROR frame, then ask QUIC
        # to close the connection. The ctrlQueue sentinel unblocks any awaiting
        # CLI coroutine so it can exit cleanly.
        self.state = State.CLOSED
        if errorWire is not None:
            try:
                self.sendControl(errorWire)
            except Exception:
                pass
        self._quic.close()
        self.transmit()
        self.ctrlQueue.put_nowait((None, None, None))

# Async helper utilities

async def recvCtrl(proto: QMSPClientProtocol, timeout: float = 10.0):
    # Await the next entry from the control queue with a configurable timeout.
    # A (None, None, None) sentinel means the connection was closed while waiting,
    # raise RuntimeError so callers can propagate the error cleanly.
    mt, hdr, payload = await asyncio.wait_for(proto.ctrlQueue.get(), timeout)
    if mt is None:
        raise RuntimeError("Connection closed while waiting for server response")
    return mt, hdr, payload

# Display helpers

def fmtBytes(n: int) -> str:
    # Format a byte count as a human-readable string (MB, KB, or raw bytes).
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} KB"
    return f"{n} B"


def fmtDuration(ms: int) -> str:
    # Format a millisecond duration as M:SS for catalog display.
    s    = ms // 1000
    m, s = divmod(s, 60)
    return f"{m}:{s:02d}"


def printCatalog(entries: list) -> None:
    # Pretty-print catalog entries with stream metadata and quality tier details.
    if not entries:
        print("  (no streams found)")
        return
    for e in entries:
        stype = "VOD " if e["streamType"] == 0x01 else "LIVE"
        dur   = fmtDuration(e["durationMs"]) if e["durationMs"] else "live"
        # Live streams report total_bytes = 0xFFFF..., show ∞ instead of a number.
        size  = (fmtBytes(e["totalBytes"])
                 if e["totalBytes"] != 0xFFFFFFFFFFFFFFFF else "∞")
        print(f"  [{e['streamId']}] {e['title']!r}  ({stype}  {dur}  {size})")
        for i, t in enumerate(e["tiers"]):
            bps = t["bitrateBps"] // 1000
            print(f"        tier {i}: {t['name']:12s}  {bps:6d} kbps  "
                  f"{t['width']}x{t['height']}@{t['fps']}fps")


def readLineBlocking() -> str:
    # Read a line from stdin synchronously. Executed in a thread-pool executor
    # (via loop.run_in_executor) so it doesn't block the asyncio event loop.
    # Returns "quit" on EOF (Ctrl-D) for a clean shutdown path.
    sys.stdout.write("> ")
    sys.stdout.flush()
    line = sys.stdin.readline()
    return line.strip() if line else "quit"

# CLI help text

HELP = """\
Commands:
  catalog [filter]   Browse streams (optional title substring filter)
  play <id> [tier]   Start playback (quality tier index, default 0)
  pause              Pause active stream
  resume             Resume from last paused position
  seek <bytes>       Seek to byte offset in current stream
  quality <tier>     Switch quality tier mid-stream
  stop               Stop playback, return to browsing
  ping               Send keepalive probe, measures round-trip time
  help               Show this help
  quit / exit        Disconnect and exit"""

# Main CLI coroutine

async def runCli(proto: QMSPClientProtocol, args: argparse.Namespace) -> None:
    # Driving the full QMSP session lifecycle from the user's perspective:
    #   1. HELLO handshake
    #   2. AUTH
    #   3. Initial catalog fetch
    #   4. Interactive command loop
    loop = asyncio.get_running_loop()

    # HELLO handshake
    print("[*] Sending HELLO ...")
    proto.sendControl(buildHello(proto.nextSeq()))

    try:
        mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
    except (asyncio.TimeoutError, RuntimeError) as exc:
        print(f"[-] HELLO failed: {exc}"); return

    if mt == MsgType.HELLO_ACK:
        p = parseHelloAck(payload)
        if not p:
            print("[-] Malformed HELLO_ACK"); return
        # Store the server-assigned session ID, required in every subsequent header.
        proto.sessionId = p["sessionId"]
        proto.state      = State.CONNECTED
        print(f"[+] HELLO_ACK  session={p['sessionId']:#010x}  "
              f"server={p['serverId']!r}  version={p['negotiatedVersion']}")
    elif mt == MsgType.HELLO_NACK:
        p = parseHelloNack(payload)
        print(f"[-] HELLO_NACK: {p['reason'] if p else 'unknown'}"); return
    else:
        print(f"[-] Unexpected message type 0x{mt:02X} during HELLO"); return

    # Authentication
    print(f"[*] Authenticating as {args.user!r} ...")
    proto.sendControl(
        buildAuthPsk(proto.sessionId, proto.nextSeq(), args.user, args.password)
    )

    try:
        mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
    except (asyncio.TimeoutError, RuntimeError) as exc:
        print(f"[-] AUTH failed: {exc}"); return

    if mt == MsgType.AUTH_ACK:
        p = parseAuthAck(payload)
        proto.state = State.AUTHENTICATED
        ttl = p["tokenTtl"] if p else "?"
        print(f"[+] AUTH_ACK  tokenTtl={ttl}s  -> authenticated")
    elif mt == MsgType.AUTH_NACK:
        p = parseAuthNack(payload)
        print(f"[-] AUTH_NACK: {p['reason'] if p else 'invalid credentials'}"); return
    else:
        print(f"[-] Unexpected message type 0x{mt:02X} during AUTH"); return

    # Initial catalog fetch
    # Automatically request the full catalog so the user can see what's available
    # immediately after login, without needing to type "catalog" first.
    proto.sendControl(
        buildCatalogReq(proto.sessionId, proto.nextSeq())
    )
    try:
        mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
    except (asyncio.TimeoutError, RuntimeError) as exc:
        print(f"[-] Catalog fetch failed: {exc}"); return

    catalogEntries: list = []
    if mt == MsgType.CATALOG_RESP:
        p = parseCatalogResp(payload)
        proto.state     = State.BROWSING
        catalogEntries = p["entries"] if p else []
        print(f"\n[+] Catalog ({p['totalEntries'] if p else 0} stream(s)):")
        printCatalog(catalogEntries)
    else:
        print(f"[-] Unexpected message type 0x{mt:02X} waiting for catalog")

    print(HELP + "\n")

    # Optional keepalive task
    # Runs as a background coroutine independent of the CLI command loop.
    keepaliveTask: Optional[asyncio.Task] = None
    if args.keepalive > 0:
        keepaliveTask = asyncio.ensure_future(
            proto._keepaliveLoop(args.keepalive)
        )
        print(f"[*] Keepalive enabled  interval={args.keepalive:.0f}s")

    # Playback state tracked across commands.
    currentStreamId: Optional[int] = None  # Stream currently playing or paused
    resumeOffset:    int           = 0     # Byte offset for the next PLAY (resume)
    qualityTier:     int           = 0     # Currently active quality tier index
    pingIdCtr:       int           = 0     # Monotonic counter for manual ping IDs

    async def eventListener() -> None:
        # Background coroutine that polls eventQueue and prints asynchronous
        # notices (stream completion, disconnect) without blocking the CLI prompt.
        while proto.state != State.CLOSED:
            try:
                kind, data = await asyncio.wait_for(
                    proto.eventQueue.get(), timeout=0.3
                )
                if kind == EVT_STREAM_COMPLETE:
                    print(f"\n  [*] Stream complete  "
                          f"segments={data['segs']}  "
                          f"bytes={fmtBytes(data['bytes'])}\n"
                          f"  -> state: BROWSING  "
                          f"(type 'catalog' to browse or 'play <id>' to watch again)")
                    # Re-print the prompt after the notice to avoid a broken display.
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                elif kind == EVT_DISCONNECTED:
                    break
            except asyncio.TimeoutError:
                # No events within 300 ms - loop and check state again.
                pass
            except asyncio.CancelledError:
                break

    # Interactive command loop
    bgTask = asyncio.ensure_future(eventListener())
    try:
        while True:
            # run_in_executor prevents the blocking readline() call from
            # stalling the event loop while the user is thinking.
            line  = await loop.run_in_executor(None, readLineBlocking)
            parts = line.split()
            if not parts:
                continue
            cmd = parts[0].lower()

            if cmd in ("quit", "exit"):
                print("[*] Disconnecting ...")
                break

            elif cmd == "help":
                print(HELP)

            elif cmd == "catalog":
                # catalog is allowed from AUTHENTICATED, BROWSING, or PAUSED.
                # Sending it during STREAMING would disrupt the control stream
                # interleaving, so it is rejected in that state.
                valid = {State.AUTHENTICATED, State.BROWSING, State.PAUSED}
                if proto.state not in valid:
                    print(f"  [!] catalog not allowed in state {proto.state}")
                    continue
                filterStr = parts[1] if len(parts) > 1 else ""
                proto.sendControl(
                    buildCatalogReq(proto.sessionId, proto.nextSeq(),
                                    filterStr=filterStr)
                )
                try:
                    mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
                except asyncio.TimeoutError:
                    print("  [!] Timeout waiting for CATALOG_RESP"); continue
                if mt == MsgType.CATALOG_RESP:
                    p = parseCatalogResp(payload)
                    proto.state     = State.BROWSING
                    catalogEntries = p["entries"] if p else []
                    total = p["totalEntries"] if p else 0
                    print(f"  Catalog ({total} total):")
                    printCatalog(catalogEntries)
                else:
                    print(f"  [!] Unexpected response 0x{mt:02X}")

            elif cmd == "play":
                # PLAY is valid from BROWSING or AUTHENTICATED (initial play
                # without an explicit prior catalog command).
                valid = {State.BROWSING, State.AUTHENTICATED}
                if proto.state not in valid:
                    print(f"  [!] play not allowed in state {proto.state}")
                    continue
                if len(parts) < 2:
                    print("  Usage: play <streamId> [qualityTier]"); continue
                try:
                    streamId    = int(parts[1])
                    qualityTier = int(parts[2]) if len(parts) > 2 else 0
                except ValueError:
                    print("  [!] streamId and qualityTier must be integers"); continue

                proto.resetMediaStats()
                proto.sendControl(
                    buildPlay(proto.sessionId, proto.nextSeq(),
                              streamId, qualityTier, 0)
                )
                try:
                    mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
                except asyncio.TimeoutError:
                    print("  [!] Timeout waiting for PLAY response"); continue

                if mt == MsgType.PLAY_ACK:
                    p = parsePlayAck(payload)
                    if p:
                        currentStreamId    = streamId
                        resumeOffset        = p["confirmedOffset"]
                        qualityTier         = p["qualityTier"]
                        proto.mediaQuicSid = p["mediaQuicStreamId"]
                        proto.state          = State.STREAMING
                        bps                  = p["bitrateBps"] // 1000
                        print(f"  [+] Streaming  stream={streamId}  "
                              f"tier={qualityTier}  {bps} kbps  "
                              f"offset={p['confirmedOffset']}")
                elif mt == MsgType.PLAY_NACK:
                    p = parsePlayNack(payload)
                    print(f"  [-] PLAY_NACK: {p['reason'] if p else 'unknown'}")
                else:
                    print(f"  [!] Unexpected response 0x{mt:02X}")

            elif cmd == "pause":
                if proto.state != State.STREAMING:
                    print(f"  [!] pause not allowed in state {proto.state}"); continue
                proto.sendControl(
                    buildPause(proto.sessionId, proto.nextSeq())
                )
                try:
                    mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
                except asyncio.TimeoutError:
                    print("  [!] Timeout"); continue

                if mt == MsgType.PAUSE_ACK:
                    p = parsePauseAck(payload)
                    if p:
                        # Store last_offset so "resume" can send the correct start_offset.
                        resumeOffset = p["lastOffset"]
                        proto.state   = State.PAUSED
                        print(f"  [+] Paused  lastOffset={resumeOffset}")
                else:
                    print(f"  [!] Unexpected response 0x{mt:02X}")

            elif cmd == "resume":
                if proto.state != State.PAUSED:
                    print(f"  [!] resume not allowed in state {proto.state}"); continue
                if currentStreamId is None:
                    print("  [!] No stream to resume"); continue
                proto.resetMediaStats()
                # Resume is implemented as a PLAY with the saved resumeOffset and
                # the same stream ID and quality tier.
                proto.sendControl(
                    buildPlay(proto.sessionId, proto.nextSeq(),
                              currentStreamId, qualityTier, resumeOffset)
                )
                try:
                    mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
                except asyncio.TimeoutError:
                    print("  [!] Timeout"); continue

                if mt == MsgType.PLAY_ACK:
                    p = parsePlayAck(payload)
                    if p:
                        proto.mediaQuicSid = p["mediaQuicStreamId"]
                        proto.state          = State.STREAMING
                        print(f"  [+] Resumed from offset={p['confirmedOffset']}")
                else:
                    print(f"  [!] Unexpected response 0x{mt:02X}")

            elif cmd == "seek":
                # SEEK is valid in both STREAMING and PAUSED states so the user
                # can reposition without needing to resume first.
                valid = {State.STREAMING, State.PAUSED}
                if proto.state not in valid:
                    print(f"  [!] seek not allowed in state {proto.state}"); continue
                if len(parts) < 2:
                    print("  Usage: seek <byteOffset>"); continue
                try:
                    target = int(parts[1])
                except ValueError:
                    print("  [!] Offset must be an integer"); continue

                proto.resetMediaStats()
                proto.sendControl(
                    buildSeek(proto.sessionId, proto.nextSeq(), target)
                )
                try:
                    mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
                except asyncio.TimeoutError:
                    print("  [!] Timeout"); continue

                if mt == MsgType.SEEK_ACK:
                    p = parseSeekAck(payload)
                    if p:
                        resumeOffset        = p["confirmedOffset"]
                        proto.mediaQuicSid = p["newMediaQuicStreamId"]
                        # Enter SEEKING; the DFA auto-transitions to STREAMING
                        # when the first MEDIA_DATA from the new stream arrives.
                        proto.state          = State.SEEKING
                        print(f"  [+] SEEK_ACK  confirmedOffset={p['confirmedOffset']}  "
                              f"(transitioning to STREAMING on first media frame)")
                elif mt == MsgType.ERROR:
                    p = parseErrorResp(payload)
                    print(f"  [-] Seek error: {p['reason'] if p else 'unknown'}")
                else:
                    print(f"  [!] Unexpected response 0x{mt:02X}")

            elif cmd == "quality":
                if proto.state != State.STREAMING:
                    print(f"  [!] quality not allowed in state {proto.state}"); continue
                if len(parts) < 2:
                    print("  Usage: quality <tier>"); continue
                try:
                    newTier = int(parts[1])
                except ValueError:
                    print("  [!] Tier must be an integer"); continue

                proto.sendControl(
                    buildQualityChange(proto.sessionId, proto.nextSeq(), newTier)
                )
                try:
                    mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
                except asyncio.TimeoutError:
                    print("  [!] Timeout"); continue

                if mt == MsgType.QUALITY_ACK:
                    p = parseQualityAck(payload)
                    if p:
                        qualityTier = p["confirmedTier"]
                        bps          = p["bitrateBps"] // 1000
                        print(f"  [+] QUALITY_ACK  tier={qualityTier}  {bps} kbps")
                elif mt == MsgType.ERROR:
                    p = parseErrorResp(payload)
                    print(f"  [-] Quality change error: {p['reason'] if p else 'unknown'}")
                else:
                    print(f"  [!] Unexpected response 0x{mt:02X}")

            elif cmd == "stop":
                # STOP is valid from STREAMING, PAUSED, or the transient SEEKING
                # state so the user can always escape back to the catalog.
                valid = {State.STREAMING, State.PAUSED, State.SEEKING}
                if proto.state not in valid:
                    print(f"  [!] stop not allowed in state {proto.state}"); continue
                proto.sendControl(
                    buildStop(proto.sessionId, proto.nextSeq())
                )
                try:
                    mt, hdr, payload = await recvCtrl(proto, timeout=8.0)
                except asyncio.TimeoutError:
                    print("  [!] Timeout"); continue

                if mt == MsgType.STOP_ACK:
                    p = parseStopAck(payload)
                    if p:
                        proto.state       = State.BROWSING
                        currentStreamId = None
                        resumeOffset     = 0
                        print(f"  [+] STOP_ACK  finalOffset={p['finalOffset']}")
                else:
                    print(f"  [!] Unexpected response 0x{mt:02X}")

            elif cmd == "ping":
                # Manual ping: measure round-trip time to the server.
                # Uses a separate counter from the keepalive loop so the two
                # don't collide on the pongQueue.
                pingIdCtr += 1
                tSent = time.monotonic()
                proto.sendControl(
                    buildPing(proto.sessionId, proto.nextSeq(), pingIdCtr)
                )
                try:
                    pong   = await asyncio.wait_for(proto.pongQueue.get(), timeout=8.0)
                    rttMs  = (time.monotonic() - tSent) * 1000
                    echoed = pong.get("pingId") if pong else "?"
                    print(f"  [+] PONG  pingId={echoed}  RTT={rttMs:.2f} ms")
                except asyncio.TimeoutError:
                    print("  [!] PONG timeout - server may be unreachable")

            else:
                print(f"  Unknown command {cmd!r} - type 'help' for options.")

    finally:
        # Tear down background tasks before exiting the CLI coroutine so that
        # no orphaned tasks linger when the QUIC connection closes.
        bgTask.cancel()
        if keepaliveTask is not None:
            keepaliveTask.cancel()
            try:
                await keepaliveTask
            except asyncio.CancelledError:
                pass
        try:
            await bgTask
        except asyncio.CancelledError:
            pass

# Connection setup

async def run(args: argparse.Namespace) -> None:
    # Configure the QUIC stack, open the connection, and run the CLI coroutine.
    config = QuicConfiguration(is_client=True)
    if args.insecure:
        # Disable certificate verification for self-signed test certificates.
        # Never use this flag in production.
        config.verify_mode = ssl.CERT_NONE

    print(f"[*] Connecting to {args.host}:{args.port} ...")
    try:
        async with connect(
            args.host,
            args.port,
            configuration=config,
            create_protocol=QMSPClientProtocol,
        ) as proto:
            await runCli(proto, args)
    except ConnectionRefusedError:
        print(f"[-] Connection refused  ({args.host}:{args.port})")
    except OSError as exc:
        print(f"[-] Network error: {exc}")
    except Exception as exc:
        logging.exception("Unexpected error: %s", exc)

# Entry point

def main() -> None:
    parser = argparse.ArgumentParser(
        description="QMSP Client - QUIC Media Streaming Protocol",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host",      default="localhost",
                        help="Server hostname or IP address")
    parser.add_argument("--port",      type=int, default=QMSP_PORT,
                        help="Server UDP port")
    parser.add_argument("--user",      default="alice",
                        help="Username (see USER_DB in qmsp_server.py)")
    parser.add_argument("--password",  default="alicepass",
                        help="Password")
    parser.add_argument("--insecure",  action="store_true",
                        help="Skip TLS certificate verification "
                             "(required for self-signed test certs)")
    parser.add_argument(
        "--keepalive",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Automatic PING keepalive interval in seconds "
             "(0 = disabled). Disconnects if no PONG received within "
             "min(interval, 10) seconds.",
    )
    parser.add_argument("--log-level", dest="logLevel", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging verbosity")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.logLevel),
        format="%(asctime)s  [%(levelname)-8s]  %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")


if __name__ == "__main__":
    main()