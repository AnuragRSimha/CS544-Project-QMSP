# QMSP - QUIC Media Streaming Protocol

**CS544 Computer Networks - Term Project Part 3b**  
Anurag R Simha | 14763701 | ars589@drexel.edu

A prototype client/server implementation of QMSP (QUIC Media Streaming Protocol), a stateful application-layer streaming protocol built on top of QUIC (RFC 9000). The server streams simulated on-demand media segments and the client provides an interactive command-line interface for browsing, playback, and playback control.

**Watch a live demo of QMSP here: https://youtu.be/EzIPCPXDuhk**

---

## Files

| File | Description |
|---|---|
| `qmsp_server.py` | QMSP server - binds on UDP 4544, handles all sessions |
| `qmsp_client.py` | QMSP client - interactive CLI |
| `qmsp_messages.py` | Shared PDU serialization/deserialization and constants |
| `certgen.py` | Generates a self-signed TLS certificate for local testing |
| `README.md` | This file |

---

## Dependencies

Python 3.11 or later is required.

```bash
pip install aioquic cryptography
```

`aioquic` provides the QUIC/TLS 1.3 transport. `cryptography` is used by `certgen.py` to generate a self-signed certificate.

---

## Quick Start

The included `build.sh` script takes care of the full build and run process for you. Open a terminal on computer and simply run:
```bash
chmod +x build.sh
./build.sh
```
If you prefer running each command individually, please follow the steps below:

Before you begin, please clone this repository with the following command:
```bash
git clone https://github.com/AnuragRSimha/CS544-Project-QMSP.git
```
Next, cd into the cloned repo's directory:
```bash
cd CS544-Project-QMSP
```

### 1. Generate a TLS certificate

The server requires a TLS certificate. For local testing, generate a self-signed one:

```bash
python certgen.py
```

This writes `server.crt` and `server.key` to the current directory.

### 2. Start the server

By default the server binds on `0.0.0.0:4544`. On one terminal, run:

```bash
python qmsp_server.py
```

### 3. Run the client

Open another terminal and run:

```bash
python qmsp_client.py --insecure
```

`--insecure` disables TLS certificate verification, which is necessary when using the self-signed certificate from `certgen.py`. The client defaults to `localhost:4544` and authenticates as `alice` with password `alicepass`.

If you want to be more specific while starting the server and client, follow the steps below:

### Server

Run this command in one terminal:

```bash
python qmsp_server.py --host 127.0.0.1 --log-level DEBUG --no-delay
```

What each flag means:

```
--host HOST        Bind address (default: 0.0.0.0)
--port PORT        UDP port (default: 4544)
--cert FILE        TLS certificate PEM file (default: server.crt)
--key  FILE        TLS private key PEM file (default: server.key)
--no-delay         Skip inter-segment sleep for fast local testing
--log-level LEVEL  DEBUG/INFO/WARNING/ERROR (default: INFO)
```

### Client

The following accounts are built into the server:

| Username | Password |
|---|---|
| alice | alicepass |
| admin | adminpass |
| bob | bobpass |

Run this command in another terminal:

```bash
python qmsp_client.py --host 127.0.0.1 --user admin --password adminpass --insecure --keepalive 30
```

What each flag means:

```
--host HOST          Server hostname or IP (default: localhost)
--port PORT          Server UDP port (default: 4544)
--user USER          Username (default: alice)
--password PASS      Password (default: alicepass)
--insecure           Skip TLS certificate verification
--keepalive SECONDS  Automatic PING interval. 0 = disabled (default: 0)
```

---

## Client Commands

Once connected and authenticated, the following commands are available:

```
catalog [filter]   List available streams. Optional title substring filter.
play <id> [tier]   Start playback of stream <id> at quality tier index (default 0).
pause              Pause the active stream.
resume             Resume from the last paused position.
seek <bytes>       Seek to a byte offset in the current stream.
quality <tier>     Switch quality tier mid-stream.
stop               Stop playback and return to the catalog.
ping               Send a keepalive probe and display the round-trip time.
help               Show command reference.
quit / exit        Disconnect and exit.
```

A typical session looks like:

```
[*] Sending HELLO …
[+] HELLO_ACK  session=0x3f2a1b4c  server='QMSPServer/1.0'  version=1
[*] Authenticating as 'alice' …
[+] AUTH_ACK  tokenTtl=3600s  -> authenticated

[+] Catalog (3 stream(s)):
  [1] 'Big Buck Bunny'     (VOD  9:56  1.05 MB)
        tier 0: 360p24        500 kbps  640x360@24fps
        tier 1: 1080p24      2000 kbps  1920x1080@24fps
  [2] 'Elephants Dream'    (VOD  10:54  1.05 MB)
  [3] 'Cosmos Laundromat'  (VOD  12:45  1.05 MB)

> play 1 1
  [+] Streaming  stream=1  tier=1  2000 kbps  offset=0
> pause
  [+] Paused  lastOffset=4096
> seek 8192
  [+] SEEK_ACK  confirmedOffset=8192  (transitioning to STREAMING on first media frame)
> quality 0
  [+] QUALITY_ACK  tier=0  500 kbps
> stop
  [+] STOP_ACK  finalOffset=12288
> quit
```

**NOTE: While testing the server-client interaction, it is suggested to open Wireshark as this helps monitor the packets being transmitted in real-time, giving a much better understanding of the implementation.**

---

## Protocol Overview

QMSP is a stateful client/server protocol. Both sides independently enforce a DFA and any message received in an illegal state causes an `ERROR` frame and connection close.

```
IDLE -> CONNECTED -> AUTHENTICATED -> BROWSING <-> STREAMING <-> PAUSED
                                                       ↕
                                                    SEEKING
```

All messages share a fixed 16-byte common header (`version`, `msg_type`, `flags`, `session_id`, `sequence_num`, `payload_len`) followed by a message-specific payload. The control stream (QUIC stream 0) carries all signaling and media is delivered on a separate server-initiated unidirectional QUIC stream.

Full protocol specification is in the Part 2 design document.

---

## What Is Implemented

- HELLO/AUTH/CATALOG handshake and full session lifecycle
- On-demand playback with simulated media segments (PLAY, MEDIA_DATA, STOP)
- PAUSE and RESUME (PLAY with `start_offset` from PAUSE_ACK)
- SEEK with segment-boundary snapping and new media stream ID
- Mid-stream QUALITY_CHANGE
- PING/PONG keepalive with configurable interval and timeout-driven disconnect
- Full DFA enforcement on both client and server
- Concurrent async server (multiple simultaneous clients via aioquic)
- Catalog pagination and substring title filtering

## Future Improvements

Due to time constraints, the following features are considered for future improvement:

- Live streams (`stream_type = 0x02`) - catalog is VOD (Video On-Demand) only
- 0-RTT session resumption - bearer token is issued but implementing the fast-path reconnect can be a future improvement
- HMAC-SHA-256 auth on the client - the server supports it, but the client sends PSK only

## Reflection on Implementation vs. Design

Implementing QMSP surfaced several design gaps that only become visible when I was actually writing the code. The most significant was concurrency on the client side. The Part 2 design treated the control stream as a single logical channel, but during implementation I discovered that the keepalive loop and a manual ping CLI command could race on the same queue and steal each other's PONG replies. This led to splitting pongQueue from ctrlQueue, a distinction the protocol spec never anticipated. A second practical change was pre-serializing the catalog at server startup (`CATALOG_WIRE`) rather than re-packing entries on every CATALOG_REQ, the design assumed on-demand serialization, but having a fixed catalog made the startup-time approach obviously better. The `--no-delay` flag also emerged purely from testing. Realistic bitrate pacing at 500 kbps made a 1 MiB simulated stream take over 16 seconds, which made iterating on the session lifecycle tedious. Finally, `asyncio.run_in_executor` for readline was not something the design needed to specify. The Part 2 spec correctly focused on the protocol's message structure and state machine, leaving implementation-level concurrency decisions where they belong, and that is in the code. These details aren't gaps in the design so much as the natural boundary between a protocol specification and its implementation. The DFA and PDU definitions held up without modification, which is the real measure of a solid design, and the concurrency model was always an implementation concern, not a protocol one.

## Extra Credit Work

- Demo video: https://youtu.be/EzIPCPXDuhk
- GitHub repository: https://github.com/AnuragRSimha/CS544-Project-QMSP
- Concurrent async server: Multiple simultaneous clients supported via aioquic
- Implementation robustness: SEEK, QUALITY_CHANGE, catalog pagination, and HMAC-SHA-256 auth were all listed as "time permitting" in Part 3a and are fully implemented
- Reflection on design vs. implementation: Please see section above