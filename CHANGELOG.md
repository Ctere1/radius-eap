# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (0.x: the minor
version is bumped for features and breaking changes).

## [0.2.2] - 2026-06-20

Patch release fixing an intermittent EAP-TLS handshake-completion race
introduced by the 0.2.1 channel-based `BuffConn` rewrite.

### Fixed

- **Intermittent EAP-TLS stall / client re-authentication** (most visible on
  **TLS 1.2** full handshakes). `BuffConn.WaitOutbound` treated a transient
  parked `Read` (empty inbound, empty outbound) as a flight boundary. In a
  TLS 1.2 full handshake the server reads the client's `Finished` *before*
  writing its own `ChangeCipherSpec`/`Finished`, so `crypto/tls` can park in
  `Read` mid-completion; the false boundary made the handler harvest an empty
  outbound and emit a **bare zero-length EAP-TLS request** (`0d8000000000`), or
  race `SetHandshakeDone` into a **premature EAP-Success** before the server's
  final flight was flushed. Either way the supplicant could not finish key
  derivation and re-authenticated (~13s later). `WaitOutbound` now blocks until
  real outbound bytes, handshake completion, an error, or the stale-connection
  timeout. (`protocol/tls/buff_conn.go`)
- **Defense-in-depth**: `outboundPayload` no longer emits a zero-length
  length-flagged EAP-TLS data packet when there is nothing to send; it resolves
  the final status (or ends as error) instead. (`protocol/tls/payload.go`)

The EAP-TLS keying path (`ExportKeyingMaterial`, MS-MPPE-Recv/Send keys) is
unchanged; this is purely a transport-framing/timing fix.

## [0.2.1] - 2026-06-20

Patch release fixing issues surfaced by the new `-race` CI job on 0.2.0.

### Fixed

- **Data race** on the per-session protocol-state map
  (`protocol.State.TypeState`): it was accessed both by the request handler and
  by the background TLS handshake goroutine (the `VerifyConnection` /
  `HandshakeSuccessful` callbacks). It is now mutex-guarded via
  `ProtocolState`/`SetProtocolState`/`IsProtocolStart`.
- Lint: removed unused TLS test helpers so `golangci-lint` is clean.

### Changed

- Refactored the EAP state machine (`handler.go`) for clarity: the duplicated
  method-dispatch path was collapsed into one, and helpers were extracted
  (`buildContext`, `samePayloadType`, `applyEndStatus`, `radiusCodeForEAP`). Pure
  refactor — no wire-protocol, RFC-semantics, or behavior change.

## [0.2.0] - 2026-06-20

A reliability, security, and documentation release. EAP-TLS/PEAP are now
race-free and state-safe, the protocol behavior is documented against the RFCs,
and every source file with behavior has its own tests (the whole module passes
`go test -race`).

### Added

- Thread-safe, session-scoped store on `protocol.Context`
  (`SessionValue`/`SetSessionValue`), backed by `State.SessionData`, so consumers
  can stash request-spanning data without a separate, separately-locked map.
- `eap.NewMemoryStateManager(settings, ttl)` — a ready-to-use, concurrency-safe
  `StateManager` with TTL eviction (avoids the unbounded-growth trap of a naive
  map that never evicts abandoned EAP sessions).
- Configurable maximum reassembled EAP-TLS message size (`MaxMessageSize` on the
  TLS and PEAP settings, default 64 KiB) — a DoS guard per RFC 5216 Section 3.1.
- Per-protocol RFC reference documents (`_RFC.md`) with Mermaid diagrams, plus
  godoc on the key engine functions.
- Per-file unit tests across all protocols, a `-race` CI job, and a
  `make test-race` target.

### Changed

- **BREAKING:** `protocol.Context` gained `SessionValue`/`SetSessionValue`;
  custom `Context` implementations must add them.
- **BREAKING:** the EAP-TLS in-memory `BuffConn` was rewritten with a
  channel-based, mutex-guarded handoff; `NewBuffConn`'s signature changed.
- EAP-TLS fragmentation/reassembly moved out of the conn into a dedicated
  reassembler, keeping the conn a pure byte pipe (single responsibility).
- Dropped the `avast/retry-go` dependency (the poll/backoff handoff was replaced
  by a blocking channel handoff).

### Fixed

- **Data race** in the EAP-TLS handshake transport: the background handshake
  goroutine and the request handler shared a `bytes.Buffer` and non-atomic
  counters. The transport is now race-free (verified under `-race`, including a
  real TLS 1.2/1.3 handshake driven through the bridge).
- **RFC 9190 Section 2.5:** the TLS 1.3 protected success indication is now sent
  only after the peer is both authenticated and authorized. Previously it was
  emitted before the authorization decision, so a valid-certificate client that
  was denied by policy received a success commitment immediately followed by
  EAP-Failure (this corrupts a Windows 11 supplicant's state machine).
- **RFC 3748 Section 4:** EAP packets whose declared Length is shorter than the
  received octets are now accepted (the trailing octets are treated as
  link-layer padding and ignored) instead of being rejected.
- PEAP inner-method authentication failure (e.g. wrong MS-CHAPv2 password) now
  ends cleanly with EAP-Failure instead of falling through to a spurious internal
  encode error and misleading WARN logs.
- MS-CHAPv2 reserved-byte validation no longer allocates on every parse.

### Security

- EAP-TLS reassembly is bounded (DoS) and abandoned handshakes time out, so a
  malicious or vanished peer cannot cause unbounded memory growth or leak the
  handshake goroutine.
- The session store is mutex-protected and therefore safe to use from the
  background TLS verification/handshake callbacks; `MemoryStateManager` evicts
  abandoned sessions.

## [0.1.7] - 2026-05-22

- Tightened EAP response handling and general protocol safety.

## [0.1.6] - 2026-04-14

- Added TLS 1.3 protected success indication and handshake tests.

## [0.1.5] - 2026-04-07

- Implemented PEAP extension ResultStatus handling and improved AVP decoding.

## [0.1.4] - 2026-04-07

- Hardened protocol handling and error validation across components.

## [0.1.3] - 2026-04-07

- Added context state management and richer protocol settings for EAP handling.

## [0.1.2] - 2026-04-02

- Refactored BuffConn data handling and post-handshake client-data handling.

## [0.1.1] - 2026-03-18

- Improved error handling and validation in payload decoding; added unit tests.

## [0.1.0] - 2025-10-28

- Initial release (fork of [BeryJu/radius-eap](https://github.com/BeryJu/radius-eap)).
