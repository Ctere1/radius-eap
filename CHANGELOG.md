# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (0.x: the minor
version is bumped for features and breaking changes).

## [0.5.0] - 2026-09-03

Corrects the **MS-MPPE-Send-Key** derivation, which shipped half of the EMSK as a
link key, and hardens the EAP state machine: Response Identifiers are now matched
(RFC 3748 §4.1), the session store can be bounded, and tunnelled methods keep
their own per-method state so the **protected inner identity** is finally
recorded. Nothing is removed from the exported API, but three behaviours change
in ways a consumer must account for — see **Migration**.

### Fixed

- **MS-MPPE-Send-Key was derived from the EMSK, not the MSK.** RFC 5216 §2.3
  defines `Enc-SEND-Key = MSK(32,63)`, but the key was taken from
  `Key_Material(64,95)` — the first 32 octets of the EMSK. 802.1X/WPA2 never
  noticed, because the PMK comes from the Recv-Key, but PPP/MPPE links (PPTP,
  L2TP) were keyed with a value the peer could not reproduce, and 32 octets of
  EMSK were handed to the NAS, which the same section says must not be exported.
  A length guard now rejects keying material shorter than 64 octets instead of
  slicing out of bounds. (`protocol/tls`)
- **PEAP ended in Access-Reject when the inner method set offered Identity, and
  when the peer sent an inner Legacy Nak.** Advancing the tunnelled method ladder
  ended the whole conversation, because `EndInnerProtocol(StatusNextProtocol)`
  propagated to the root context and `next()` dropped the parent context. Both
  now advance the ladder that dispatched the method. (`context.go`, `handler.go`)
- **A peer flight the TLS state machine could not finish reading pinned the
  request goroutine for the full 10 s stale-connection timeout.** It is now
  resolved after a 2 s grace (`WaitNeedInput`), and a PEAP phase-2 packet
  carrying no tunnelled data ends the exchange instead of blocking on a read.
  (`protocol/tls`)
- **The fragment reassembler accepted contradictory framing.** A later fragment
  declaring a different total length, and a message whose reassembled size does
  not match the declared length, are now errors; every rejection clears the
  buffer so no partial message survives for a later fragment to extend.
  (`protocol/tls`)

### Security

- **EAP Response Identifiers are matched (RFC 3748 §4.1).** A Response whose
  Identifier is not the outstanding Request's is silently discarded instead of
  re-entering the method state machine, where a replayed Access-Request could
  feed the same TLS flight twice. **This makes RFC 5080 §2.2.2 duplicate
  detection a requirement of the RADIUS layer above** — see Migration.
  (`handler.go`, `protocol/state.go`)
- **The session store can be bounded.** Eviction is TTL-driven, so without a cap
  a burst of initial EAP packets — none of which has authenticated anything —
  grows the store for a whole session lifetime. The bound is soft: the check and
  the insert are not one atomic step, so concurrent starts may overshoot by the
  number of requests in flight. (`memory_state.go`, `protocol/state.go`)
- **`SSLKEYLOGFILE` is no longer honoured.** It was read unconditionally, so
  anyone able to set an environment variable on the server process got every TLS
  session secret written to disk, and the file handle was never closed (one
  descriptor per session). Key logging is now opt-in through
  `tls.Settings.KeyLogWriter`. (`protocol/tls`)
- **The Message-Authenticator is the first attribute of every reply**, including
  the error Access-Reject, which carried none at all
  (draft-ietf-radext-deprecating-radius §4.5). (`handler.go`)
- **Peer-supplied fields are bounded.** An Identity is limited to the 253 octets
  a RADIUS User-Name can carry and refused if it contains an embedded NUL; the
  MS-CHAPv2 `Name` field is limited to 256 octets. (`protocol/identity`,
  `protocol/mschapv2`)
- **No panics on the request path.** An unavailable CSPRNG now fails the one
  request rather than the process — the RADIUS layer runs handlers in goroutines
  with no recover. (`handler.go`, `protocol/mschapv2`)

### Added

- **`protocol.SessionLimiter`** and **`MemoryStateManager.SetMaxSessions`** —
  once the bound is reached, requests that would start another conversation are
  refused while existing ones continue.
- **`tls.Settings.KeyLogWriter`** — opt-in NSS key logging for outer EAP-TLS. A
  PEAP tunnel is configured through `peap.Settings`, so set
  `peap.Settings.Config.KeyLogWriter` for that one.
- **`State.LastRequestID` / `State.OutstandingRequest`** — the Identifier
  bookkeeping behind the RFC 3748 §4.1 check.
- **`WaitNeedInput`** — the `WaitOutbound` outcome reporting that the peer's
  flight was incomplete, so a caller stops instead of waiting for something that
  is not coming.

### Changed

- **Tunnelled (PEAP phase 2) methods keep per-method state on the nested state
  manager's `State`**, not on the shared outer session. The protected inner
  Identity is therefore recorded separately from the unprotected outer one, which
  is what an inner method should authenticate. Session-scoped values
  (`SessionValue` / `SetSessionValue`) stay shared. (`context.go`, `handler.go`)
- **A non-UTF-8 Identity is carried through rather than refused**, and a single
  trailing NUL is trimmed. RFC 3748 §5.1 only RECOMMENDS UTF-8, and supplicants
  terminate the value despite the same section. (`protocol/identity`)
- **Go 1.27 is now the minimum**, and `testify` moves to v1.12.1.

### Migration

- **Implement RFC 5080 §2.2.2 duplicate detection in the RADIUS layer.** With
  Identifier matching in place, a retransmitted Access-Request carries a Response
  this library has already answered and moved past, so it is discarded here; the
  caller must replay the reply it cached for that request. Without such a cache
  the retransmission goes unanswered and the NAS retries to timeout. The cache
  should live long enough to cover the retransmission window the same document
  recommends (30 s).
- **Lead tunnelled method sets with `identity.TypeIdentity`.** The inner identity
  exchange is only dispatched, and the protected identity only recorded, when the
  inner `ProtocolPriority` includes it. A consumer reading
  `ctx.GetProtocolState(identity.TypeIdentity)` from an inner method gets `nil`
  until it does, where before it silently got the outer identity.
- **Replace `SSLKEYLOGFILE` with `tls.Settings.KeyLogWriter`** if you relied on
  key logging.
- **Expect a different MS-MPPE-Send-Key value.** Deployments that key PPP/MPPE
  links from it start working; 802.1X/WPA2 deployments are unaffected.

## [0.4.0] - 2026-06-22

Adds a **standalone (outer) mode** to EAP-MS-CHAP-v2 so it can run directly as the
outer EAP method — not only as a PEAP inner method — for transports that already
provide a protected channel (e.g. EAP-MSCHAPv2 over IKEv2/IPsec). The PEAP-inner
behaviour is unchanged; all additions are opt-in, so this release is backward
compatible.

### Added

- **Standalone EAP-MSCHAPv2 (`mschapv2.Settings.Standalone`).** When set, a
  successful exchange ends with an outer EAP-Success (instead of the PEAP protected
  Result TLV) and a failed one runs the MS-CHAP-V2 **Failure sub-protocol**
  (draft-kamath §4 / RFC 2759 §6): an `OpFailure` Failure-Request carrying
  `E=691 R=0 C=<challenge> V=3 M=…`, then an outer EAP-Failure once the peer acks.
  New `op_failure.go` (`FailureRequest`), `State.AuthFailed`, and `Decode` now
  accepts the peer's Failure ack. (`protocol/mschapv2`)
- **`mschapv2.Settings.OnResult` hook.** Optional side-effect callback invoked with
  the password verdict (`true` on NT-Response match, `false` on mismatch) so a
  consumer can audit access/reject. It must not influence the exchange and is not
  called for backend errors surfaced by `AuthenticateRequest`. (`protocol/mschapv2`)

### Changed

- NT-Response comparison now uses `crypto/subtle.ConstantTimeCompare` (was
  `bytes.Equal`), matching the documented constant-time guarantee.
  (`protocol/mschapv2`)

## [0.3.0] - 2026-06-21

Makes **EAP-GTC** (one-time password inside the PEAP tunnel) actually terminate.
Until now the inner GTC exchange could never complete and re-challenged forever;
this release fixes the result signalling and, in doing so, changes the
`gtc.ValidateResponse` signature (breaking).

### Fixed

- **EAP-GTC never completed (infinite re-challenge).** The `getChallenge` /
  `validateResponse` closures returned by `Settings.ChallengeHandler` capture the
  `protocol.Context` from the round in which the handler first ran. On every
  later round the GTC payload re-invoked the *captured* closure, so a
  `ctx.EndInnerProtocol(...)` call inside `validateResponse` landed on a stale,
  already-completed request and had no effect on the current one — the method
  kept re-issuing the challenge and never emitted success or EAP-Failure. Unlike
  MS-CHAPv2, whose `Handle` runs on the live context each round, GTC delegated to
  these context-less callbacks. `gtc.Payload.Handle` now applies the validator's
  decision against the **current** context. (`protocol/gtc/payload.go`)

### Changed

- **BREAKING: `gtc.ValidateResponse` now returns `protocol.Status`**
  (`func(answer []byte) protocol.Status`, was `func(answer []byte)`). Consumers
  return the outcome instead of calling `ctx.EndInnerProtocol` themselves:
  - `StatusSuccess` → GTC emits a protected success **Result TLV**
    (`peap.ExtensionPayload`, `AVPAckResult = success`); PEAP forwards it, awaits
    the peer's acknowledgement, and ends successfully — the same completion path
    as MS-CHAPv2.
  - `StatusError` → the method ends on the current context and the tunnel emits
    EAP-Failure.
  - `StatusUnknown` → the challenge is re-issued (enables OTP retry).
  (`protocol/gtc/settings.go`, `protocol/gtc/payload.go`)

### Added

- GTC OTP **retry** support: returning `StatusUnknown` re-prompts within the same
  tunnel, so consumers can allow a bounded number of attempts before rejecting.
- Tests for all three `ValidateResponse` outcomes (success → Result TLV, error →
  `EndInnerProtocol`, undecided → re-challenge). (`protocol/gtc/payload_test.go`)

### Migration

Update each `gtc.ValidateResponse` to return a status and stop calling
`ctx.EndInnerProtocol`:

```go
// before
func(answer []byte) {
    if ok { ctx.EndInnerProtocol(protocol.StatusSuccess) } else { ctx.EndInnerProtocol(protocol.StatusError) }
}

// after
func(answer []byte) protocol.Status {
    if ok {
        return protocol.StatusSuccess
    }
    return protocol.StatusError // or protocol.StatusUnknown to re-challenge
}
```

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
