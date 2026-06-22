# EAP-MS-CHAP-v2 — RFC 2759 / RFC 3079

EAP method **Type 26**. Microsoft's challenge/handshake authentication. Mutual
authentication via NT-hash-derived responses plus MPPE key derivation for link
encryption. The method runs in two modes:

- **Tunnelled (default)** — as the PEAP phase-2 inner method; success is confirmed
  with the PEAP protected Result TLV.
- **Standalone (`Settings.Standalone`)** — directly as the outer EAP method (e.g.
  EAP-MSCHAPv2 inside IKEv2/IPsec, where the transport already protects it); success
  ends with an outer EAP-Success and failure runs the MS-CHAP-V2 Failure
  sub-protocol (RFC 2759 §6). The PEAP-inner behaviour is unchanged when the flag is
  off, so the same method is reusable in both contexts.

## Specifications

- **RFC 2759** — Microsoft PPP CHAP Extensions, Version 2 (the core algorithm:
  challenges, NT-Response, Authenticator-Response).
- **RFC 3079** — Deriving MPPE keys from MS-CHAP-v2 credentials.
- **draft-kamath-pppext-eap-mschapv2** — the EAP encapsulation of the above
  (including §4, the Failure-Request used in standalone mode).

## Message flow (RFC 2759 Sections 4-8)

```mermaid
sequenceDiagram
    participant S as Server (authenticator)
    participant P as Peer (supplicant)
    S->>P: Challenge — OpCode 1, 16-byte AuthenticatorChallenge
    P->>S: Response — OpCode 2, 49-byte value (Peer-Challenge + NT-Response)
    Note over S: verify NT-Response (constant-time), derive MPPE keys
    alt NT-Response matches
        S->>P: Success — OpCode 3, "S=<auth> M=<msg>"
        P->>S: Success ACK — OpCode 3
        Note over S,P: tunnelled → PEAP protected Result TLV;<br/>standalone → outer EAP-Success
    else NT-Response mismatch
        Note over S,P: tunnelled → end inner with error (EAP-Failure)
        S->>P: Failure — OpCode 4, "E=691 R=0 C=… V=3 M=…" (standalone)
        P->>S: Failure ACK — OpCode 4 (standalone)
        Note over S,P: standalone → outer EAP-Failure
    end
```

### Response value layout (RFC 2759 Section 4, 49 octets)

| Offset | Size | Field |
|--------|------|-------|
| 0  | 16 | Peer-Challenge |
| 16 | 8  | Reserved (MUST be zero) |
| 24 | 24 | NT-Response |
| 48 | 1  | Flags |

## Working logic & file map

| File | Responsibility |
|------|----------------|
| `payload.go` | Decodes/encodes the MS-CHAPv2 packet (`OpCode`, `MSCHAPv2ID`, `MS-Length`, `ValueSize`). `Handle`: issues the 16-byte server Challenge (from `crypto/rand` via `securecookie`), parses the peer Response, asks the consumer to authenticate, compares the expected vs received NT-Response with **`crypto/subtle.ConstantTimeCompare`**, then drives the verdict — tunnelled: Success → PEAP protected Result, or end-with-error; standalone: outer EAP-Success, or the Failure sub-protocol. `Decode` also accepts the peer's Success/Failure ack. `ModifyRADIUSResponse` attaches MS-MPPE-Recv/Send keys on Access-Accept. |
| `op_response.go` | `ParseResponse` validates the 49-octet Response: exact length, **all-zero reserved octets** (Section 4), and extracts Peer-Challenge / NT-Response / Flags. |
| `op_success.go` | `SuccessRequest.Encode` emits the Success packet (OpCode 3 + "S=…" Authenticator-Response); unlike Challenge it has no ValueSize octet. |
| `op_failure.go` | `FailureRequest.Encode` emits the standalone Failure packet (OpCode 4 + the RFC 2759 §6 "E=… R=… C=… V=… M=…" string); `formatFailureMessage` builds that string (E=691, R=0, fresh challenge, V=3). |
| `settings.go` | `AuthenticateRequest` / `AuthenticateRequestWithContext` are the consumer hooks returning the expected `NTResponse`, `AuthenticatorResponse`, and MPPE `RecvKey`/`SendKey`. `Standalone` selects the outer flow. `OnResult` is an optional side-effect hook reporting the password verdict (e.g. for access/reject auditing). `DebugStaticCredentials` is a fixed-credential helper for testing only. |
| `state.go` | Per-session `Challenge`, `PeerChallenge`, `AuthResponse`, `IsProtocolEnded`, and `AuthFailed` (awaiting the peer's Failure ack in standalone mode). |

## Security notes

- The server **never sees the password**; the consumer computes responses from a
  stored NT hash (RFC 2759 Section 8). NT-Response comparison is constant-time
  (`crypto/subtle`).
- The server Challenge is cryptographically random per session.
- MS-CHAPv2 is cryptographically weak in isolation. **Tunnelled mode** (PEAP) is
  the safe default — the exchange is protected by the TLS tunnel. **Standalone
  mode** is for transports that already provide a protected channel (e.g.
  EAP-MSCHAPv2 over IKEv2/IPsec); used bare on an open link it is exposed to
  offline cracking, so the consumer must only enable it over a protected transport.

## Tests

`payload_test.go` (decode/handle/MPPE, standalone success/failure, `OnResult`
verdict), `op_response_test.go` (RFC 2759 Section 4 layout, reserved-zero rule,
Type 26), `op_success_test.go` (Section 5 encoding), `op_failure_test.go` (RFC 2759
§6 Failure format), `settings_test.go` (RFC 2759/3079 material, determinism).
