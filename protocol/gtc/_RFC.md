# EAP-GTC — RFC 3748 Section 5.6

EAP method **Type 6**, Generic Token Card. A simple challenge/response carrying
a human-readable prompt and a cleartext reply — in practice used inside a
protected tunnel (PEAP phase 2) for one-time passwords (OTP).

## Specification

- **RFC 3748 Section 5.6** — Generic Token Card (GTC).

## Security model

GTC sends the response **in cleartext**. It MUST only be run inside a TLS tunnel
(PEAP) so the OTP is never exposed on the wire. This package is therefore
registered as an *inner* protocol of PEAP, never as an outer EAP method.

## Working logic & file map

| File | Responsibility |
|------|----------------|
| `payload.go` | `Payload.Challenge` is the displayable prompt. `Decode` stores the peer's raw reply; `Encode` emits the challenge text. `Handle`: on method start it obtains `(GetChallenge, ValidateResponse)` from the consumer and returns the first challenge; on a subsequent packet it feeds the peer's reply to `ValidateResponse` and acts on the returned `protocol.Status` (see *Result signalling*). Invalid settings or nil callbacks end the method with `StatusError`. |
| `settings.go` | `Settings.ChallengeHandler` lets the consumer plug in OTP generation/validation. `GetChallenge` returns the prompt; `ValidateResponse` returns a `protocol.Status` deciding the outcome. It MUST NOT call `ctx.EndInnerProtocol` itself — the closures capture the context from the round in which the challenge handler first ran, so ending the protocol through that stale context never terminates the conversation. |
| `state.go` | `State` carries the per-session `getChallenge`/`validateResponse` closures across round-trips. |

## Result signalling

GTC has no explicit success/failure packet of its own; the *consumer's*
`ValidateResponse` callback returns a `protocol.Status` that `Payload.Handle`
applies against the **current** request context:

| Returned status | GTC payload action |
|-----------------|--------------------|
| `StatusSuccess` | Emits a protected success Result TLV (`peap.ExtensionPayload`, `AVPAckResult = success`). PEAP forwards it, awaits the peer's acknowledgement, and ends the inner method successfully — the same completion path MS-CHAPv2 uses. |
| `StatusError`   | Ends the method on the current context (`ctx.EndInnerProtocol(StatusError)`), so the tunnel emits EAP-Failure. |
| `StatusUnknown` | Undecided (e.g. a wrong answer with retries remaining): re-issues the challenge for another attempt. |

Returning the decision — rather than calling `ctx.EndInnerProtocol` from inside
the captured-context callback — is what makes a multi-round GTC exchange (OTP
retries) terminate correctly. The PEAP layer turns the Result TLV into the
protected success/failure conveyed to the peer (see `../peap/_RFC.md`).

## Tests

`payload_test.go` — Type code (Section 5.6), challenge issue, validator
forwarding, the three `ValidateResponse` outcomes (success → Result TLV, error →
`EndInnerProtocol`, undecided → re-challenge), and rejection of invalid settings /
nil callbacks.
