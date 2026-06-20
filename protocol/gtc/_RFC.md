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
| `payload.go` | `Payload.Challenge` is the displayable prompt. `Decode` stores the peer's raw reply; `Encode` emits the challenge text. `Handle`: on method start it obtains `(GetChallenge, ValidateResponse)` from the consumer and returns the first challenge; on a subsequent packet it feeds the peer's reply to `ValidateResponse` and re-issues a challenge. Invalid settings or nil callbacks end the method with `StatusError`. |
| `settings.go` | `Settings.ChallengeHandler` lets the consumer plug in OTP generation/validation. `GetChallenge` returns the prompt; `ValidateResponse` decides success/failure (it calls `ctx.EndInnerProtocol`). |
| `state.go` | `State` carries the per-session `getChallenge`/`validateResponse` closures across round-trips. |

## Result signalling

GTC itself has no explicit success/failure packet; the *consumer's*
`ValidateResponse` callback decides the outcome by calling
`ctx.EndInnerProtocol(StatusSuccess|StatusError)`. The PEAP layer then conveys
the result to the peer via a protected Result TLV (see `../peap/_RFC.md`).

## Tests

`payload_test.go` — Type code (Section 5.6), challenge issue/re-issue, response
forwarding to the validator, and rejection of invalid settings / nil callbacks.
