# EAP-Identity — RFC 3748 Section 5.1

EAP method **Type 1**. The first exchange of almost every EAP conversation: the
server asks "who are you?" and the peer answers with an NAI/username. It is
informational only — it performs no authentication.

## Specification

- **RFC 3748 Section 5.1** — Identity.

## Working logic & file map

| File | Responsibility |
|------|----------------|
| `payload.go` | `Payload.Identity` holds the peer's claimed identity. `Decode` reads the Type-Data as a UTF-8 string and rejects an empty value. `Encode` emits no Type-Data (the server's Identity *Request* has none). `Handle` stores the identity in `State` and ends the method with `StatusNextProtocol`, signalling the driver to offer the next (real) authentication method. |
| `state.go` | `State.Identity` — the recorded identity, later read by inner methods (e.g. MS-CHAPv2 username lookup). |

## Notes

- Per RFC 3748 Section 5.1 the Identity Response is **not** trustworthy on its own; it
  must be confirmed by a subsequent authenticating method. Here `Handle` only
  records it and advances.
- The identity may be truncated/obfuscated by the peer (privacy NAI). Consumers
  that need the *authenticated* identity should use the result of the inner
  method, not this value.

## Tests

`payload_test.go` — Type code (Section 5.1), empty rejection, identity decode, and the
`Handle` → `StatusNextProtocol` transition.
