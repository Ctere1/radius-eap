# EAP Legacy Nak — RFC 3748 Section 5.3.1

EAP method **Type 3**. Sent by the *peer* (never offered by the server) to
reject the authentication Type the server proposed and to suggest an
alternative.

## Specification

- **RFC 3748 Section 5.3.1** — Legacy Nak.

## Working logic & file map

| File | Responsibility |
|------|----------------|
| `payload.go` | `Payload.DesiredType` is the method the peer would prefer. `Decode` reads the first Type-Data octet (rejecting an empty body). `Encode` writes that octet back. `Handle` ends the current inner method with `StatusError`; the top-level driver (`../../handler.go`) treats an inbound Nak as the signal to advance to the next method in `ProtocolPriority`. `Offerable()` returns `false` — the server never sends a Nak. |

## Protocol negotiation flow

1. Server offers method A (e.g. MS-CHAPv2).
2. Peer cannot/won't do A → replies with a Legacy Nak carrying `DesiredType` = B.
3. Driver advances `ProtocolIndex` and offers the next supported method,
   converging on a mutually supported one (or failing if none remain).

The library advances by **priority order**, using the peer's `DesiredType` as a
hint rather than blindly trusting it — this avoids a peer steering the server to
a weaker method that is not in the configured priority list.

## Tests

`payload_test.go` — Type code (Section 5.3.1), empty rejection, `DesiredType`
round-trip, `Handle` → `StatusError`, and `Offerable()==false`.
