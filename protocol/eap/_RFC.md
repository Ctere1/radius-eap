# EAP core — RFC 3748

Implements the base **Extensible Authentication Protocol** framing and method
dispatch. Every other protocol in this repository is carried inside an EAP
packet decoded here.

## Specifications

- **RFC 3748** — Extensible Authentication Protocol (EAP). Primary reference.
- **RFC 5247** — EAP Key Management Framework (MSK/EMSK terminology used by the
  TLS/PEAP/MS-CHAPv2 key derivation).

## Packet format (RFC 3748 Section 4)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |  Type-Data ...
+-+-+-+-+-+-+-+-+
```

- **Code** (Section 4): `1`=Request, `2`=Response, `3`=Success, `4`=Failure
  (`protocol.Code*` in `protocol/packet.go`).
- **Identifier** (Section 4.1): aids matching Responses to Requests.
- **Length**: covers the whole packet; a mismatch is rejected.
- **Type** (Section 5): present only for Request/Response; selects the method.

## Working logic & file map

| File | Responsibility |
|------|----------------|
| `payload.go` | `Payload` is the decoded EAP packet. `Decode` validates the Length (`4 <= Length <= received`; a larger Length is discarded, and trailing octets beyond Length are link-layer padding that is ignored — RFC 3748 Section 4) and, for Request/Response, resolves the method `Payload` via `EmptyPayload` and recurses into it. Success/Failure carry no Type and skip method resolution. `Encode` re-serializes and back-fills `Length`. |
| `decode.go` | `EmptyPayload` performs **method type negotiation**: it scans the configured constructors for one whose `Type()` matches the offered type. For a tunneling method that wraps an inner payload (e.g. PEAP — a `tls.Payload` whose `HasInner()` is the PEAP payload), it returns the outer payload together with the **inner** Type code that must appear on the wire. |
| `state.go` | `State.PacketID` tracks the EAP Identifier across a method exchange. |

## Method type codes (IANA / RFC 3748 Section 5)

| Type | Method | Package |
|------|--------|---------|
| 1 | Identity | `protocol/identity` |
| 3 | Legacy Nak | `protocol/legacy_nak` |
| 6 | Generic Token Card (GTC) | `protocol/gtc` |
| 13 | EAP-TLS | `protocol/tls` |
| 25 | PEAP | `protocol/peap` |
| 26 | EAP-MS-CHAP-v2 | `protocol/mschapv2` |

## Identifier handling

The top-level driver (`../../handler.go`) increments the Identifier for each new
Request (`peer Response.ID + 1`) and echoes the Response Identifier on
Success/Failure, per RFC 3748 Sections 4.1-4.2.

## Tests

`payload_test.go` (framing, length validation), `decode_test.go` (type
negotiation incl. inner-type resolution), `state_test.go`.
