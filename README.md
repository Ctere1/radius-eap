[![Go Report Card](https://goreportcard.com/badge/github.com/Ctere1/radius-eap)](https://goreportcard.com/report/github.com/Ctere1/radius-eap)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/Ctere1/radius-eap)](https://pkg.go.dev/github.com/Ctere1/radius-eap)

# radius-eap

A production-oriented implementation of common **EAP** methods for **RADIUS** in
Go — **race-free**, **state-safe**, and tested clause-by-clause against the
relevant RFCs.

## Supported methods

| EAP method           | Type | Specification                  |
| -------------------- | ---- | ------------------------------ |
| Identity             | 1    | RFC 3748 Section 5.1           |
| Legacy Nak           | 3    | RFC 3748 Section 5.3.1         |
| GTC (OTP, in-tunnel) | 6    | RFC 3748 Section 5.6           |
| EAP-TLS              | 13   | RFC 5216 / RFC 9190            |
| PEAP (PEAPv0)        | 25   | draft-josefsson / draft-kamath |
| MS-CHAP-v2           | 26   | RFC 2759 / RFC 3079            |

## Documentation

Architecture and per-protocol RFC references live in [`_RFC.md`](_RFC.md), which
indexes a detailed document (with diagrams) for each protocol. Start there to see
how a protocol works and which file/function implements which RFC clause.

## Usage

Implement `protocol.StateManager` (or use the bundled
`eap.NewMemoryStateManager`, a concurrency-safe store with TTL eviction), then
decode the EAP-Message from each RADIUS request and let the library drive the
exchange:

```go
sm := eap.NewMemoryStateManager(settings, 5*time.Minute)
defer sm.Close()

func (s *Server) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
    raw := rfc2869.EAPMessage_Get(r.Packet)
    if len(raw) == 0 {
        return
    }
    pkt, err := eap.Decode(sm, raw)
    if err != nil {
        return
    }
    pkt.HandleRadiusPacket(w, r) // writes Access-Challenge/Accept/Reject
}
```

See [`examples/server`](examples/server) for a complete EAP-TLS + PEAP-MSCHAPv2
server.

## Testing

```sh
make test       # unit tests + eapol_test integration
make test-race  # the full suite under the race detector
```

Integration tests use `eapol_test` (`sudo apt install eapoltest`) and a minimal
PKI (a CA, a server certificate, and — for EAP-TLS — a client certificate). Run a
client against the server with:

```sh
eapol_test -c peap.conf -s foo -a <radius-server-ip>
```

### PEAP (phase 2: MS-CHAP-v2)

```
network={
    ssid="DoesNotMatterForThisTest"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="foo"
    password="bar"
    ca_cert="ca.pem"
    phase2="auth=MSCHAPV2"
}
```

### EAP-TLS

```
network={
    ssid="DoesNotMatterForThisTest"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="foo"
    ca_cert="ca.pem"
    client_cert="cert_client.pem"
    private_key="cert_client.key"
    eapol_flags=3
    eap_workaround=0
}
```

## Acknowledgements

Originally forked from [BeryJu/radius-eap](https://github.com/BeryJu/radius-eap);
see BeryJu's write-up [Implementing EAP](https://beryju.io/blog/2025-05-implementing-eap/).
This fork has since been substantially reworked (race-free EAP-TLS transport,
session-safe state handling, DoS hardening, RFC documentation, and expanded
tests).
