package tests

import (
	"context"
	ttls "crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"testing"

	eap "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/identity"
	"github.com/Ctere1/radius-eap/protocol/legacy_nak"
	"github.com/Ctere1/radius-eap/protocol/tls"
	"github.com/stretchr/testify/assert"
	"layeh.com/radius"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc3580"
)

// eapTLSVersions pins the EAP-TLS handshake to a specific TLS version so both
// the TLS 1.2 and TLS 1.3 paths are exercised end-to-end. A recent intermittent
// bug was TLS-1.2-specific (production uses 1.2) while the RFC 9190 protected-
// success handling is TLS-1.3-specific, so neither version may go untested.
var eapTLSVersions = []struct {
	name string
	ver  uint16
}{
	{"TLS1.2", ttls.VersionTLS12},
	{"TLS1.3", ttls.VersionTLS13},
}

func TestEAP_TLS(t *testing.T) {
	for _, tc := range eapTLSVersions {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := NewTestServer(t)
			// ident is written from the background TLS handshake callback and read by the
			// test goroutine, so guard it.
			var (
				identMu sync.Mutex
				ident   string
			)
			s.config = protocol.Settings{
				Logger: eap.DefaultLogger(),
				Protocols: []protocol.ProtocolConstructor{
					identity.Protocol,
					legacy_nak.Protocol,
					tls.Protocol,
				},
				ProtocolPriority: []protocol.Type{identity.TypeIdentity, tls.TypeTLS},
				ProtocolSettings: map[protocol.Type]interface{}{
					tls.TypeTLS: tls.Settings{
						Config: &ttls.Config{
							Certificates: []ttls.Certificate{s.cert},
							ClientAuth:   ttls.RequireAnyClientCert,
							MinVersion:   tc.ver,
							MaxVersion:   tc.ver,
						},
						HandshakeSuccessful: func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status {
							identMu.Lock()
							ident = ctx.GetProtocolState(identity.TypeIdentity).(*identity.State).Identity
							identMu.Unlock()
							ctx.AddResponseModifier(func(r, q *radius.Packet) error {
								_ = rfc2868.TunnelType_Set(r, 0x01, rfc3580.TunnelType_Value_VLAN)
								_ = rfc2868.TunnelMediumType_Set(r, 0x01, rfc2868.TunnelMediumType_Value_IEEE802)
								_ = rfc2868.TunnelPrivateGroupID_Set(r, 0x01, []byte{13})
								return nil
							})
							return protocol.StatusSuccess
						},
					},
				},
			}

			ctx, canc := context.WithCancel(context.Background())
			s.Run(ctx)
			t.Cleanup(canc)

			tr, st := EAPOLTest(t, "config/eap_tls.conf")
			assert.Equal(t, 0, st)
			assert.Equal(t, "SUCCESS", tr[len(tr)-2])
			identMu.Lock()
			got := ident
			identMu.Unlock()
			assert.Equal(t, "foo", got)
			assert.Contains(t, strings.Join(tr, "\n"), "Attribute 64 (Tunnel-Type) length=6\n      Value: 0100000d")
			assert.Contains(t, strings.Join(tr, "\n"), "Attribute 65 (Tunnel-Medium-Type) length=6\n      Value: 01000006")
			assert.Contains(t, strings.Join(tr, "\n"), "Attribute 81 (Tunnel-Private-Group-Id) length=4\n      Value: 010d")
		})
	}
}

func TestEAP_TLS_Reject(t *testing.T) {
	for _, tc := range eapTLSVersions {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := NewTestServer(t)
			s.config = protocol.Settings{
				Logger: eap.DefaultLogger(),
				Protocols: []protocol.ProtocolConstructor{
					identity.Protocol,
					legacy_nak.Protocol,
					tls.Protocol,
				},
				ProtocolPriority: []protocol.Type{tls.TypeTLS},
				ProtocolSettings: map[protocol.Type]interface{}{
					tls.TypeTLS: tls.Settings{
						Config: &ttls.Config{
							Certificates: []ttls.Certificate{s.cert},
							ClientAuth:   ttls.RequireAnyClientCert,
							MinVersion:   tc.ver,
							MaxVersion:   tc.ver,
						},
						HandshakeSuccessful: func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status {
							ctx.AddResponseModifier(func(r, q *radius.Packet) error {
								_ = rfc2868.TunnelType_Set(r, 0x01, rfc3580.TunnelType_Value_VLAN)
								_ = rfc2868.TunnelMediumType_Set(r, 0x01, rfc2868.TunnelMediumType_Value_IEEE802)
								_ = rfc2868.TunnelPrivateGroupID_Set(r, 0x01, []byte{13})
								return nil
							})
							return protocol.StatusError
						},
					},
				},
			}

			ctx, canc := context.WithCancel(context.Background())
			s.Run(ctx)
			t.Cleanup(canc)

			tr, st := EAPOLTest(t, "config/eap_tls.conf")
			assert.Equal(t, 252, st)
			assert.NotEqual(t, "SUCCESS", tr[len(tr)-2])
			assert.NotContains(t, strings.Join(tr, "\n"), "Attribute 64 (Tunnel-Type) length=6\n      Value: 0100000d")
			assert.NotContains(t, strings.Join(tr, "\n"), "Attribute 65 (Tunnel-Medium-Type) length=6\n      Value: 01000006")
			assert.NotContains(t, strings.Join(tr, "\n"), "Attribute 81 (Tunnel-Private-Group-Id) length=4\n      Value: 010d")
		})
	}
}
