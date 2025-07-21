package tests

import (
	"context"
	ttls "crypto/tls"
	"crypto/x509"
	"strings"
	"testing"

	"beryju.io/radius-eap/protocol"
	"beryju.io/radius-eap/protocol/identity"
	"beryju.io/radius-eap/protocol/legacy_nak"
	"beryju.io/radius-eap/protocol/tls"
	"github.com/stretchr/testify/assert"
	"layeh.com/radius"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc3580"
)

func TestEAP_TLS(t *testing.T) {
	s := NewTestServer(t)
	s.config = protocol.Settings{
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
				},
				HandshakeSuccessful: func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status {
					ctx.AddResponseModifier(func(r, q *radius.Packet) error {
						rfc2868.TunnelType_Set(r, 0x01, rfc3580.TunnelType_Value_VLAN)
						rfc2868.TunnelMediumType_Set(r, 0x01, rfc2868.TunnelMediumType_Value_IEEE802)
						rfc2868.TunnelPrivateGroupID_Set(r, 0x01, []byte{13})
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
	assert.Contains(t, strings.Join(tr, "\n"), "Attribute 64 (Tunnel-Type) length=6\n      Value: 0100000d")
	assert.Contains(t, strings.Join(tr, "\n"), "Attribute 65 (Tunnel-Medium-Type) length=6\n      Value: 01000006")
	assert.Contains(t, strings.Join(tr, "\n"), "Attribute 81 (Tunnel-Private-Group-Id) length=4\n      Value: 010d")
}

func TestEAP_TLS_Reject(t *testing.T) {
	s := NewTestServer(t)
	s.config = protocol.Settings{
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
				},
				HandshakeSuccessful: func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status {
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
}
