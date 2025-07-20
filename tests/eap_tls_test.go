package tests

import (
	"context"
	ttls "crypto/tls"
	"crypto/x509"
	"testing"

	"beryju.io/radius-eap/protocol"
	"beryju.io/radius-eap/protocol/identity"
	"beryju.io/radius-eap/protocol/legacy_nak"
	"beryju.io/radius-eap/protocol/tls"
	"github.com/stretchr/testify/assert"
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
