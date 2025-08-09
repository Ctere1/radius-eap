package tests

import (
	"context"
	ttls "crypto/tls"
	"testing"

	eap "beryju.io/radius-eap"
	"beryju.io/radius-eap/protocol"
	"beryju.io/radius-eap/protocol/identity"
	"beryju.io/radius-eap/protocol/legacy_nak"
	"beryju.io/radius-eap/protocol/mschapv2"
	"beryju.io/radius-eap/protocol/peap"
	"github.com/stretchr/testify/assert"
)

func TestEAP_PEAP_MSCHAPv2(t *testing.T) {
	s := NewTestServer(t)
	s.config = protocol.Settings{
		Logger: eap.DefaultLogger(),
		Protocols: []protocol.ProtocolConstructor{
			identity.Protocol,
			legacy_nak.Protocol,
			peap.Protocol,
		},
		ProtocolPriority: []protocol.Type{peap.TypePEAP},
		ProtocolSettings: map[protocol.Type]interface{}{
			peap.TypePEAP: peap.Settings{
				Config: &ttls.Config{
					Certificates: []ttls.Certificate{s.cert},
				},
				InnerProtocols: protocol.Settings{
					Protocols: []protocol.ProtocolConstructor{
						identity.Protocol,
						legacy_nak.Protocol,
						mschapv2.Protocol,
					},
					ProtocolPriority: []protocol.Type{mschapv2.TypeMSCHAPv2},
					ProtocolSettings: map[protocol.Type]interface{}{
						mschapv2.TypeMSCHAPv2: mschapv2.Settings{
							AuthenticateRequest: mschapv2.DebugStaticCredentials(
								[]byte("foo"), []byte("bar"),
							),
							ServerIdentifier: "radius-eap example",
						},
					},
				},
			},
		},
	}

	ctx, canc := context.WithCancel(context.Background())
	s.Run(ctx)
	t.Cleanup(canc)

	tr, st := EAPOLTest(t, "config/peap_mschap.conf")
	assert.Equal(t, 0, st)
	assert.Equal(t, "SUCCESS", tr[len(tr)-2])
}

func TestEAP_PEAP_MSCHAPv2_Reject(t *testing.T) {
	s := NewTestServer(t)
	s.config = protocol.Settings{
		Logger: eap.DefaultLogger(),
		Protocols: []protocol.ProtocolConstructor{
			identity.Protocol,
			legacy_nak.Protocol,
			peap.Protocol,
		},
		ProtocolPriority: []protocol.Type{peap.TypePEAP},
		ProtocolSettings: map[protocol.Type]interface{}{
			peap.TypePEAP: peap.Settings{
				Config: &ttls.Config{
					Certificates: []ttls.Certificate{s.cert},
				},
				InnerProtocols: protocol.Settings{
					Protocols: []protocol.ProtocolConstructor{
						identity.Protocol,
						legacy_nak.Protocol,
						mschapv2.Protocol,
					},
					ProtocolPriority: []protocol.Type{mschapv2.TypeMSCHAPv2},
					ProtocolSettings: map[protocol.Type]interface{}{
						mschapv2.TypeMSCHAPv2: mschapv2.Settings{
							AuthenticateRequest: mschapv2.DebugStaticCredentials(
								[]byte("foo"), []byte("baz"),
							),
							ServerIdentifier: "radius-eap example",
						},
					},
				},
			},
		},
	}

	ctx, canc := context.WithCancel(context.Background())
	s.Run(ctx)
	t.Cleanup(canc)

	tr, st := EAPOLTest(t, "config/peap_mschap.conf")
	assert.Equal(t, 252, st)
	assert.NotEqual(t, "SUCCESS", tr[len(tr)-2])
}
