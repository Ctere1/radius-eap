package main

import (
	"context"
	ttls "crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	eap "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/gtc"
	"github.com/Ctere1/radius-eap/protocol/identity"
	"github.com/Ctere1/radius-eap/protocol/legacy_nak"
	"github.com/Ctere1/radius-eap/protocol/mschapv2"
	"github.com/Ctere1/radius-eap/protocol/peap"
	"github.com/Ctere1/radius-eap/protocol/tls"
	"layeh.com/radius"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3580"
)

type Server struct {
	rs   radius.PacketServer
	cert ttls.Certificate
	// eapStates is the library-provided StateManager: concurrency-safe with
	// time-based eviction, so abandoned EAP sessions cannot leak memory.
	eapStates *eap.MemoryStateManager
}

func main() {
	cert, err := ttls.LoadX509KeyPair("./examples/server/cert.pem", "./examples/server/key.pem")
	if err != nil {
		panic(err)
	}
	s := &Server{cert: cert}
	s.eapStates = eap.NewMemoryStateManager(eapSettings(cert), 5*time.Minute)
	defer s.eapStates.Close()

	s.rs = radius.PacketServer{
		Handler:      s,
		SecretSource: s,
		Addr:         "0.0.0.0:1812",
	}
	if err := s.rs.ListenAndServe(); err != nil {
		panic(err)
	}
}

func (s *Server) RADIUSSecret(ctx context.Context, remoteAddr net.Addr) ([]byte, error) {
	return []byte("foo"), nil
}

func (s *Server) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	ep := rfc2869.EAPMessage_Get(r.Packet)
	if len(ep) > 0 {
		ep, err := eap.Decode(s.eapStates, ep)
		if err != nil {
			panic(err)
		}
		ep.HandleRadiusPacket(w, r)
	}
}

func eapSettings(cert ttls.Certificate) protocol.Settings {
	return protocol.Settings{
		Logger: eap.DefaultLogger(),
		Protocols: []protocol.ProtocolConstructor{
			identity.Protocol,
			legacy_nak.Protocol,
			tls.Protocol,
			peap.Protocol,
		},
		ProtocolPriority: []protocol.Type{
			identity.TypeIdentity,
			tls.TypeTLS,
			peap.TypePEAP,
		},
		ProtocolSettings: map[protocol.Type]interface{}{
			tls.TypeTLS: tls.Settings{
				Config: &ttls.Config{
					Certificates: []ttls.Certificate{cert},
					ClientAuth:   ttls.RequireAnyClientCert,
				},
				HandshakeSuccessful: func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status {
					ident := ctx.GetProtocolState(identity.TypeIdentity).(*identity.State).Identity
					ctx.Log().Info("Successful handshake with Identity", "identity", ident)
					ctx.AddResponseModifier(func(r, q *radius.Packet) error {
						_ = rfc2868.TunnelType_Set(r, 0x01, rfc3580.TunnelType_Value_VLAN)
						_ = rfc2868.TunnelMediumType_Set(r, 0x01, rfc2868.TunnelMediumType_Value_IEEE802)
						_ = rfc2868.TunnelPrivateGroupID_Set(r, 0x01, []byte{13})
						return nil
					})
					return protocol.StatusSuccess
				},
			},
			peap.TypePEAP: peap.Settings{
				Config: &ttls.Config{
					Certificates: []ttls.Certificate{cert},
				},
				InnerProtocols: protocol.Settings{
					Protocols: []protocol.ProtocolConstructor{
						identity.Protocol,
						legacy_nak.Protocol,
						gtc.Protocol,
						mschapv2.Protocol,
					},
					ProtocolPriority: []protocol.Type{mschapv2.TypeMSCHAPv2, gtc.TypeGTC},
					ProtocolSettings: map[protocol.Type]interface{}{
						mschapv2.TypeMSCHAPv2: mschapv2.Settings{
							AuthenticateRequest: mschapv2.DebugStaticCredentials(
								[]byte("foo"), []byte("bar"),
							),
							ServerIdentifier: "radius-eap example",
						},
						gtc.TypeGTC: gtc.Settings{
							ChallengeHandler: func(ctx protocol.Context) (gtc.GetChallenge, gtc.ValidateResponse) {
								return func() []byte {
										return []byte("Enter OTP:")
									}, func(response []byte) protocol.Status {
										fmt.Printf("GTC Response: %s\n", string(response))
										// Demo: accept any non-empty answer. Return
										// StatusError to reject, or StatusUnknown to
										// re-prompt for another attempt.
										if len(response) == 0 {
											return protocol.StatusError
										}
										return protocol.StatusSuccess
									}
							},
						},
					},
				},
			},
		},
	}
}
