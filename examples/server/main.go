package main

import (
	"context"
	ttls "crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	eap "beryju.io/radius-eap"
	"beryju.io/radius-eap/protocol"
	"beryju.io/radius-eap/protocol/gtc"
	"beryju.io/radius-eap/protocol/identity"
	"beryju.io/radius-eap/protocol/legacy_nak"
	"beryju.io/radius-eap/protocol/mschapv2"
	"beryju.io/radius-eap/protocol/peap"
	"beryju.io/radius-eap/protocol/tls"
	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

type Server struct {
	rs       radius.PacketServer
	eapState map[string]*protocol.State
	cert     ttls.Certificate
}

func main() {
	s := &Server{
		eapState: map[string]*protocol.State{},
	}
	s.rs = radius.PacketServer{
		Handler:      s,
		SecretSource: s,
		Addr:         "0.0.0.0:1812",
	}
	cert, err := ttls.LoadX509KeyPair("./cert.pem", "./key.pem")
	if err != nil {
		panic(err)
	}
	s.cert = cert
	err = s.rs.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func (s *Server) RADIUSSecret(ctx context.Context, remoteAddr net.Addr) ([]byte, error) {
	return []byte("foo"), nil
}

func (s *Server) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	ep := rfc2869.EAPMessage_Get(r.Packet)
	if len(ep) > 0 {
		ep, err := eap.Decode(s, ep)
		if err != nil {
			panic(err)
		}
		ep.HandleRadiusPacket(w, r)
	}
}

func (s *Server) GetEAPState(key string) *protocol.State {
	return s.eapState[key]
}

func (s *Server) SetEAPState(key string, state *protocol.State) {
	s.eapState[key] = state
}

func (s *Server) GetEAPSettings() protocol.Settings {
	return protocol.Settings{
		Protocols: []protocol.ProtocolConstructor{
			identity.Protocol,
			legacy_nak.Protocol,
			tls.Protocol,
			peap.Protocol,
		},
		ProtocolPriority: []protocol.Type{tls.TypeTLS, peap.TypePEAP},
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
			peap.TypePEAP: peap.Settings{
				Config: &ttls.Config{
					Certificates: []ttls.Certificate{s.cert},
				},
				InnerProtocols: protocol.Settings{
					Protocols: []protocol.ProtocolConstructor{
						identity.Protocol,
						legacy_nak.Protocol,
						gtc.Protocol,
						mschapv2.Protocol,
					},
					ProtocolPriority: []protocol.Type{gtc.TypeGTC, mschapv2.TypeMSCHAPv2},
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
										return []byte("challenge")
									}, func(answer []byte) {
										fmt.Println(string(answer))
									}
							},
						},
					},
				},
			},
		},
	}
}
