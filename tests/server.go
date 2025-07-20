package tests

import (
	"context"
	ttls "crypto/tls"
	"errors"
	"net"
	"testing"

	eap "beryju.io/radius-eap"
	"beryju.io/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

type Server struct {
	rs       radius.PacketServer
	eapState map[string]*protocol.State
	cert     ttls.Certificate
	config   protocol.Settings
}

func NewTestServer(t *testing.T) *Server {
	s := &Server{
		eapState: map[string]*protocol.State{},
	}
	s.rs = radius.PacketServer{
		Handler:      s,
		SecretSource: s,
		Addr:         "0.0.0.0:1812",
	}
	cert, err := ttls.LoadX509KeyPair("./certs/cert_server.pem", "./certs/cert_server.key")
	assert.NoError(t, err)
	s.cert = cert
	return s
}

func (s *Server) Run(ctx context.Context) {
	go func() {
		err := s.rs.ListenAndServe()
		if errors.Is(err, radius.ErrServerShutdown) {
			return
		} else if err != nil {
			panic(err)
		}
	}()
	go func() {
		<-ctx.Done()
		err := s.rs.Shutdown(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()
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
	return s.config
}
