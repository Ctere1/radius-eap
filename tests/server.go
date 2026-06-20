package tests

import (
	"context"
	ttls "crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	eap "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

// Server is a minimal RADIUS test harness driving the EAP library end-to-end via
// eapol_test. It uses the library's MemoryStateManager so the integration path
// exercises the same session store recommended to consumers.
type Server struct {
	rs     radius.PacketServer
	cert   ttls.Certificate
	config protocol.Settings
	states *eap.MemoryStateManager
}

func NewTestServer(t *testing.T) *Server {
	t.Helper()
	requireTestAsset(t, filepath.Join("certs", "cert_server.pem"))
	requireTestAsset(t, filepath.Join("certs", "cert_server.key"))

	s := &Server{}
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
	// config is populated by the test before Run; build the StateManager here.
	s.states = eap.NewMemoryStateManager(s.config, 5*time.Minute)
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
		s.states.Close()
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
		pkt, err := eap.Decode(s.states, ep)
		if err != nil {
			panic(err)
		}
		pkt.HandleRadiusPacket(w, r)
	}
}
