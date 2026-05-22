package tls

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/Ctere1/radius-eap/protocol"
)

type State struct {
	// statusMu synchronizes request processing with the background TLS handshake
	// goroutine when handshake completion and final status are observed.
	statusMu                    sync.RWMutex
	RemainingChunks             [][]byte
	HandshakeDone               bool
	FinalStatus                 protocol.Status
	ClientHello                 *tls.ClientHelloInfo
	MPPEKey                     []byte
	TotalPayloadSize            int
	IncludeLengthInNextFragment bool
	TLS                         *tls.Conn
	Conn                        *BuffConn
	Context                     context.Context
	ContextCancel               context.CancelFunc
	HandshakeCtx                protocol.Context
	Logger                      protocol.Logger
}

func NewState(c protocol.Context) any {
	c.Log().Debug("TLS: new state")
	return &State{
		RemainingChunks: make([][]byte, 0),
	}
}

func (s *State) HasMore() bool {
	return len(s.RemainingChunks) > 0
}

func (s *State) HandshakeDoneValue() bool {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.HandshakeDone
}

func (s *State) SetHandshakeDone(done bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.HandshakeDone = done
}

func (s *State) FinalStatusValue() protocol.Status {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.FinalStatus
}

func (s *State) SetFinalStatus(status protocol.Status) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.FinalStatus = status
}
