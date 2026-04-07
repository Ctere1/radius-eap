package tls

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/Ctere1/radius-eap/protocol"
)

type State struct {
	mu                          sync.RWMutex
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.HandshakeDone
}

func (s *State) SetHandshakeDone(done bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.HandshakeDone = done
}

func (s *State) FinalStatusValue() protocol.Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.FinalStatus
}

func (s *State) SetFinalStatus(status protocol.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FinalStatus = status
}
