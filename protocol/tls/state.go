package tls

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/Ctere1/radius-eap/protocol"
)

// State is the per-session state for the EAP-TLS / PEAP outer layer. One State
// lives for the whole TLS exchange of a single EAP session and is persisted
// between RADIUS round-trips by the StateManager.
//
// Concurrency model: the TLS handshake runs on a dedicated background goroutine
// (started in tlsInit) while each RADIUS packet is processed on a separate
// handler goroutine. The two communicate through Conn (a race-free BuffConn) and
// through the synchronization fields below. Every field that both goroutines may
// touch is accessed only through the helper methods on State, never directly, so
// the locking stays in one place.
type State struct {
	// --- TLS connection and its lifetime ---

	// TLS is the server side of the in-memory TLS connection; Conn is the
	// byte pipe it reads from / writes to. Context (with ContextCancel) bounds
	// the whole handshake to staleConnectionTimeout and is cancelled when the
	// exchange ends. ClientHello captures the peer's hello for inspection.
	TLS           *tls.Conn
	Conn          *BuffConn
	Context       context.Context
	ContextCancel context.CancelFunc
	ClientHello   *tls.ClientHelloInfo

	// --- Handshake completion synchronization ---
	//
	// statusMu guards HandshakeDone and FinalStatus, which the background
	// handshake goroutine writes and the handler goroutine reads. Use the
	// HandshakeDoneValue/SetHandshakeDone and FinalStatusValue/SetFinalStatus
	// helpers rather than the fields directly.
	//
	// HandshakeDoneCh / HandshakeErrCh are closed exactly once (guarded by
	// doneOnce / errOnce via signalHandshakeDone / signalHandshakeError) to let
	// the handler block on completion through a select instead of polling.
	statusMu      sync.RWMutex
	HandshakeDone bool
	FinalStatus   protocol.Status

	HandshakeDoneCh chan struct{}
	HandshakeErrCh  chan struct{}
	doneOnce        sync.Once
	errOnce         sync.Once

	// --- Outbound fragmentation (server -> peer) ---
	//
	// A TLS flight larger than maxChunkSize is split into RemainingChunks and
	// sent across several EAP-TLS fragments. TotalPayloadSize is the original
	// size advertised in the first fragment's Length field, and
	// IncludeLengthInNextFragment marks that first fragment.
	RemainingChunks             [][]byte
	TotalPayloadSize            int
	IncludeLengthInNextFragment bool

	// reassembler reassembles fragmented peer flights (peer -> server) at the
	// EAP layer so Conn only ever sees complete TLS flights.
	reassembler inboundReassembler

	// --- Results / plumbing ---

	// MPPEKey is the exported keying material (RFC 5216) used to derive the
	// MS-MPPE-Recv/Send keys returned on Access-Accept.
	MPPEKey []byte
	// HandshakeCtx is the protocol.Context handed to the handshake-completion
	// callbacks; Logger is the session logger.
	HandshakeCtx protocol.Context
	Logger       protocol.Logger
}

// signalHandshakeDone closes HandshakeDoneCh exactly once. It is safe to call on
// a state with a nil channel (e.g. in unit tests that drive tlsHandshakeFinished
// directly).
func (s *State) signalHandshakeDone() {
	s.doneOnce.Do(func() {
		if s.HandshakeDoneCh != nil {
			close(s.HandshakeDoneCh)
		}
	})
}

// signalHandshakeError closes HandshakeErrCh exactly once.
func (s *State) signalHandshakeError() {
	s.errOnce.Do(func() {
		if s.HandshakeErrCh != nil {
			close(s.HandshakeErrCh)
		}
	})
}

func NewState(c protocol.Context) any {
	c.Log().Debug("TLS: new state")
	return &State{
		RemainingChunks: make([][]byte, 0),
		HandshakeDoneCh: make(chan struct{}),
		HandshakeErrCh:  make(chan struct{}),
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
