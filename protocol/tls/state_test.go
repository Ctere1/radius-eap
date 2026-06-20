package tls

import (
	"sync"
	"testing"

	eap "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStateInitializesChannels(t *testing.T) {
	st := NewState(testContext{log: eap.DefaultLogger()}).(*State)
	require.NotNil(t, st.HandshakeDoneCh)
	require.NotNil(t, st.HandshakeErrCh)
	require.NotNil(t, st.RemainingChunks)
	assert.False(t, st.HandshakeDoneValue())
	assert.Equal(t, protocol.StatusUnknown, st.FinalStatusValue())
}

func TestStateHasMore(t *testing.T) {
	st := &State{}
	assert.False(t, st.HasMore())
	st.RemainingChunks = [][]byte{{0x01}}
	assert.True(t, st.HasMore())
}

func TestStateHandshakeDoneRoundTrip(t *testing.T) {
	st := &State{}
	assert.False(t, st.HandshakeDoneValue())
	st.SetHandshakeDone(true)
	assert.True(t, st.HandshakeDoneValue())
}

func TestStateFinalStatusRoundTrip(t *testing.T) {
	st := &State{}
	assert.Equal(t, protocol.StatusUnknown, st.FinalStatusValue())
	st.SetFinalStatus(protocol.StatusSuccess)
	assert.Equal(t, protocol.StatusSuccess, st.FinalStatusValue())
}

func TestSignalHandshakeDoneIsIdempotentAndClosesChannel(t *testing.T) {
	st := &State{HandshakeDoneCh: make(chan struct{})}
	st.signalHandshakeDone()
	st.signalHandshakeDone() // must not panic on a second close

	select {
	case <-st.HandshakeDoneCh:
	default:
		t.Fatal("HandshakeDoneCh should be closed")
	}
}

func TestSignalHandshakeErrorIsIdempotentAndClosesChannel(t *testing.T) {
	st := &State{HandshakeErrCh: make(chan struct{})}
	st.signalHandshakeError()
	st.signalHandshakeError()

	select {
	case <-st.HandshakeErrCh:
	default:
		t.Fatal("HandshakeErrCh should be closed")
	}
}

func TestSignalHandshakeNilChannelIsSafe(t *testing.T) {
	st := &State{} // nil channels (as in unit tests that drive callbacks directly)
	assert.NotPanics(t, st.signalHandshakeDone)
	assert.NotPanics(t, st.signalHandshakeError)
}

func TestStateStatusAccessorsAreConcurrencySafe(t *testing.T) {
	// The handshake goroutine writes while the handler reads; the helpers must
	// be race-free (run under -race).
	st := &State{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); st.SetHandshakeDone(true); st.SetFinalStatus(protocol.StatusSuccess) }()
		go func() { defer wg.Done(); _ = st.HandshakeDoneValue(); _ = st.FinalStatusValue() }()
	}
	wg.Wait()
}
