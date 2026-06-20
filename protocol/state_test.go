package protocol

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetNextProtocolWalksPriority(t *testing.T) {
	st := &State{ProtocolPriority: []Type{1, 13, 25}}

	typ, err := st.GetNextProtocol()
	require.NoError(t, err)
	assert.Equal(t, Type(1), typ)

	st.ProtocolIndex = 2
	typ, err = st.GetNextProtocol()
	require.NoError(t, err)
	assert.Equal(t, Type(25), typ)
}

func TestGetNextProtocolExhausted(t *testing.T) {
	st := &State{ProtocolPriority: []Type{1}, ProtocolIndex: 1}
	_, err := st.GetNextProtocol()
	require.Error(t, err)
}

func TestBlankStateClonesSettings(t *testing.T) {
	settings := Settings{
		Protocols:        []ProtocolConstructor{func() Payload { return nil }},
		ProtocolPriority: []Type{1, 13},
	}

	st := BlankState(settings)
	require.NotNil(t, st)
	assert.Equal(t, settings.ProtocolPriority, st.ProtocolPriority)
	assert.NotNil(t, st.TypeState)
	assert.NotNil(t, st.SessionData)
	assert.Equal(t, 0, st.ProtocolIndex)

	// Mutating the clone's priority must not affect the original settings slice.
	st.ProtocolPriority[0] = 99
	assert.Equal(t, Type(1), settings.ProtocolPriority[0])
}

func TestSessionValueRoundTrip(t *testing.T) {
	st := BlankState(Settings{})
	assert.Nil(t, st.SessionValue("missing"))

	st.SetSessionValue("user", "alice")
	assert.Equal(t, "alice", st.SessionValue("user"))
}

func TestSetSessionValueLazilyAllocates(t *testing.T) {
	st := &State{} // no BlankState; SessionData is nil
	assert.Nil(t, st.SessionValue("k"))
	st.SetSessionValue("k", 42)
	assert.Equal(t, 42, st.SessionValue("k"))
}

func TestSessionValueConcurrentAccessIsSafe(t *testing.T) {
	// Both the handshake goroutine and the handler may touch SessionData; the
	// accessors must be race-free (run under -race).
	st := BlankState(Settings{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); st.SetSessionValue("k", 1) }()
		go func() { defer wg.Done(); _ = st.SessionValue("k") }()
	}
	wg.Wait()
}
