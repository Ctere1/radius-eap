package protocol

import (
	"errors"
	"slices"
	"sync"
)

type StateManager interface {
	GetEAPSettings() Settings
	GetEAPState(string) *State
	SetEAPState(string, *State)
}

type ProtocolConstructor func() Payload

type Settings struct {
	Protocols        []ProtocolConstructor
	ProtocolPriority []Type
	ProtocolSettings map[Type]interface{}
	Logger           Logger
}

type State struct {
	Protocols        []ProtocolConstructor
	ProtocolIndex    int
	ProtocolPriority []Type
	TypeState        map[Type]any
	// SessionData is a free-form, session-scoped store shared across every
	// protocol (outer and inner) handled under the same RADIUS State. Consumers
	// use Context.SessionValue/SetSessionValue to stash request-spanning data
	// (resolved identity, certificates, OTP progress, response attributes)
	// without maintaining a parallel, separately-locked map. Access it only
	// through SessionValue/SetSessionValue, which guard it with sessionMu so it
	// is safe to use from callbacks that run on the background TLS handshake
	// goroutine (e.g. VerifyConnection, HandshakeSuccessful).
	SessionData map[string]any
	sessionMu   sync.RWMutex
}

// SessionValue returns the session-scoped value for key, or nil if absent.
func (st *State) SessionValue(key string) any {
	st.sessionMu.RLock()
	defer st.sessionMu.RUnlock()
	return st.SessionData[key]
}

// SetSessionValue stores a session-scoped value, lazily allocating the backing
// map. It is safe for concurrent use.
func (st *State) SetSessionValue(key string, value any) {
	st.sessionMu.Lock()
	defer st.sessionMu.Unlock()
	if st.SessionData == nil {
		st.SessionData = map[string]any{}
	}
	st.SessionData[key] = value
}

func (st *State) GetNextProtocol() (Type, error) {
	if st.ProtocolIndex >= len(st.ProtocolPriority) {
		return Type(0), errors.New("no more protocols to offer")
	}
	return st.ProtocolPriority[st.ProtocolIndex], nil
}

func BlankState(settings Settings) *State {
	return &State{
		Protocols:        slices.Clone(settings.Protocols),
		ProtocolPriority: slices.Clone(settings.ProtocolPriority),
		TypeState:        map[Type]any{},
		SessionData:      map[string]any{},
	}
}
