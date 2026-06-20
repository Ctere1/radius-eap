package eap

import (
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EmptyPayload implements EAP type negotiation: given an offered EAP Type it
// returns the payload constructor whose Type matches, OR — for tunneling
// protocols that wrap an inner payload (e.g. PEAP, which is a tls.Payload
// carrying an inner peap.Payload) — the outer payload together with the inner
// Type code that should appear on the wire.

type fakePayload struct {
	typ   protocol.Type
	inner protocol.Payload
}

func (p *fakePayload) Type() protocol.Type                      { return p.typ }
func (p *fakePayload) Decode([]byte) error                      { return nil }
func (p *fakePayload) Encode() ([]byte, error)                  { return nil, nil }
func (p *fakePayload) Offerable() bool                          { return true }
func (p *fakePayload) String() string                           { return "fake" }
func (p *fakePayload) Handle(protocol.Context) protocol.Payload { return nil }
func (p *fakePayload) HasInner() protocol.Payload               { return p.inner }

func settingsWith(constructors ...protocol.ProtocolConstructor) protocol.Settings {
	return protocol.Settings{Protocols: constructors}
}

func TestEmptyPayloadDirectTypeMatch(t *testing.T) {
	s := settingsWith(func() protocol.Payload { return &fakePayload{typ: 6} })

	np, typ, err := EmptyPayload(s, 6)
	require.NoError(t, err)
	assert.Equal(t, protocol.Type(6), typ)
	assert.Equal(t, protocol.Type(6), np.Type())
}

func TestEmptyPayloadResolvesInnerType(t *testing.T) {
	// Outer payload reports Type 13 (TLS) but wraps an inner of Type 25 (PEAP).
	// Offering Type 25 must return the outer payload with the inner Type code.
	s := settingsWith(func() protocol.Payload {
		return &fakePayload{typ: 13, inner: &fakePayload{typ: 25}}
	})

	np, typ, err := EmptyPayload(s, 25)
	require.NoError(t, err)
	assert.Equal(t, protocol.Type(25), typ, "wire type should be the inner type")
	assert.Equal(t, protocol.Type(13), np.Type(), "returned payload is the outer wrapper")
}

func TestEmptyPayloadUnsupportedType(t *testing.T) {
	s := settingsWith(func() protocol.Payload { return &fakePayload{typ: 1} })

	np, _, err := EmptyPayload(s, 99)
	require.Error(t, err)
	assert.Nil(t, np)
}

func TestEmptyPayloadFirstMatchWins(t *testing.T) {
	s := settingsWith(
		func() protocol.Payload { return &fakePayload{typ: 1} },
		func() protocol.Payload { return &fakePayload{typ: 6} },
	)

	np, typ, err := EmptyPayload(s, 6)
	require.NoError(t, err)
	assert.Equal(t, protocol.Type(6), typ)
	assert.Equal(t, protocol.Type(6), np.Type())
}
