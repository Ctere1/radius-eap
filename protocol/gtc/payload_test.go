package gtc

import (
	"testing"

	eaproot "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
)

// testContext is a minimal protocol.Context for exercising the GTC payload.
type testContext struct {
	settings     interface{}
	state        interface{}
	stateStored  interface{}
	protocolDone bool
	endStatus    protocol.Status
}

func (t *testContext) Packet() *radius.Request       { return nil }
func (t *testContext) RootPayload() protocol.Payload { return nil }
func (t *testContext) State() string                 { return "" }
func (t *testContext) ProtocolSettings() interface{} { return t.settings }
func (t *testContext) GetProtocolState(protocol.Type) interface{} {
	return t.state
}
func (t *testContext) SetProtocolState(_ protocol.Type, s interface{})                { t.stateStored = s }
func (t *testContext) IsProtocolStart(protocol.Type) bool                             { return !t.protocolDone }
func (t *testContext) ModifyRADIUSResponse(*radius.Packet, *radius.Packet) error      { return nil }
func (t *testContext) AddResponseModifier(func(*radius.Packet, *radius.Packet) error) {}
func (t *testContext) HandleInnerEAP(protocol.Payload, protocol.StateManager) (protocol.Payload, error) {
	return nil, nil
}
func (t *testContext) Inner(protocol.Payload, protocol.Type) protocol.Context { return t }
func (t *testContext) EndInnerProtocol(s protocol.Status)                     { t.endStatus = s }
func (t *testContext) Log() protocol.Logger                                   { return eaproot.DefaultLogger() }
func (t *testContext) SessionValue(string) any                                { return nil }
func (t *testContext) SetSessionValue(string, any)                            {}

func validSettings() Settings {
	return Settings{
		ChallengeHandler: func(protocol.Context) (GetChallenge, ValidateResponse) {
			return func() []byte { return nil }, func([]byte) {}
		},
	}
}

func TestTypeIsRFC3748GTC(t *testing.T) {
	// RFC 3748 Section 5.6 assigns EAP Type 6 to Generic Token Card.
	assert.Equal(t, protocol.Type(6), TypeGTC)
	assert.Equal(t, TypeGTC, (&Payload{}).Type())
}

func TestEncodeReturnsChallenge(t *testing.T) {
	p := &Payload{Challenge: []byte("One-time password:")}
	raw, err := p.Encode()
	require.NoError(t, err)
	assert.Equal(t, []byte("One-time password:"), raw)
}

func TestDecodeStoresRawResponse(t *testing.T) {
	p := &Payload{}
	require.NoError(t, p.Decode([]byte("123456")))
	// The decoded answer is forwarded to the validator on Handle.
	var got []byte
	ctx := &testContext{
		settings:     validSettings(),
		protocolDone: true,
		state: &State{
			getChallenge:     func() []byte { return []byte("again") },
			validateResponse: func(answer []byte) { got = answer },
		},
	}
	p.Handle(ctx)
	assert.Equal(t, []byte("123456"), got)
}

func TestHandleStartIssuesChallenge(t *testing.T) {
	ctx := &testContext{
		settings: Settings{
			ChallengeHandler: func(protocol.Context) (GetChallenge, ValidateResponse) {
				return func() []byte { return []byte("Enter OTP:") }, func([]byte) {}
			},
		},
	}
	p := &Payload{}

	out := p.Handle(ctx)
	require.NotNil(t, out)
	resp, ok := out.(*Payload)
	require.True(t, ok)
	assert.Equal(t, []byte("Enter OTP:"), resp.Challenge)
	assert.NotNil(t, ctx.stateStored, "GTC state must be persisted")
}

func TestHandleResponseRevalidatesAndReissues(t *testing.T) {
	validated := false
	ctx := &testContext{
		settings:     validSettings(),
		protocolDone: true,
		state: &State{
			getChallenge:     func() []byte { return []byte("Enter OTP:") },
			validateResponse: func([]byte) { validated = true },
		},
	}
	p := &Payload{}
	require.NoError(t, p.Decode([]byte("000000")))

	out := p.Handle(ctx)
	assert.True(t, validated)
	require.NotNil(t, out)
	assert.Equal(t, []byte("Enter OTP:"), out.(*Payload).Challenge)
}

func TestHandleRejectsInvalidSettings(t *testing.T) {
	ctx := &testContext{settings: "not gtc settings"}
	out := (&Payload{}).Handle(ctx)
	assert.Nil(t, out)
	assert.Equal(t, protocol.StatusError, ctx.endStatus)
}

func TestHandleRejectsNilCallbacks(t *testing.T) {
	ctx := &testContext{
		settings: Settings{
			ChallengeHandler: func(protocol.Context) (GetChallenge, ValidateResponse) { return nil, nil },
		},
	}
	out := (&Payload{}).Handle(ctx)
	assert.Nil(t, out)
	assert.Equal(t, protocol.StatusError, ctx.endStatus)
}
