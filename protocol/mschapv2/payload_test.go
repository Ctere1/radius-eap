package mschapv2

import (
	"testing"

	eaproot "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/eap"
	"github.com/Ctere1/radius-eap/protocol/peap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
	"layeh.com/radius/vendors/microsoft"
)

func TestDecodeRejectsShortPayload(t *testing.T) {
	p := &Payload{}

	err := p.Decode([]byte{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecodeRejectsTruncatedResponse(t *testing.T) {
	p := &Payload{}
	raw := []byte{byte(OpResponse), 0x01, 0x00, 0x36, responseValueSize}
	raw = append(raw, make([]byte, 40)...)

	err := p.Decode(raw)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect MS-Length")
}

func TestDecodeRejectsUnsupportedPeerOpcode(t *testing.T) {
	p := &Payload{}

	err := p.Decode([]byte{byte(OpChallenge), 0x01, 0x00, 0x05, 0x00})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported peer opcode")
}

type testContext struct {
	root        protocol.Payload
	settings    interface{}
	state       interface{}
	endStatus   protocol.Status
	stateStored interface{}
	sessionData map[string]any
}

func (t *testContext) Packet() *radius.Request                                       { return nil }
func (t *testContext) RootPayload() protocol.Payload                                 { return t.root }
func (t *testContext) State() string                                                 { return "" }
func (t *testContext) ProtocolSettings() interface{}                                 { return t.settings }
func (t *testContext) GetProtocolState(protocol.Type) interface{}                    { return t.state }
func (t *testContext) SetProtocolState(_ protocol.Type, s interface{})               { t.stateStored = s }
func (t *testContext) IsProtocolStart(protocol.Type) bool                            { return false }
func (t *testContext) ModifyRADIUSResponse(r *radius.Packet, q *radius.Packet) error { return nil }
func (t *testContext) AddResponseModifier(func(r, q *radius.Packet) error)           {}
func (t *testContext) HandleInnerEAP(protocol.Payload, protocol.StateManager) (protocol.Payload, error) {
	return nil, nil
}
func (t *testContext) Inner(protocol.Payload, protocol.Type) protocol.Context { return t }
func (t *testContext) EndInnerProtocol(status protocol.Status)                { t.endStatus = status }
func (t *testContext) Log() protocol.Logger                                   { return eaproot.DefaultLogger() }
func (t *testContext) SessionValue(key string) any {
	if t.sessionData == nil {
		return nil
	}
	return t.sessionData[key]
}
func (t *testContext) SetSessionValue(key string, value any) {
	if t.sessionData == nil {
		t.sessionData = map[string]any{}
	}
	t.sessionData[key] = value
}

func TestHandleSuccessAcknowledgesWithoutMPPEDependency(t *testing.T) {
	ctx := &testContext{
		root: &eap.Payload{ID: 7},
		settings: Settings{
			AuthenticateRequest: func(req AuthRequest) (*AuthResponse, error) {
				return &AuthResponse{}, nil
			},
		},
		state: &State{
			AuthResponse: &AuthResponse{AuthenticatorResponse: "S=ok"},
		},
	}

	res := (&Payload{OpCode: OpSuccess}).Handle(ctx)

	ext, ok := res.(*peap.ExtensionPayload)
	require.True(t, ok)
	require.Len(t, ext.AVPs, 1)
	assert.Equal(t, peap.AVPAckResult, ext.AVPs[0].Type)
	assert.Equal(t, []byte{0, 1}, ext.AVPs[0].Value)
	stored, ok := ctx.stateStored.(*State)
	require.True(t, ok)
	assert.True(t, stored.IsProtocolEnded)
}

// On a wrong password the NT-Response will not match; the method must end the
// inner exchange with StatusError (so the tunnel emits a clean EAP-Failure)
// rather than returning nil without a verdict.
func TestHandleAuthenticationFailureEndsWithError(t *testing.T) {
	ctx := &testContext{
		root: &eap.Payload{ID: 7},
		settings: Settings{
			AuthenticateRequest: func(req AuthRequest) (*AuthResponse, error) {
				// Expected NT-Response is all-zero; the peer's will differ.
				return &AuthResponse{NTResponse: make([]byte, responseNTResponseSize)}, nil
			},
		},
		state: &State{Challenge: make([]byte, challengeValueSize)},
	}

	value := make([]byte, responseValueSize)
	for i := 0; i < responseNTResponseSize; i++ {
		value[challengeValueSize+responseReservedSize+i] = 0xFF // non-zero NT-Response
	}

	res := (&Payload{OpCode: OpResponse, Response: value}).Handle(ctx)

	assert.Nil(t, res, "no payload is returned on authentication failure")
	assert.Equal(t, protocol.StatusError, ctx.endStatus, "inner exchange must end with StatusError")
}

func TestModifyRADIUSResponseAddsMSMPPEKeys(t *testing.T) {
	req := radius.New(radius.CodeAccessRequest, []byte("secret"))
	res := radius.New(radius.CodeAccessAccept, []byte("secret"))
	res.Authenticator = req.Authenticator

	payload := &Payload{
		st: &State{
			AuthResponse: &AuthResponse{
				RecvKey: []byte("recv"),
				SendKey: []byte("send"),
			},
		},
	}

	require.NoError(t, payload.ModifyRADIUSResponse(res, req))
	assert.Equal(t, []byte("recv"), microsoft.MSMPPERecvKey_Get(res, req))
	assert.Equal(t, []byte("send"), microsoft.MSMPPESendKey_Get(res, req))
}
