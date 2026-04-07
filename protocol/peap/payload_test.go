package peap

import (
	"crypto/tls"
	"testing"

	eaproot "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/eap"
	"github.com/Ctere1/radius-eap/protocol/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
)

type testContext struct {
	root        protocol.Payload
	settings    interface{}
	state       interface{}
	endStatus   protocol.Status
	stateStored interface{}
	handleInner func(protocol.Payload, protocol.StateManager) (protocol.Payload, error)
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
func (t *testContext) HandleInnerEAP(p protocol.Payload, sm protocol.StateManager) (protocol.Payload, error) {
	if t.handleInner == nil {
		return nil, nil
	}
	return t.handleInner(p, sm)
}
func (t *testContext) Inner(protocol.Payload, protocol.Type) protocol.Context { return t }
func (t *testContext) EndInnerProtocol(status protocol.Status)                { t.endStatus = status }
func (t *testContext) Log() protocol.Logger                                   { return eaproot.DefaultLogger() }

func TestHandleTracksProtectedResultRequest(t *testing.T) {
	ctx := &testContext{
		root: &eap.Payload{Code: protocol.CodeResponse, ID: 7},
		settings: Settings{
			Config: &tls.Config{},
			InnerProtocols: protocol.Settings{
				Protocols: []protocol.ProtocolConstructor{identity.Protocol},
			},
		},
		state: &State{
			SubState: map[string]*protocol.State{},
		},
		handleInner: func(protocol.Payload, protocol.StateManager) (protocol.Payload, error) {
			return &eap.Payload{
				Code: protocol.CodeRequest,
				ID:   8,
				Payload: &ExtensionPayload{
					AVPs: []ExtensionAVP{
						{
							Mandatory: true,
							Type:      AVPAckResult,
							Value:     []byte{0, 1},
						},
					},
				},
			}, nil
		},
	}
	p := &Payload{}
	require.NoError(t, p.Decode([]byte{byte(1), 'u'}))

	res := p.Handle(ctx)

	pres, ok := res.(*eap.Payload)
	require.True(t, ok)
	assert.Equal(t, TypePEAPExtension, pres.MsgType)
	stored, ok := ctx.stateStored.(*State)
	require.True(t, ok)
	assert.True(t, stored.AwaitingResultAVPAck)
}

func TestHandleAcceptsProtectedResultAck(t *testing.T) {
	ctx := &testContext{
		root: &eap.Payload{Code: protocol.CodeResponse, ID: 7},
		settings: Settings{
			Config: &tls.Config{},
		},
		state: &State{
			SubState:             map[string]*protocol.State{},
			AwaitingResultAVPAck: true,
		},
	}
	inner, err := (&eap.Payload{
		Code:    protocol.CodeResponse,
		ID:      7,
		MsgType: TypePEAPExtension,
		Payload: &ExtensionPayload{AVPs: []ExtensionAVP{{Mandatory: true, Type: AVPAckResult, Value: []byte{0, 1}}}},
	}).Encode()
	require.NoError(t, err)
	p := &Payload{}
	require.NoError(t, p.Decode(inner))

	res := p.Handle(ctx)

	assert.Nil(t, res)
	assert.Equal(t, protocol.StatusSuccess, ctx.endStatus)
	stored, ok := ctx.stateStored.(*State)
	require.True(t, ok)
	assert.False(t, stored.AwaitingResultAVPAck)
}

func TestHandleRejectsUnexpectedProtectedResultAck(t *testing.T) {
	ctx := &testContext{
		root: &eap.Payload{Code: protocol.CodeResponse, ID: 7},
		settings: Settings{
			Config: &tls.Config{},
		},
		state: &State{
			SubState:             map[string]*protocol.State{},
			AwaitingResultAVPAck: true,
		},
	}
	inner, err := (&eap.Payload{
		Code:    protocol.CodeResponse,
		ID:      7,
		MsgType: TypePEAPExtension,
		Payload: &ExtensionPayload{AVPs: []ExtensionAVP{{Mandatory: true, Type: AVPAckResult, Value: []byte{0, 2}}}},
	}).Encode()
	require.NoError(t, err)
	p := &Payload{}
	require.NoError(t, p.Decode(inner))

	res := p.Handle(ctx)

	assert.Nil(t, res)
	assert.Equal(t, protocol.StatusError, ctx.endStatus)
	stored, ok := ctx.stateStored.(*State)
	require.True(t, ok)
	assert.False(t, stored.AwaitingResultAVPAck)
}
