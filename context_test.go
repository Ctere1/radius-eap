package eap

import (
	"errors"
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	eapprotocol "github.com/Ctere1/radius-eap/protocol/eap"
	"github.com/Ctere1/radius-eap/protocol/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func newTestContext() *context {
	return &context{
		session: protocol.BlankState(protocol.Settings{}),
		log:     DefaultLogger(),
	}
}

func TestContextSessionValueDelegatesToState(t *testing.T) {
	st := protocol.BlankState(protocol.Settings{})
	ctx := &context{session: st, log: DefaultLogger()}

	ctx.SetSessionValue("user", "alice")
	assert.Equal(t, "alice", ctx.SessionValue("user"))
	assert.Equal(t, "alice", st.SessionValue("user"), "writes go through to the shared State")
}

func TestContextSessionValueNilSessionIsSafe(t *testing.T) {
	ctx := &context{log: DefaultLogger()}
	assert.Nil(t, ctx.SessionValue("user"))
	assert.NotPanics(t, func() { ctx.SetSessionValue("user", "x") })
}

func TestContextEndInnerProtocolFirstWins(t *testing.T) {
	ctx := newTestContext()
	assert.Equal(t, protocol.StatusUnknown, ctx.EndStatus())

	ctx.EndInnerProtocol(protocol.StatusSuccess)
	ctx.EndInnerProtocol(protocol.StatusError) // ignored: status already set
	assert.Equal(t, protocol.StatusSuccess, ctx.EndStatus())
}

func TestContextModifiersRunInRegistrationOrder(t *testing.T) {
	ctx := newTestContext()
	var order []int
	ctx.AddResponseModifier(func(*radius.Packet, *radius.Packet) error { order = append(order, 1); return nil })
	ctx.AddResponseModifier(func(*radius.Packet, *radius.Packet) error { order = append(order, 2); return nil })

	require.NoError(t, ctx.ModifyRADIUSResponse(nil, nil))
	assert.Equal(t, []int{1, 2}, order)
}

func TestContextModifierErrorStopsChain(t *testing.T) {
	ctx := newTestContext()
	called := false
	ctx.AddResponseModifier(func(*radius.Packet, *radius.Packet) error { return errors.New("boom") })
	ctx.AddResponseModifier(func(*radius.Packet, *radius.Packet) error { called = true; return nil })

	require.Error(t, ctx.ModifyRADIUSResponse(nil, nil))
	assert.False(t, called, "modifiers after a failing one must not run")
}

func TestContextInnerSharesSessionAndRoutesToParent(t *testing.T) {
	parent := newTestContext()
	child := parent.Inner(nil, protocol.Type(1)).(*context)

	assert.Same(t, parent, child.parent)

	// Session data is shared with the root session.
	child.SetSessionValue("k", "v")
	assert.Equal(t, "v", parent.SessionValue("k"))

	// Modifiers registered on a child are routed to and run from the root.
	ran := false
	child.AddResponseModifier(func(*radius.Packet, *radius.Packet) error { ran = true; return nil })
	require.NoError(t, parent.ModifyRADIUSResponse(nil, nil))
	assert.True(t, ran)
}

// A minimal tunnel method: it plays the role PEAP plays (a nested EAP
// conversation with its own StateManager) without TLS in the way, so the
// identity visible to an inner method can be asserted in-process.
const (
	tunnelType protocol.Type = 200
	probeType  protocol.Type = 201
)

type tunnelMethod struct {
	settings protocol.Settings
	sub      map[string]*protocol.State
	raw      []byte
	inner    *eapprotocol.Payload
}

func (t *tunnelMethod) GetEAPSettings() protocol.Settings       { return t.settings }
func (t *tunnelMethod) GetEAPState(k string) *protocol.State    { return t.sub[k] }
func (t *tunnelMethod) SetEAPState(k string, s *protocol.State) { t.sub[k] = s }
func (t *tunnelMethod) Type() protocol.Type                     { return tunnelType }
func (t *tunnelMethod) Offerable() bool                         { return true }
func (t *tunnelMethod) String() string                          { return "tunnel" }
func (t *tunnelMethod) Decode(raw []byte) error                 { t.raw = raw; return nil }
func (t *tunnelMethod) Encode() ([]byte, error) {
	if t.inner == nil {
		return nil, nil
	}
	return t.inner.Encode()
}
func (t *tunnelMethod) Handle(ctx protocol.Context) protocol.Payload {
	if ctx.IsProtocolStart(tunnelType) {
		ctx.SetProtocolState(tunnelType, &struct{}{})
		t.inner = &eapprotocol.Payload{Code: protocol.CodeRequest, ID: 1, MsgType: identity.TypeIdentity, Payload: &identity.Payload{}}
		return t
	}
	in := &eapprotocol.Payload{Settings: t.settings}
	if err := in.Decode(t.raw); err != nil {
		ctx.EndInnerProtocol(protocol.StatusError)
		return nil
	}
	res, err := ctx.HandleInnerEAP(in, t)
	if err != nil {
		ctx.EndInnerProtocol(protocol.StatusError)
		return nil
	}
	t.inner = res.(*eapprotocol.Payload)
	return t
}

// probeMethod records the identity an inner method observes, then succeeds.
type probeMethod struct{ seen *string }

func (p *probeMethod) Type() protocol.Type     { return probeType }
func (p *probeMethod) Offerable() bool         { return true }
func (p *probeMethod) String() string          { return "probe" }
func (p *probeMethod) Decode([]byte) error     { return nil }
func (p *probeMethod) Encode() ([]byte, error) { return nil, nil }
func (p *probeMethod) Handle(ctx protocol.Context) protocol.Payload {
	if st, ok := ctx.GetProtocolState(identity.TypeIdentity).(*identity.State); ok && st != nil {
		*p.seen = st.Identity
	}
	if ctx.IsProtocolStart(probeType) {
		ctx.SetProtocolState(probeType, &struct{}{})
		return &probeMethod{seen: p.seen}
	}
	ctx.EndInnerProtocol(protocol.StatusSuccess)
	return nil
}

// rawEAP builds a peer EAP packet by hand: the library's payload encoders only
// produce server-side (Request) bodies, so peer Responses need the wire bytes.
func rawEAP(code protocol.Code, id uint8, msgType protocol.Type, data []byte) []byte {
	length := 5 + len(data)
	out := []byte{byte(code), id, byte(length >> 8), byte(length), byte(msgType)}
	return append(out, data...)
}

func TestPEAPStyleTunnel_InnerMethodSeesInnerIdentity(t *testing.T) {
	var seen string
	tunnel := &tunnelMethod{sub: map[string]*protocol.State{}}
	tunnel.settings = protocol.Settings{
		Logger:           DefaultLogger(),
		Protocols:        []protocol.ProtocolConstructor{identity.Protocol, func() protocol.Payload { return &probeMethod{seen: &seen} }},
		ProtocolPriority: []protocol.Type{identity.TypeIdentity, probeType},
		ProtocolSettings: map[protocol.Type]any{},
	}
	outer := protocol.Settings{
		Logger:           DefaultLogger(),
		Protocols:        []protocol.ProtocolConstructor{identity.Protocol, func() protocol.Payload { return tunnel }},
		ProtocolPriority: []protocol.Type{identity.TypeIdentity, tunnelType},
		ProtocolSettings: map[protocol.Type]any{},
	}
	stm := NewMemoryStateManager(outer, 0)

	send := func(state string, raw []byte) *radius.Packet {
		req := &radius.Request{Packet: radius.New(radius.CodeAccessRequest, []byte("secret"))}
		if state != "" {
			require.NoError(t, rfc2865.State_SetString(req.Packet, state))
		}
		pkt, err := Decode(stm, raw)
		require.NoError(t, err)
		w := &recordingResponseWriter{}
		pkt.HandleRadiusPacket(w, req)
		require.NotNil(t, w.packet, "expected a RADIUS response")
		return w.packet
	}
	decodeEAP := func(pkt *radius.Packet) *eapprotocol.Payload {
		ep := &eapprotocol.Payload{Settings: outer}
		require.NoError(t, ep.Decode(rfc2869.EAPMessage_Get(pkt)))
		return ep
	}

	// 1. Outer identity "anonymous" starts the tunnel.
	resp := send("", rawEAP(protocol.CodeResponse, 1, identity.TypeIdentity, []byte("anonymous")))
	require.Equal(t, radius.CodeAccessChallenge, resp.Code)
	state := rfc2865.State_GetString(resp)
	outerReq := decodeEAP(resp)
	require.Equal(t, tunnelType, outerReq.MsgType)

	// 2. Inner identity "alice" travels inside the tunnel.
	innerIdentity := rawEAP(protocol.CodeResponse, outerReq.ID, identity.TypeIdentity, []byte("alice"))
	resp = send(state, rawEAP(protocol.CodeResponse, outerReq.ID, tunnelType, innerIdentity))
	require.Equal(t, radius.CodeAccessChallenge, resp.Code, "the tunnel must continue with the inner method after the inner identity")
	outerReq = decodeEAP(resp)

	// 3. The inner probe answers and reports which identity it saw.
	innerProbe := rawEAP(protocol.CodeResponse, outerReq.ID, probeType, nil)
	resp = send(state, rawEAP(protocol.CodeResponse, outerReq.ID, tunnelType, innerProbe))
	require.Equal(t, radius.CodeAccessAccept, resp.Code)
	require.Equal(t, "alice", seen, "the inner method must see the protected inner identity, not the outer one")
}
