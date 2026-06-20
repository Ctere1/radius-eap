package eap

import (
	"errors"
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
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
