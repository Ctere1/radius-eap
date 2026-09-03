package identity

import (
	"strings"
	"testing"

	eaproot "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
)

func TestTypeIsRFC3748Identity(t *testing.T) {
	// RFC 3748 Section 5.1 assigns EAP Type 1 to Identity.
	assert.Equal(t, protocol.Type(1), TypeIdentity)
}

func TestDecodeRejectsEmptyIdentity(t *testing.T) {
	p := &Payload{}
	err := p.Decode(nil)
	require.Error(t, err)
}

func TestDecodeReadsIdentity(t *testing.T) {
	p := &Payload{}
	require.NoError(t, p.Decode([]byte("alice@example.org")))
	assert.Equal(t, "alice@example.org", p.Identity)
}

// RFC 3748 Section 5.1: the Identity Response is informational. Once received the
// server records it and proceeds to the next authentication method.
func TestHandleStartsNextProtocolAndStoresIdentity(t *testing.T) {
	ctx := &idTestContext{}
	p := &Payload{Identity: "bob"}

	out := p.Handle(ctx)
	assert.Nil(t, out)
	assert.Equal(t, protocol.StatusNextProtocol, ctx.endStatus)

	state, ok := ctx.stored.(*State)
	require.True(t, ok)
	assert.Equal(t, "bob", state.Identity)
}

type idTestContext struct {
	done      bool
	stored    interface{}
	endStatus protocol.Status
}

func (c *idTestContext) Packet() *radius.Request                                        { return nil }
func (c *idTestContext) RootPayload() protocol.Payload                                  { return nil }
func (c *idTestContext) State() string                                                  { return "" }
func (c *idTestContext) ProtocolSettings() interface{}                                  { return nil }
func (c *idTestContext) GetProtocolState(protocol.Type) interface{}                     { return nil }
func (c *idTestContext) SetProtocolState(_ protocol.Type, s interface{})                { c.stored = s; c.done = true }
func (c *idTestContext) IsProtocolStart(protocol.Type) bool                             { return !c.done }
func (c *idTestContext) ModifyRADIUSResponse(*radius.Packet, *radius.Packet) error      { return nil }
func (c *idTestContext) AddResponseModifier(func(*radius.Packet, *radius.Packet) error) {}
func (c *idTestContext) HandleInnerEAP(protocol.Payload, protocol.StateManager) (protocol.Payload, error) {
	return nil, nil
}
func (c *idTestContext) Inner(protocol.Payload, protocol.Type) protocol.Context { return c }
func (c *idTestContext) EndInnerProtocol(s protocol.Status)                     { c.endStatus = s }
func (c *idTestContext) Log() protocol.Logger                                   { return eaproot.DefaultLogger() }
func (c *idTestContext) SessionValue(string) any                                { return nil }
func (c *idTestContext) SetSessionValue(string, any)                            {}

// The identity is carried on as a RADIUS User-Name, so it is bounded to what
// that attribute holds, and an embedded NUL is refused. RFC 3748 Section 5.1
// says the Response MUST NOT be null terminated but supplicants terminate it
// anyway, so a single trailing NUL is trimmed; the same section only RECOMMENDS
// UTF-8, so a legacy eight-bit identity is carried through.
func TestDecodeIdentityBoundsAndNulHandling(t *testing.T) {
	p := &Payload{}

	require.Error(t, p.Decode([]byte("al\x00ice")), "an embedded NUL must be refused")
	require.Error(t, p.Decode([]byte{0}), "a lone NUL leaves nothing behind")
	require.Error(t, p.Decode([]byte(strings.Repeat("a", 254))))

	require.NoError(t, p.Decode([]byte(strings.Repeat("a", 253))))

	require.NoError(t, p.Decode([]byte("alice\x00")))
	require.Equal(t, "alice", p.Identity, "a trailing NUL is trimmed, not kept")

	require.NoError(t, p.Decode([]byte{0xC3, 0x28}), "RFC 3748 only recommends UTF-8")
}
