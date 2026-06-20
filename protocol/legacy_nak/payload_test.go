package legacy_nak

import (
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
)

// noopLogger is a local protocol.Logger so this test avoids importing the root
// eap package (which imports legacy_nak — that would be an import cycle).
type noopLogger struct{}

func (noopLogger) Debug(string, ...interface{})        {}
func (noopLogger) Info(string, ...interface{})         {}
func (noopLogger) Warn(string, ...interface{})         {}
func (noopLogger) Error(string, ...interface{})        {}
func (noopLogger) With(...interface{}) protocol.Logger { return noopLogger{} }

func TestTypeIsRFC3748LegacyNak(t *testing.T) {
	// RFC 3748 Section 5.3.1 assigns EAP Type 3 to Legacy Nak.
	assert.Equal(t, protocol.Type(3), TypeLegacyNAK)
}

func TestDecodeRejectsEmptyPayload(t *testing.T) {
	p := &Payload{}
	err := p.Decode(nil)
	require.Error(t, err)
}

// RFC 3748 Section 5.3.1: the Nak Response carries the peer's desired authentication
// type so the server can offer an alternative.
func TestDecodeReadsDesiredTypeAndRoundTrips(t *testing.T) {
	p := &Payload{}
	require.NoError(t, p.Decode([]byte{byte(26)})) // peer wants MS-CHAPv2
	assert.Equal(t, protocol.Type(26), p.DesiredType)

	raw, err := p.Encode()
	require.NoError(t, err)
	assert.Equal(t, []byte{26}, raw)
}

// A Nak terminates the offered inner method with an error status; the outer
// handler then advances to the next protocol in priority order.
func TestHandleEndsInnerProtocolWithError(t *testing.T) {
	ctx := &nakTestContext{}
	out := (&Payload{DesiredType: 26}).Handle(ctx)
	assert.Nil(t, out)
	assert.Equal(t, protocol.StatusError, ctx.endStatus)
}

func TestNotOfferable(t *testing.T) {
	// Legacy Nak is only ever a peer response; the server never offers it.
	assert.False(t, (&Payload{}).Offerable())
}

type nakTestContext struct {
	endStatus protocol.Status
}

func (c *nakTestContext) Packet() *radius.Request                                        { return nil }
func (c *nakTestContext) RootPayload() protocol.Payload                                  { return nil }
func (c *nakTestContext) State() string                                                  { return "" }
func (c *nakTestContext) ProtocolSettings() interface{}                                  { return nil }
func (c *nakTestContext) GetProtocolState(protocol.Type) interface{}                     { return nil }
func (c *nakTestContext) SetProtocolState(protocol.Type, interface{})                    {}
func (c *nakTestContext) IsProtocolStart(protocol.Type) bool                             { return true }
func (c *nakTestContext) ModifyRADIUSResponse(*radius.Packet, *radius.Packet) error      { return nil }
func (c *nakTestContext) AddResponseModifier(func(*radius.Packet, *radius.Packet) error) {}
func (c *nakTestContext) HandleInnerEAP(protocol.Payload, protocol.StateManager) (protocol.Payload, error) {
	return nil, nil
}
func (c *nakTestContext) Inner(protocol.Payload, protocol.Type) protocol.Context { return c }
func (c *nakTestContext) EndInnerProtocol(s protocol.Status)                     { c.endStatus = s }
func (c *nakTestContext) Log() protocol.Logger                                   { return noopLogger{} }
func (c *nakTestContext) SessionValue(string) any                                { return nil }
func (c *nakTestContext) SetSessionValue(string, any)                            {}
