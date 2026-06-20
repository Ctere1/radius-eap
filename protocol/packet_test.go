package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"layeh.com/radius"
)

// RFC 3748 Section 4 assigns the EAP Code values.
func TestEAPCodeValuesMatchRFC3748(t *testing.T) {
	assert.Equal(t, Code(1), CodeRequest)
	assert.Equal(t, Code(2), CodeResponse)
	assert.Equal(t, Code(3), CodeSuccess)
	assert.Equal(t, Code(4), CodeFailure)
}

// Compile-time contract guards: the package's concrete payloads are expected to
// satisfy these interfaces. The stub documents the required method set and fails
// the build if an interface changes incompatibly.
type stubPayload struct{}

func (stubPayload) Decode([]byte) error                            { return nil }
func (stubPayload) Encode() ([]byte, error)                        { return nil, nil }
func (stubPayload) Handle(Context) Payload                         { return nil }
func (stubPayload) Type() Type                                     { return 0 }
func (stubPayload) Offerable() bool                                { return false }
func (stubPayload) String() string                                 { return "" }
func (stubPayload) HasInner() Payload                              { return nil }
func (stubPayload) ModifyRADIUSResponse(_, _ *radius.Packet) error { return nil }

func TestInterfaceContracts(t *testing.T) {
	var (
		_ Payload          = stubPayload{}
		_ Inner            = stubPayload{}
		_ ResponseModifier = stubPayload{}
	)
}
