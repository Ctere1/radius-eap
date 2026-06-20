package eap

import (
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeRejectsShortHeader(t *testing.T) {
	p := &Payload{}

	err := p.Decode([]byte{0x01, 0x02, 0x00})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid EAP packet length")
}

func TestDecodeRejectsRequestWithoutType(t *testing.T) {
	p := &Payload{}

	err := p.Decode([]byte{byte(protocol.CodeRequest), 0x07, 0x00, 0x04})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "type missing")
}

func TestDecodeAcceptsSuccessWithoutType(t *testing.T) {
	p := &Payload{}

	err := p.Decode([]byte{byte(protocol.CodeSuccess), 0x07, 0x00, 0x04})

	require.NoError(t, err)
	assert.Empty(t, p.RawPayload)
}

// RFC 3748 Section 4: octets beyond the Length field are link-layer padding and
// MUST be ignored, not rejected.
func TestDecodeIgnoresTrailingPadding(t *testing.T) {
	p := &Payload{}

	// Success packet of Length 4 followed by 2 padding octets.
	err := p.Decode([]byte{byte(protocol.CodeSuccess), 0x07, 0x00, 0x04, 0xFF, 0xFF})

	require.NoError(t, err)
	assert.Equal(t, uint16(4), p.Length)
	assert.Empty(t, p.RawPayload, "padding must not be exposed as payload")
}

// RFC 3748 Section 4: a Length larger than the received octets MUST be discarded.
func TestDecodeRejectsLengthExceedingReceived(t *testing.T) {
	p := &Payload{}

	err := p.Decode([]byte{byte(protocol.CodeSuccess), 0x07, 0x00, 0x09}) // claims 9, only 4
	require.Error(t, err)
}

func TestDecodeRejectsLengthBelowHeader(t *testing.T) {
	p := &Payload{}

	err := p.Decode([]byte{byte(protocol.CodeSuccess), 0x07, 0x00, 0x03, 0x00}) // Length 3 < header
	require.Error(t, err)
}
