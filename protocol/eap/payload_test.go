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
