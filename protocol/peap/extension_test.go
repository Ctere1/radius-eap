package peap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtensionDecodeRejectsOverlongAVP(t *testing.T) {
	p := &ExtensionPayload{}

	err := p.Decode([]byte{
		0x80, 0x03,
		0x00, 0x04,
		0x00, 0x01,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds remaining payload")
}

func TestExtensionAVPDecodePreservesValue(t *testing.T) {
	avp := &ExtensionAVP{}

	err := avp.Decode([]byte{
		0x80, 0x03,
		0x00, 0x02,
		0x00, 0x01,
	})

	require.NoError(t, err)
	assert.True(t, avp.Mandatory)
	assert.Equal(t, AVPAckResult, avp.Type)
	assert.Equal(t, []byte{0x00, 0x01}, avp.Value)
}
