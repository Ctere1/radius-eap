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
