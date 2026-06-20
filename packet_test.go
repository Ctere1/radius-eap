package eap

import (
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 3748 Section 4: an EAP packet is Code(1) | Identifier(1) | Length(2) | Data.
// Success (Code 3) and Failure (Code 4) packets carry no Type/Data.
func TestDecodeEncodeRoundTripSuccess(t *testing.T) {
	stm := NewMemoryStateManager(protocol.Settings{}, 0)
	defer stm.Close()

	raw := []byte{0x03, 0x07, 0x00, 0x04} // Success, ID=7, Length=4

	p, err := Decode(stm, raw)
	require.NoError(t, err)

	out, err := p.Encode()
	require.NoError(t, err)
	assert.Equal(t, raw, out)
}

func TestDecodeRejectsShortPacket(t *testing.T) {
	stm := NewMemoryStateManager(protocol.Settings{}, 0)
	defer stm.Close()

	_, err := Decode(stm, []byte{0x01})
	require.Error(t, err)
}

func TestDecodeRejectsLengthMismatch(t *testing.T) {
	stm := NewMemoryStateManager(protocol.Settings{}, 0)
	defer stm.Close()

	// Declared length (5) does not match the actual 4 bytes.
	_, err := Decode(stm, []byte{0x03, 0x01, 0x00, 0x05})
	require.Error(t, err)
}
