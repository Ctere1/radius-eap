package mschapv2

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFailureRequestEncode(t *testing.T) {
	fr := &FailureRequest{
		Payload: &Payload{OpCode: OpFailure, MSCHAPv2ID: 9},
		Message: "E=691 R=0 C=00000000000000000000000000000000 V=3 M=Authentication failed",
	}

	encoded, err := fr.Encode()
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(encoded), 4)
	assert.Equal(t, byte(OpFailure), encoded[0], "first byte is the Failure opcode")
	assert.Equal(t, byte(9), encoded[1], "MSCHAPv2 ID is preserved")
	assert.Equal(t, uint16(len(encoded)), binary.BigEndian.Uint16(encoded[2:4]), "MS-Length covers the whole packet")
	assert.Equal(t, fr.Message, string(encoded[4:]), "message body follows the 4-byte header")
	assert.Equal(t, uint16(len(encoded)), fr.MSLength, "MS-Length is written back onto the struct")
}

// The Failure message must follow the RFC 2759 §6 format: a non-retryable
// (R=0) authentication failure (E=691), a fresh 16-byte challenge in hex,
// version 3, and the human-readable message.
func TestFormatFailureMessage(t *testing.T) {
	msg := formatFailureMessage("Authentication failed")

	assert.Regexp(t, `^E=691 R=0 C=[0-9a-f]{32} V=3 M=Authentication failed$`, msg)
}

// Two calls must mint independent challenges (C is freshly random each time).
func TestFormatFailureMessageUsesFreshChallenge(t *testing.T) {
	assert.NotEqual(t, formatFailureMessage("x"), formatFailureMessage("x"))
}
