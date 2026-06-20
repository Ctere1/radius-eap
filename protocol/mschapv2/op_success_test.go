package mschapv2

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 2759 Section 5: the Success Request carries OpCode=3, the MS-CHAPv2 identifier, a
// 2-octet MS-Length, and the "S=<auth> M=<message>" authenticator string. Unlike
// the Challenge it has no ValueSize octet.
func TestSuccessRequestEncode(t *testing.T) {
	auth := []byte("S=0123456789ABCDEF0123456789ABCDEF01234567")
	sr := &SuccessRequest{
		Payload:       &Payload{OpCode: OpSuccess, MSCHAPv2ID: 7},
		Authenticator: auth,
	}

	raw, err := sr.Encode()
	require.NoError(t, err)

	assert.Equal(t, byte(OpSuccess), raw[0], "OpCode")
	assert.Equal(t, byte(7), raw[1], "MS-CHAPv2 identifier")

	gotLen := binary.BigEndian.Uint16(raw[2:4])
	assert.Equal(t, uint16(len(raw)), gotLen, "MS-Length must equal the total length")
	assert.Equal(t, uint16(4+len(auth)), gotLen)

	assert.Equal(t, auth, raw[4:], "authenticator string follows the 4-byte header")
}

func TestSuccessRequestEncodeEmptyAuthenticator(t *testing.T) {
	sr := &SuccessRequest{Payload: &Payload{OpCode: OpSuccess, MSCHAPv2ID: 1}}
	raw, err := sr.Encode()
	require.NoError(t, err)
	assert.Len(t, raw, 4)
	assert.Equal(t, uint16(4), binary.BigEndian.Uint16(raw[2:4]))
}
