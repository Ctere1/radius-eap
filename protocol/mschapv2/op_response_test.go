package mschapv2

import (
	"bytes"
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeMSCHAPv2IsIANAEAPMethod26(t *testing.T) {
	// IANA EAP method types: EAP-MS-CHAP-v2 is type 26.
	assert.Equal(t, protocol.Type(26), TypeMSCHAPv2)
}

// RFC 2759 Section 4: the MS-CHAPv2 Response value is exactly 49 octets:
//
//	16  Peer-Challenge
//	 8  Reserved (MUST be zero)
//	24  NT-Response
//	 1  Flags
func validResponseValue() []byte {
	raw := make([]byte, responseValueSize)
	for i := 0; i < challengeValueSize; i++ {
		raw[i] = byte(i + 1) // peer challenge
	}
	// reserved bytes [16:24] stay zero
	for i := 0; i < responseNTResponseSize; i++ {
		raw[challengeValueSize+responseReservedSize+i] = byte(0xA0 + i) // NT response
	}
	raw[responseValueSize-1] = 0x01 // flags
	return raw
}

func TestParseResponseExtractsFields(t *testing.T) {
	raw := validResponseValue()

	res, err := ParseResponse(raw)
	require.NoError(t, err)
	assert.Len(t, res.Challenge, challengeValueSize)
	assert.Equal(t, raw[:challengeValueSize], res.Challenge)
	assert.Len(t, res.NTResponse, responseNTResponseSize)
	assert.Equal(t, raw[challengeValueSize+responseReservedSize:challengeValueSize+responseReservedSize+responseNTResponseSize], res.NTResponse)
	assert.Equal(t, uint8(0x01), res.Flags)
}

func TestParseResponseRejectsWrongLengthTooShort(t *testing.T) {
	_, err := ParseResponse(make([]byte, responseValueSize-1))
	require.Error(t, err)
}

func TestParseResponseRejectsWrongLengthTooLong(t *testing.T) {
	_, err := ParseResponse(make([]byte, responseValueSize+1))
	require.Error(t, err)
}

func TestParseResponseRejectsNonZeroReservedBytes(t *testing.T) {
	// RFC 2759 Section 4: the 8 reserved octets MUST be zero.
	raw := validResponseValue()
	raw[challengeValueSize+3] = 0x01
	_, err := ParseResponse(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Reserved")
}

func TestParseResponseAllZeroReservedAccepted(t *testing.T) {
	raw := validResponseValue()
	reserved := raw[challengeValueSize : challengeValueSize+responseReservedSize]
	require.True(t, bytes.Equal(reserved, make([]byte, responseReservedSize)))
	_, err := ParseResponse(raw)
	require.NoError(t, err)
}
