package mschapv2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeRejectsShortPayload(t *testing.T) {
	p := &Payload{}

	err := p.Decode([]byte{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecodeRejectsTruncatedResponse(t *testing.T) {
	p := &Payload{}
	raw := []byte{byte(OpResponse), 0x01, 0x00, 0x36, responseValueSize}
	raw = append(raw, make([]byte, 40)...)

	err := p.Decode(raw)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect MS-Length")
}

func TestParseResponseRejectsWrongLength(t *testing.T) {
	_, err := ParseResponse(make([]byte, responseValueSize-1))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid response length")
}
