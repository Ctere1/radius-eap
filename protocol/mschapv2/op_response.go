package mschapv2

import (
	"errors"
)

type Response struct {
	Challenge  []byte
	NTResponse []byte
	Flags      uint8
}

func ParseResponse(raw []byte) (*Response, error) {
	if len(raw) != responseValueSize {
		return nil, errors.New("MSCHAPv2: invalid response length")
	}
	res := &Response{}
	res.Challenge = raw[:challengeValueSize]
	// RFC 2759 Section 4: the 8 reserved bytes MUST be zero. Checked with a plain loop
	// (no per-call allocation); these bytes are not secret, so a constant-time
	// comparison is unnecessary.
	for _, b := range raw[challengeValueSize : challengeValueSize+responseReservedSize] {
		if b != 0 {
			return nil, errors.New("MSCHAPv2: Reserved bytes not empty?")
		}
	}
	res.NTResponse = raw[challengeValueSize+responseReservedSize : challengeValueSize+responseReservedSize+responseNTResponseSize]
	res.Flags = (raw[challengeValueSize+responseReservedSize+responseNTResponseSize])
	return res, nil
}
