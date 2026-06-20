package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC 5216 Section 3.1 defines the EAP-TLS Flags octet:
//
//	0 1 2 3 4 5 6 7
//	L M S R R R R R
//
// L = Length included (0x80), M = More fragments (0x40), S = EAP-TLS start
// (0x20); bits 3-7 are reserved and MUST be zero.
func TestFlagBitsMatchRFC5216(t *testing.T) {
	assert.Equal(t, Flag(0x80), FlagLengthIncluded, "L bit")
	assert.Equal(t, Flag(0x40), FlagMoreFragments, "M bit")
	assert.Equal(t, Flag(0x20), FlagTLSStart, "S bit")
	assert.Equal(t, Flag(0x00), FlagNone)
}

func TestFlagsAreDistinctSingleBits(t *testing.T) {
	// Each flag is a distinct single bit and none overlap the reserved range.
	all := FlagLengthIncluded | FlagMoreFragments | FlagTLSStart
	assert.Equal(t, Flag(0xE0), all)
	assert.Zero(t, all&0x1F, "reserved bits must be untouched")
}

func TestFlagsCombineAndMask(t *testing.T) {
	f := FlagLengthIncluded | FlagMoreFragments
	assert.NotZero(t, f&FlagLengthIncluded)
	assert.NotZero(t, f&FlagMoreFragments)
	assert.Zero(t, f&FlagTLSStart)
}
