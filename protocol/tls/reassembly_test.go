package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reassembler implements peer-side EAP-TLS message reassembly per RFC 5216
// Section 2.1.5 / Section 3.1: the first fragment of a multi-fragment message carries the
// Length (L) flag with the total size, and every non-final fragment carries the
// More (M) flag.

func TestInboundReassemblerSingleCompleteFlight(t *testing.T) {
	var r inboundReassembler

	// A message that fits in one packet: no M flag, optionally L. It completes
	// immediately.
	complete, needMore, err := r.accept(FlagLengthIncluded, 4, []byte{1, 2, 3, 4}, 0)
	require.NoError(t, err)
	assert.False(t, needMore)
	assert.Equal(t, []byte{1, 2, 3, 4}, complete)
	assert.Zero(t, r.expected)
}

func TestInboundReassemblerTracksInitialFragment(t *testing.T) {
	var r inboundReassembler

	// First fragment: length-included + more, carrying 900 of 1800 bytes.
	complete, needMore, err := r.accept(FlagLengthIncluded|FlagMoreFragments, 1800, make([]byte, 900), 0)
	require.NoError(t, err)
	assert.True(t, needMore)
	assert.Nil(t, complete)
	assert.Equal(t, 1800, r.expected)

	// Final fragment completes the reassembled message.
	complete, needMore, err = r.accept(FlagNone, 0, make([]byte, 900), 0)
	require.NoError(t, err)
	assert.False(t, needMore)
	assert.Len(t, complete, 1800)
	assert.Zero(t, r.expected)
}

func TestInboundReassemblerMultipleFragmentsViaMoreFlag(t *testing.T) {
	var r inboundReassembler

	// Three fragments where only the M flag (no declared length) drives
	// continuation; the final fragment clears M.
	_, needMore, err := r.accept(FlagMoreFragments, 0, []byte{1, 2}, 0)
	require.NoError(t, err)
	assert.True(t, needMore)

	_, needMore, err = r.accept(FlagMoreFragments, 0, []byte{3, 4}, 0)
	require.NoError(t, err)
	assert.True(t, needMore)

	complete, needMore, err := r.accept(FlagNone, 0, []byte{5}, 0)
	require.NoError(t, err)
	assert.False(t, needMore)
	assert.Equal(t, []byte{1, 2, 3, 4, 5}, complete)
}

func TestInboundReassemblerWaitsForDeclaredLengthWithoutMoreFlag(t *testing.T) {
	var r inboundReassembler

	// Declared length exceeds delivered bytes and the (non-conformant) peer did
	// not set the M flag: the reassembler still waits for the rest.
	_, needMore, err := r.accept(FlagLengthIncluded, 10, make([]byte, 4), 0)
	require.NoError(t, err)
	assert.True(t, needMore)

	complete, needMore, err := r.accept(FlagNone, 0, make([]byte, 6), 0)
	require.NoError(t, err)
	assert.False(t, needMore)
	assert.Len(t, complete, 10)
}

func TestInboundReassemblerRejectsOversizedDeclaredLength(t *testing.T) {
	var r inboundReassembler
	_, _, err := r.accept(FlagLengthIncluded, 70*1024, []byte{0x01}, 64*1024)
	require.Error(t, err)
}

func TestInboundReassemblerRejectsOversizedAccumulation(t *testing.T) {
	var r inboundReassembler
	_, needMore, err := r.accept(FlagMoreFragments, 0, make([]byte, 60*1024), 64*1024)
	require.NoError(t, err)
	require.True(t, needMore)

	_, _, err = r.accept(FlagNone, 0, make([]byte, 10*1024), 64*1024)
	require.Error(t, err)
}

func TestInboundReassemblerUsesDefaultMaxWhenZero(t *testing.T) {
	var r inboundReassembler
	_, _, err := r.accept(FlagLengthIncluded, uint32(defaultMaxTLSMessageSize)+1, []byte{0x01}, 0)
	require.Error(t, err)
}

func TestInboundReassemblerResetsBetweenMessages(t *testing.T) {
	var r inboundReassembler

	first, needMore, err := r.accept(FlagLengthIncluded, 2, []byte{1, 2}, 0)
	require.NoError(t, err)
	require.False(t, needMore)
	require.Len(t, first, 2)

	// A second, independent message reuses the same reassembler cleanly.
	second, needMore, err := r.accept(FlagNone, 0, []byte{9}, 0)
	require.NoError(t, err)
	assert.False(t, needMore)
	assert.Equal(t, []byte{9}, second)
}
