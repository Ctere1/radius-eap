package tls

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadInnerTLSRecordReturnsClonedData(t *testing.T) {
	src := []byte{0x17, 0x03, 0x03, 0x00, 0x01}
	got, err := readInnerTLSRecord(bytes.NewReader(src))
	require.NoError(t, err)
	assert.Equal(t, src, got)

	// The result must be a copy, independent of the caller's buffer.
	got[0] = 0xFF
	assert.Equal(t, byte(0x17), src[0])
}

func TestReadInnerTLSRecordPropagatesEOF(t *testing.T) {
	got, err := readInnerTLSRecord(bytes.NewReader(nil))
	assert.Nil(t, got)
	assert.ErrorIs(t, err, io.EOF)
}

func TestReadInnerTLSRecordPropagatesError(t *testing.T) {
	sentinel := errors.New("boom")
	got, err := readInnerTLSRecord(errReader{err: sentinel})
	assert.Nil(t, got)
	assert.ErrorIs(t, err, sentinel)
}

func TestReadInnerTLSRecordNoProgress(t *testing.T) {
	// A reader that returns (0, nil) must surface ErrNoProgress rather than loop.
	got, err := readInnerTLSRecord(zeroReader{})
	assert.Nil(t, got)
	assert.ErrorIs(t, err, io.ErrNoProgress)
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) { return 0, nil }
