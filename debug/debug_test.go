package debug

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatBytesShort(t *testing.T) {
	assert.Equal(t, "01 02 03", FormatBytes([]byte{0x01, 0x02, 0x03}))
}

func TestFormatBytesEmpty(t *testing.T) {
	assert.Equal(t, "", FormatBytes(nil))
}

func TestFormatBytesTruncatesAt32(t *testing.T) {
	in := make([]byte, 64)
	out := FormatBytes(in)
	// Only the first 32 bytes are rendered (space-separated hex tokens).
	assert.Len(t, strings.Fields(out), 32)
}
