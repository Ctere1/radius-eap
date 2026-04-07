package legacy_nak

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeRejectsEmptyPayload(t *testing.T) {
	p := &Payload{}

	err := p.Decode(nil)

	require.Error(t, err)
}
