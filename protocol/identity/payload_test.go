package identity

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeRejectsEmptyIdentity(t *testing.T) {
	p := &Payload{}

	err := p.Decode(nil)

	require.Error(t, err)
}
