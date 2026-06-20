package eap

import (
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLoggerSatisfiesInterface(t *testing.T) {
	var _ protocol.Logger = DefaultLogger()
}

func TestStdLoggerWithReturnsChainableLogger(t *testing.T) {
	l := DefaultLogger().With("component", "eap")
	require.NotNil(t, l)

	// All levels must be callable without panicking.
	assert.NotPanics(t, func() {
		l.Debug("debug", "k", "v")
		l.Info("info")
		l.Warn("warn")
		l.Error("error")
		_ = l.With("more", "fields")
	})
}
