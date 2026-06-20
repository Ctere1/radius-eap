package peap

import (
	"crypto/tls"
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
)

func TestTypePEAPIsIANAEAPMethod25(t *testing.T) {
	// IANA EAP method types: PEAP is type 25.
	assert.Equal(t, protocol.Type(25), TypePEAP)
}

func TestSettingsTLSConfigReturnsConfig(t *testing.T) {
	cfg := &tls.Config{}
	s := Settings{Config: cfg}
	assert.Same(t, cfg, s.TLSConfig())
}

func TestSettingsMaxTLSMessageSize(t *testing.T) {
	assert.Equal(t, 0, Settings{}.MaxTLSMessageSize())
	assert.Equal(t, 16*1024, Settings{MaxMessageSize: 16 * 1024}.MaxTLSMessageSize())
}

func TestSettingsExposesInnerProtocols(t *testing.T) {
	inner := protocol.Settings{ProtocolPriority: []protocol.Type{26}}
	s := Settings{InnerProtocols: inner}
	assert.Equal(t, inner.ProtocolPriority, s.InnerProtocols.ProtocolPriority)
}
