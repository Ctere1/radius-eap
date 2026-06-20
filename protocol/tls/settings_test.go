package tls

import (
	"crypto/tls"
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
)

func TestTypeTLSIsIANAEAPMethod13(t *testing.T) {
	// RFC 5216 / IANA EAP method types: EAP-TLS is type 13.
	assert.Equal(t, protocol.Type(13), TypeTLS)
}

func TestSettingsTLSConfigReturnsConfig(t *testing.T) {
	cfg := &tls.Config{}
	s := Settings{Config: cfg}
	assert.Same(t, cfg, s.TLSConfig())
	assert.Same(t, cfg, TLSConfig(s).TLSConfig())
}

func TestSettingsMaxTLSMessageSize(t *testing.T) {
	// Zero means "use the package default" (resolved by the reassembler).
	assert.Equal(t, 0, Settings{}.MaxTLSMessageSize())
	assert.Equal(t, 32*1024, Settings{MaxMessageSize: 32 * 1024}.MaxTLSMessageSize())
}
