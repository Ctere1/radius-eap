package peap

import (
	"crypto/tls"

	"github.com/Ctere1/radius-eap/protocol"
)

type Settings struct {
	Config         *tls.Config
	InnerProtocols protocol.Settings
	// MaxMessageSize bounds a single reassembled EAP-TLS (PEAP outer) message.
	// Zero selects the package default (64 KiB).
	MaxMessageSize int
}

func (s Settings) TLSConfig() *tls.Config {
	return s.Config
}

// MaxTLSMessageSize exposes the configured reassembly bound to the TLS layer.
func (s Settings) MaxTLSMessageSize() int {
	return s.MaxMessageSize
}
