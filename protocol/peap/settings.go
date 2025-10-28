package peap

import (
	"crypto/tls"

	"github.com/Ctere1/radius-eap/protocol"
)

type Settings struct {
	Config         *tls.Config
	InnerProtocols protocol.Settings
}

func (s Settings) TLSConfig() *tls.Config {
	return s.Config
}
