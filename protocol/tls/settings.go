package tls

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Ctere1/radius-eap/protocol"
)

type TLSConfig interface {
	TLSConfig() *tls.Config
}

// Settings defines the reusable TLS extension points for EAP-TLS/PEAP consumers.
//
// Consumers that only need native Go TLS client-certificate enforcement can keep
// Config.ClientAuth at tls.RequireAndVerifyClientCert and leave the hooks nil.
//
// Consumers that need identity-aware inspection or application-specific policy
// decisions during the handshake can instead require certificate presence
// (typically tls.RequireAnyClientCert) and perform their own validation in
// VerifyConnection. That hook runs for all connections, including resumptions.
type Settings struct {
	Config *tls.Config
	// VerifyPeerCertificate mirrors tls.Config.VerifyPeerCertificate while adding
	// protocol.Context. Note that Go does not invoke this callback on resumed
	// connections.
	VerifyPeerCertificate func(ctx protocol.Context, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	// VerifyConnection mirrors tls.Config.VerifyConnection while adding
	// protocol.Context. Prefer this hook for production-critical validation that
	// must also run on resumed connections.
	VerifyConnection func(ctx protocol.Context, cs tls.ConnectionState) error
	// HandshakeSuccessful runs after the TLS handshake has completed and the EAP
	// layer is ready to decide whether the authenticated client should proceed.
	HandshakeSuccessful func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status
}

func (s Settings) TLSConfig() *tls.Config {
	return s.Config
}
