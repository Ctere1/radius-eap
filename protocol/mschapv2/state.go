package mschapv2

type State struct {
	Challenge       []byte
	PeerChallenge   []byte
	IsProtocolEnded bool
	AuthResponse    *AuthResponse
	// AuthFailed is set in standalone mode after the server sends an MS-CHAP-V2
	// Failure-Request, so the peer's Failure-Response is recognised and turned into
	// an outer EAP-Failure.
	AuthFailed bool
}
