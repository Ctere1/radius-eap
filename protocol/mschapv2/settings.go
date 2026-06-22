package mschapv2

import (
	"github.com/Ctere1/radius-eap/protocol"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc3079"
)

type Settings struct {
	AuthenticateRequest func(req AuthRequest) (*AuthResponse, error)
	// AuthenticateRequestWithContext is the preferred hook when the caller needs
	// request/session-aware policy decisions. AuthenticateRequest remains
	// available for generic consumers that only need the challenge material.
	AuthenticateRequestWithContext func(ctx protocol.Context, req AuthRequest) (*AuthResponse, error)
	ServerIdentifier               string

	// Standalone selects the outer EAP-MSCHAPv2 flow (EAP type 26 run directly as
	// the outer method, per draft-kamath-pppext-eap-mschapv2), rather than as a
	// PEAP-tunnelled inner method. In standalone mode a successful exchange ends
	// with an outer EAP-Success (instead of a PEAP result TLV) and a failed one runs
	// the MS-CHAP-V2 Failure sub-protocol (RFC 2759 §6). Default false preserves the
	// PEAP-inner behaviour unchanged.
	Standalone bool

	// OnResult, when set, is invoked once with the password verdict: success=true
	// when the peer's NT-Response matched the expected one, false on mismatch. It is
	// a side-effect hook for the consumer (e.g. access/reject auditing) and must not
	// influence the exchange. It is NOT called for backend/credential errors raised
	// by AuthenticateRequest(WithContext) — the consumer already has those.
	OnResult func(ctx protocol.Context, success bool)
}

type AuthRequest struct {
	Challenge     []byte
	PeerChallenge []byte
}

type AuthResponse struct {
	NTResponse            []byte
	RecvKey               []byte
	SendKey               []byte
	AuthenticatorResponse string
}

func DebugStaticCredentials(user, password []byte) func(req AuthRequest) (*AuthResponse, error) {
	return func(req AuthRequest) (*AuthResponse, error) {
		res := &AuthResponse{}
		ntResponse, err := rfc2759.GenerateNTResponse(req.Challenge, req.PeerChallenge, user, password)
		if err != nil {
			return nil, err
		}
		res.NTResponse = ntResponse

		res.RecvKey, err = rfc3079.MakeKey(ntResponse, password, false)
		if err != nil {
			return nil, err
		}

		res.SendKey, err = rfc3079.MakeKey(ntResponse, password, true)
		if err != nil {
			return nil, err
		}

		res.AuthenticatorResponse, err = rfc2759.GenerateAuthenticatorResponse(req.Challenge, req.PeerChallenge, ntResponse, user, password)
		if err != nil {
			return nil, err
		}
		return res, nil
	}
}
