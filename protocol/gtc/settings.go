package gtc

import "github.com/Ctere1/radius-eap/protocol"

type GetChallenge func() []byte

// ValidateResponse evaluates the peer's cleartext answer and returns the outcome
// as a protocol.Status:
//
//	StatusSuccess - the answer is accepted; the tunnel emits a protected success
//	                Result TLV.
//	StatusError   - the answer is rejected definitively; the inner method ends and
//	                the tunnel emits EAP-Failure.
//	StatusUnknown - no decision yet (e.g. a wrong answer with retries remaining);
//	                the method re-issues the challenge.
//
// The decision is applied by the GTC payload against the *current* request
// context. A consumer MUST NOT call ctx.EndInnerProtocol from here: the
// getChallenge/validateResponse closures capture the context from the round in
// which the challenge handler first ran, so ending the protocol through it would
// target a stale, already-completed request and never terminate the conversation.
type ValidateResponse func(answer []byte) protocol.Status

type Settings struct {
	ChallengeHandler func(ctx protocol.Context) (GetChallenge, ValidateResponse)
}
