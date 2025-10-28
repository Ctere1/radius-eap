package gtc

import "github.com/Ctere1/radius-eap/protocol"

type GetChallenge func() []byte
type ValidateResponse func(answer []byte)

type Settings struct {
	ChallengeHandler func(ctx protocol.Context) (GetChallenge, ValidateResponse)
}
