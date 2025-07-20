package gtc

import "beryju.io/radius-eap/protocol"

type Settings struct {
	Challenge        func(ctx protocol.Context, first bool) []byte
	ValidateResponse func(ctx protocol.Context, data []byte) protocol.Status
}
