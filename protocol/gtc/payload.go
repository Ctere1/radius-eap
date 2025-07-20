package gtc

import (
	"beryju.io/radius-eap/protocol"
)

const TypeGTC protocol.Type = 6

func Protocol() protocol.Payload {
	return &Payload{}
}

type Payload struct {
	Challenge []byte

	st  *State
	raw []byte
}

func (p *Payload) Type() protocol.Type {
	return TypeGTC
}

func (p *Payload) Decode(raw []byte) error {
	p.raw = raw
	return nil
}

func (p *Payload) Encode() ([]byte, error) {
	return p.Challenge, nil
}

func (p *Payload) Handle(ctx protocol.Context) protocol.Payload {
	defer func() {
		ctx.SetProtocolState(TypeGTC, p.st)
	}()
	settings := ctx.ProtocolSettings().(Settings)
	if ctx.IsProtocolStart(TypeGTC) {
		p.st = &State{}
		return &Payload{
			Challenge: settings.Challenge(ctx, true),
		}
	}
	p.st = ctx.GetProtocolState(TypeGTC).(*State)
	st := settings.ValidateResponse(ctx, p.raw)
	if st != protocol.StatusUnknown {
		ctx.EndInnerProtocol(st)
		return &Payload{}
	}
	return &Payload{
		Challenge: settings.Challenge(ctx, false),
	}
}

func (p *Payload) Offerable() bool {
	return true
}

func (p *Payload) String() string {
	return "<GTC Packet>"
}
