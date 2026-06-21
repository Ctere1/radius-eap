package gtc

import (
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/peap"
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
	settings, ok := ctx.ProtocolSettings().(Settings)
	if !ok || settings.ChallengeHandler == nil {
		ctx.Log().Error("GTC: invalid protocol settings")
		ctx.EndInnerProtocol(protocol.StatusError)
		return nil
	}
	if ctx.IsProtocolStart(TypeGTC) {
		g, v := settings.ChallengeHandler(ctx)
		if g == nil || v == nil {
			ctx.Log().Error("GTC: challenge handler returned nil callbacks")
			ctx.EndInnerProtocol(protocol.StatusError)
			return nil
		}
		p.st = &State{
			getChallenge:     g,
			validateResponse: v,
		}
		return &Payload{
			Challenge: p.st.getChallenge(),
		}
	}
	p.st = ctx.GetProtocolState(TypeGTC).(*State)
	switch p.st.validateResponse(p.raw) {
	case protocol.StatusSuccess:
		// Accepted: emit a protected success Result TLV. PEAP forwards it to the
		// peer, awaits the acknowledgement, and then ends the inner method
		// successfully — the same handshake-completion path MS-CHAPv2 uses.
		return &peap.ExtensionPayload{
			AVPs: []peap.ExtensionAVP{
				{Mandatory: true, Type: peap.AVPAckResult, Value: []byte{0, 1}},
			},
		}
	case protocol.StatusError:
		// Rejected definitively: end on the current context so the tunnel emits
		// EAP-Failure. (The validator must not end the protocol itself; see
		// settings.go.)
		ctx.EndInnerProtocol(protocol.StatusError)
		return nil
	default:
		// Undecided (e.g. a wrong answer with retries remaining): re-issue the
		// challenge for another attempt.
		return &Payload{
			Challenge: p.st.getChallenge(),
		}
	}
}

func (p *Payload) Offerable() bool {
	return true
}

func (p *Payload) String() string {
	return "<GTC Packet>"
}
