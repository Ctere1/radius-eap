package eap

import (
	"encoding/binary"
	"fmt"

	"github.com/Ctere1/radius-eap/protocol"
)

const TypeEAP protocol.Type = 0

func Protocol() protocol.Payload {
	return &Payload{}
}

type Payload struct {
	Code       protocol.Code
	ID         uint8
	Length     uint16
	MsgType    protocol.Type
	Payload    protocol.Payload
	RawPayload []byte

	Settings protocol.Settings
}

func (p *Payload) Type() protocol.Type {
	return TypeEAP
}

func (p *Payload) Offerable() bool {
	return false
}

func (p *Payload) Decode(raw []byte) error {
	if len(raw) < 4 {
		return fmt.Errorf("invalid EAP packet length: %d", len(raw))
	}
	p.Code = protocol.Code(raw[0])
	p.ID = raw[1]
	p.Length = binary.BigEndian.Uint16(raw[2:])
	// RFC 3748 Section 4: a Length greater than the number of received octets
	// means the packet is truncated and MUST be silently discarded. Octets
	// beyond Length are Data Link Layer padding and MUST be ignored — not
	// rejected — so we trim to Length rather than requiring an exact match.
	if int(p.Length) < 4 || int(p.Length) > len(raw) {
		return fmt.Errorf("invalid EAP length %d for %d received octets", p.Length, len(raw))
	}
	raw = raw[:p.Length]
	if p.Code != protocol.CodeRequest && p.Code != protocol.CodeResponse {
		p.RawPayload = raw[4:]
		return nil
	}
	if len(raw) < 5 {
		return fmt.Errorf("EAP packet type missing for code %d", p.Code)
	}
	p.MsgType = protocol.Type(raw[4])
	p.RawPayload = raw[5:]
	if p.Payload == nil {
		pp, _, err := EmptyPayload(p.Settings, p.MsgType)
		if err != nil {
			return err
		}
		p.Payload = pp
	}
	return p.Payload.Decode(p.RawPayload)
}

func (p *Payload) Encode() ([]byte, error) {
	buff := make([]byte, 4)
	buff[0] = uint8(p.Code)
	buff[1] = uint8(p.ID)

	if p.Payload != nil {
		payloadBuffer, err := p.Payload.Encode()
		if err != nil {
			return buff, err
		}
		if p.Code == protocol.CodeRequest || p.Code == protocol.CodeResponse {
			buff = append(buff, uint8(p.MsgType))
		}
		buff = append(buff, payloadBuffer...)
	}
	binary.BigEndian.PutUint16(buff[2:], uint16(len(buff)))
	return buff, nil
}

func (p *Payload) Handle(ctx protocol.Context) protocol.Payload {
	ctx.Log().Debug("EAP: Handle")
	return nil
}

func (p *Payload) String() string {
	return fmt.Sprintf(
		"<EAP Packet Code=%d, ID=%d, Type=%d, Length=%d, Payload=%T>",
		p.Code,
		p.ID,
		p.MsgType,
		p.Length,
		p.Payload,
	)
}
