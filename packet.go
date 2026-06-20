package eap

import (
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/eap"
	"layeh.com/radius"
)

type Packet struct {
	r                 *radius.Request
	eap               *eap.Payload
	stm               protocol.StateManager
	state             string
	responseModifiers []protocol.ResponseModifier
}

// Decode parses the raw EAP-Message bytes from a RADIUS Access-Request into a
// Packet ready for HandleRadiusPacket. The StateManager supplies the method
// settings used to resolve the inner method payload. It returns an error if the
// bytes are not a well-formed EAP packet.
func Decode(stm protocol.StateManager, raw []byte) (*Packet, error) {
	packet := &Packet{
		eap: &eap.Payload{
			Settings: stm.GetEAPSettings(),
		},
		stm:               stm,
		responseModifiers: []protocol.ResponseModifier{},
	}
	err := packet.eap.Decode(raw)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

// Encode serializes the packet's EAP payload into the bytes to place in the
// outbound EAP-Message attribute.
func (p *Packet) Encode() ([]byte, error) {
	return p.eap.Encode()
}
