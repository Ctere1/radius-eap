package peap

import (
	"encoding/binary"
	"fmt"

	"github.com/Ctere1/radius-eap/protocol"
)

const TypePEAPExtension protocol.Type = 33

type ExtensionPayload struct {
	AVPs []ExtensionAVP
}

const (
	ResultStatusSuccess uint16 = 1
	ResultStatusFailure uint16 = 2
)

func (ep *ExtensionPayload) Decode(raw []byte) error {
	ep.AVPs = []ExtensionAVP{}
	offset := 0
	for {
		if len(raw[offset:]) < 4 {
			return nil
		}
		avpLen := binary.BigEndian.Uint16(raw[offset+2:offset+2+2]) + ExtensionHeaderSize
		if avpLen < ExtensionHeaderSize {
			return fmt.Errorf("PEAP-Extension: invalid AVP length: %d", avpLen)
		}
		if offset+int(avpLen) > len(raw) {
			return fmt.Errorf("PEAP-Extension: AVP length %d exceeds remaining payload %d", avpLen, len(raw)-offset)
		}
		avp := &ExtensionAVP{}
		err := avp.Decode(raw[offset : offset+int(avpLen)])
		if err != nil {
			return err
		}
		ep.AVPs = append(ep.AVPs, *avp)
		offset = offset + int(avpLen)
	}
}

func (ep *ExtensionPayload) Encode() ([]byte, error) {
	buff := []byte{}
	for _, avp := range ep.AVPs {
		buff = append(buff, avp.Encode()...)
	}
	return buff, nil
}

func (ep *ExtensionPayload) Handle(protocol.Context) protocol.Payload {
	return nil
}

func (ep *ExtensionPayload) ResultStatus() (uint16, bool) {
	found := false
	var status uint16
	for _, avp := range ep.AVPs {
		if avp.Type != AVPAckResult || !avp.Mandatory || len(avp.Value) != 2 {
			continue
		}
		next := binary.BigEndian.Uint16(avp.Value)
		if !found {
			found = true
			status = next
			continue
		}
		if status != next {
			return 0, false
		}
	}
	return status, found
}

func (ep *ExtensionPayload) Offerable() bool {
	return false
}

func (ep *ExtensionPayload) String() string {
	return "<PEAP Extension Payload>"
}

func (ep *ExtensionPayload) Type() protocol.Type {
	return TypePEAPExtension
}
