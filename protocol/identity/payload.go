package identity

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Ctere1/radius-eap/protocol"
)

const TypeIdentity protocol.Type = 1

func Protocol() protocol.Payload {
	return &Payload{}
}

type Payload struct {
	Identity string
}

func (p *Payload) Type() protocol.Type {
	return TypeIdentity
}

// maxIdentityLength bounds the Type-Data of an Identity Response. RFC 3748 sets
// no limit, but the identity is carried on as the RADIUS User-Name, whose
// attribute value is at most 253 octets.
const maxIdentityLength = 253

func (p *Payload) Decode(raw []byte) error {
	if len(raw) == 0 {
		return errors.New("identity payload cannot be empty")
	}
	if len(raw) > maxIdentityLength {
		return fmt.Errorf("identity payload too long: %d octets", len(raw))
	}
	// RFC 3748 Section 5.1: the Identity Response MUST NOT be null terminated.
	// Supplicants send one anyway, so a single trailing NUL is trimmed rather
	// than rejected; an embedded one is refused because the value goes on to be
	// a RADIUS User-Name.
	raw = bytes.TrimSuffix(raw, []byte{0})
	if len(raw) == 0 {
		return errors.New("identity payload cannot be empty")
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return errors.New("identity payload contains a NUL octet")
	}
	// Section 5.1 only RECOMMENDS UTF-8, so a legacy eight-bit identity is
	// carried through rather than refused.
	p.Identity = string(raw)
	return nil
}

func (p *Payload) Encode() ([]byte, error) {
	return []byte{}, nil
}

func (p *Payload) Handle(ctx protocol.Context) protocol.Payload {
	if ctx.IsProtocolStart(TypeIdentity) {
		ctx.SetProtocolState(TypeIdentity, &State{
			Identity: p.Identity,
		})
		ctx.EndInnerProtocol(protocol.StatusNextProtocol)
	}
	return nil
}

func (p *Payload) Offerable() bool {
	return true
}

func (p *Payload) String() string {
	return fmt.Sprintf(
		"<Identity Packet Identity=%s>",
		p.Identity,
	)
}
