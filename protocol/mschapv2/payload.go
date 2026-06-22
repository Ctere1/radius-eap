package mschapv2

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/eap"
	"github.com/Ctere1/radius-eap/protocol/peap"
	"github.com/gorilla/securecookie"
	"layeh.com/radius"
	"layeh.com/radius/vendors/microsoft"
)

const TypeMSCHAPv2 protocol.Type = 26

func Protocol() protocol.Payload {
	return &Payload{}
}

const (
	challengeValueSize     = 16
	responseValueSize      = 49
	responseReservedSize   = 8
	responseNTResponseSize = 24
)

type OpCode uint8

const (
	OpChallenge OpCode = 1
	OpResponse  OpCode = 2
	OpSuccess   OpCode = 3
	OpFailure   OpCode = 4
)

type Payload struct {
	OpCode     OpCode
	MSCHAPv2ID uint8
	MSLength   uint16
	ValueSize  uint8

	Challenge []byte
	Response  []byte

	Name []byte

	st *State
}

func (p *Payload) Type() protocol.Type {
	return TypeMSCHAPv2
}

func (p *Payload) Decode(raw []byte) error {
	if len(raw) < 1 {
		return errors.New("MSCHAPv2: payload too short")
	}
	p.OpCode = OpCode(raw[0])
	// Success and Failure responses from the peer carry only the OpCode byte.
	if p.OpCode == OpSuccess || p.OpCode == OpFailure {
		if len(raw) != 1 {
			return fmt.Errorf("MSCHAPv2: invalid success/failure payload length: %d", len(raw))
		}
		return nil
	}
	if p.OpCode != OpResponse {
		return fmt.Errorf("MSCHAPv2: unsupported peer opcode: %d", p.OpCode)
	}
	if len(raw) < 5 {
		return fmt.Errorf("MSCHAPv2: payload too short: %d", len(raw))
	}
	p.MSCHAPv2ID = raw[1]
	p.MSLength = binary.BigEndian.Uint16(raw[2:])
	if int(p.MSLength) != len(raw) {
		return fmt.Errorf("MSCHAPv2: incorrect MS-Length: %d, should be %d", p.MSLength, len(raw))
	}

	p.ValueSize = raw[4]
	if p.ValueSize != responseValueSize {
		return fmt.Errorf("MSCHAPv2: incorrect value size: %d", p.ValueSize)
	}
	if len(raw) < 5+int(p.ValueSize) {
		return fmt.Errorf("MSCHAPv2: payload too short for response value: %d", len(raw))
	}
	p.Response = raw[5 : p.ValueSize+5]
	p.Name = raw[5+p.ValueSize:]
	return nil
}

func (p *Payload) Encode() ([]byte, error) {
	encoded := []byte{
		byte(p.OpCode),
		p.MSCHAPv2ID,
		0,
		0,
		byte(len(p.Challenge)),
	}
	encoded = append(encoded, p.Challenge...)
	encoded = append(encoded, p.Name...)
	p.MSLength = uint16(len(encoded))
	binary.BigEndian.PutUint16(encoded[2:], p.MSLength)
	return encoded, nil
}

// Handle runs the MS-CHAPv2 exchange: on start it issues the random server
// Challenge; on the peer Response it asks the consumer to authenticate, compares
// the expected and received NT-Response in constant time, and on a match drives
// the Success packet and the protected result. The consumer-supplied MPPE keys
// are attached to the Access-Accept in ModifyRADIUSResponse.
func (p *Payload) Handle(ctx protocol.Context) protocol.Payload {
	defer func() {
		ctx.SetProtocolState(TypeMSCHAPv2, p.st)
	}()

	rootEap := ctx.RootPayload().(*eap.Payload)
	settings, ok := ctx.ProtocolSettings().(Settings)
	if !ok || (settings.AuthenticateRequest == nil && settings.AuthenticateRequestWithContext == nil) {
		ctx.Log().Error("MSCHAPv2: invalid protocol settings")
		ctx.EndInnerProtocol(protocol.StatusError)
		return nil
	}

	if ctx.IsProtocolStart(TypeMSCHAPv2) {
		ctx.Log().Debug("MSCHAPv2: Empty state, starting")
		p.st = &State{
			Challenge: securecookie.GenerateRandomKey(challengeValueSize),
		}
		return &Payload{
			OpCode:     OpChallenge,
			MSCHAPv2ID: rootEap.ID + 1,
			Challenge:  p.st.Challenge,
			Name:       []byte(settings.ServerIdentifier),
		}
	}
	p.st = ctx.GetProtocolState(TypeMSCHAPv2).(*State)

	response := &Payload{
		MSCHAPv2ID: rootEap.ID + 1,
	}

	ctx.Log().Debug("MSCHAPv2: OpCode", "opcode", p.OpCode)
	if p.OpCode == OpResponse {
		res, err := ParseResponse(p.Response)
		if err != nil {
			ctx.Log().Warn("MSCHAPv2: failed to parse response", "error", err)
			ctx.EndInnerProtocol(protocol.StatusError)
			return nil
		}
		p.st.PeerChallenge = res.Challenge
		authReq := AuthRequest{
			Challenge:     p.st.Challenge,
			PeerChallenge: p.st.PeerChallenge,
		}
		auth, authErr := authenticateRequest(ctx, settings, authReq)
		if authErr != nil {
			ctx.Log().Warn("MSCHAPv2: credential backend error", "error", authErr)
			ctx.EndInnerProtocol(protocol.StatusError)
			return nil
		}
		if subtle.ConstantTimeCompare(auth.NTResponse, res.NTResponse) != 1 {
			// Normal authentication failure (wrong password), not a server error.
			ctx.Log().Info("MSCHAPv2: authentication failed (NT-Response mismatch)")
			if settings.OnResult != nil {
				settings.OnResult(ctx, false)
			}
			if settings.Standalone {
				// Standalone outer EAP-MSCHAPv2: send the MS-CHAP-V2 Failure-Request
				// (draft-kamath §4) so the supplicant gets a proper error; the outer
				// EAP-Failure follows once the peer acks it.
				p.st.AuthFailed = true
				return &FailureRequest{
					Payload: &Payload{OpCode: OpFailure, MSCHAPv2ID: rootEap.ID + 1},
					Message: formatFailureMessage("Authentication failed"),
				}
			}
			// Inner PEAP: end the inner exchange deliberately so the tunnel emits
			// EAP-Failure instead of falling through to a spurious encode error.
			ctx.EndInnerProtocol(protocol.StatusError)
			return nil
		}
		ctx.Log().Info("MSCHAPv2: Successfully checked password")
		if settings.OnResult != nil {
			settings.OnResult(ctx, true)
		}
		p.st.AuthResponse = auth
		succ := &SuccessRequest{
			Payload: &Payload{
				OpCode: OpSuccess,
			},
			Authenticator: []byte(auth.AuthenticatorResponse),
		}
		return succ
	} else if p.OpCode == OpSuccess && p.st.AuthResponse != nil {
		if settings.Standalone {
			// Standalone outer EAP-MSCHAPv2: the peer acked our Success-Request, so
			// finish with an outer EAP-Success (Access-Accept). The MPPE keys are
			// attached by ModifyRADIUSResponse. No PEAP result TLV — that is
			// tunnel-only and meaningless on the bare outer method.
			ctx.EndInnerProtocol(protocol.StatusSuccess)
			return nil
		}
		ep := &peap.ExtensionPayload{
			AVPs: []peap.ExtensionAVP{
				{
					Mandatory: true,
					Type:      peap.AVPAckResult,
					Value:     []byte{0, 1},
				},
			},
		}
		p.st.IsProtocolEnded = true
		return ep
	} else if p.OpCode == OpFailure && p.st.AuthFailed {
		// Standalone: the peer acked our Failure-Request → outer EAP-Failure
		// (Access-Reject).
		ctx.EndInnerProtocol(protocol.StatusError)
		return nil
	} else if p.st.IsProtocolEnded {
		ctx.EndInnerProtocol(protocol.StatusSuccess)
		return &Payload{}
	}
	return response
}

func authenticateRequest(ctx protocol.Context, settings Settings, authReq AuthRequest) (*AuthResponse, error) {
	if settings.AuthenticateRequestWithContext != nil {
		return settings.AuthenticateRequestWithContext(ctx, authReq)
	}
	return settings.AuthenticateRequest(authReq)
}

func (p *Payload) ModifyRADIUSResponse(r *radius.Packet, q *radius.Packet) error {
	if p.st == nil || p.st.AuthResponse == nil {
		return nil
	}
	if r.Code != radius.CodeAccessAccept {
		return nil
	}
	if len(microsoft.MSMPPERecvKey_Get(r, q)) < 1 {
		err := microsoft.MSMPPERecvKey_Set(r, p.st.AuthResponse.RecvKey)
		if err != nil {
			return err
		}
	}
	if len(microsoft.MSMPPESendKey_Get(r, q)) < 1 {
		err := microsoft.MSMPPESendKey_Set(r, p.st.AuthResponse.SendKey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Payload) Offerable() bool {
	return true
}

func (p *Payload) String() string {
	return fmt.Sprintf(
		"<MSCHAPv2 Packet OpCode=%d, MSCHAPv2ID=%d>",
		p.OpCode,
		p.MSCHAPv2ID,
	)
}
