package eap

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/eap"
	"github.com/Ctere1/radius-eap/protocol/legacy_nak"
	"github.com/gorilla/securecookie"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func (p *Packet) sendErrorResponse(w radius.ResponseWriter, r *radius.Request) {
	rres := r.Response(radius.CodeAccessReject)
	err := w.Write(rres)
	if err != nil {
		p.stm.GetEAPSettings().Logger.Error("failed to send response", "error", err)
	}
}

// HandleRadiusPacket processes one decoded EAP Access-Request and writes the
// RADIUS response. It resolves the session State, runs the EAP method state
// machine (handleEAP), maps the resulting EAP Code to a RADIUS code
// (Request→Access-Challenge, Success→Access-Accept, Failure→Access-Reject),
// applies any registered response modifiers, attaches the State on challenges,
// and finally sets the RFC 2869 Message-Authenticator. It never returns an
// error: failures are turned into an Access-Reject.
func (p *Packet) HandleRadiusPacket(w radius.ResponseWriter, r *radius.Request) {
	l := p.stm.GetEAPSettings().Logger
	p.r = r
	p.state = selectRequestState(r, p.stm)

	rep, err := p.handleEAP(p.eap, p.stm, nil)

	rres := r.Response(radius.CodeAccessReject)
	if err == nil {
		rres.Code = radiusCodeForEAP(rep.Code)
	} else {
		rres.Code = radius.CodeAccessReject
		l.Debug("Rejecting request", "error", err)
	}
	for _, mod := range p.responseModifiers {
		err := mod.ModifyRADIUSResponse(rres, r.Packet)
		if err != nil {
			l.Warn("Root-EAP: failed to modify response packet", "error", err)
			break
		}
	}

	if rres.Code == radius.CodeAccessChallenge {
		err = rfc2865.State_SetString(rres, p.state)
		if err != nil {
			l.Warn("failed to set state", "error", err)
			p.sendErrorResponse(w, r)
			return
		}
	}
	eapEncoded, err := rep.Encode()
	if err != nil {
		l.Warn("failed to encode response", "error", err)
		p.sendErrorResponse(w, r)
		return
	}
	l.Debug("Root-EAP: encapsulated challenge", "length", len(eapEncoded), "type", fmt.Sprintf("%T", rep.Payload))
	err = rfc2869.EAPMessage_Set(rres, eapEncoded)
	if err != nil {
		l.Warn("failed to set EAP message", "error", err)
		p.sendErrorResponse(w, r)
		return
	}
	err = p.setMessageAuthenticator(rres)
	if err != nil {
		l.Warn("failed to set message authenticator", "error", err)
		p.sendErrorResponse(w, r)
		return
	}
	err = w.Write(rres)
	if err != nil {
		l.Warn("failed to send response", "error", err)
	}
}

// radiusCodeForEAP maps a resulting EAP Code to the RADIUS response code:
// Request→Access-Challenge, Success→Access-Accept, Failure (and anything else)
// →Access-Reject.
func radiusCodeForEAP(c protocol.Code) radius.Code {
	switch c {
	case protocol.CodeRequest:
		return radius.CodeAccessChallenge
	case protocol.CodeSuccess:
		return radius.CodeAccessAccept
	default:
		return radius.CodeAccessReject
	}
}

// selectRequestState reuses the RADIUS State from the request when it names a
// known EAP session, otherwise it mints a fresh cryptographically-random key.
// This binds each EAP conversation to a stable, unguessable State value across
// round-trips (RFC 5080 Section 2.1.1).
func selectRequestState(r *radius.Request, stm protocol.StateManager) string {
	if r != nil && r.Packet != nil {
		if rst := rfc2865.State_GetString(r.Packet); rst != "" && stm.GetEAPState(rst) != nil {
			return rst
		}
	}
	return base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(12))
}

// handleEAP is the recursive EAP method state machine. It validates the inbound
// EAP Response, negotiates the next method from the priority list (advancing on
// a Legacy Nak or when a method ends with StatusNextProtocol), dispatches to
// that method's Handle, and builds the outbound EAP packet. The parentContext is
// non-nil only for inner methods (PEAP phase 2), in which case stm is the PEAP
// payload acting as a nested StateManager. It always returns a non-nil
// *eap.Payload so the caller can encode a response even on error.
func (p *Packet) handleEAP(pp protocol.Payload, stm protocol.StateManager, parentContext *context) (*eap.Payload, error) {
	l := p.stm.GetEAPSettings().Logger
	incoming, ok := pp.(*eap.Payload)
	if !ok {
		return &eap.Payload{Code: protocol.CodeFailure}, fmt.Errorf("unexpected root payload type %T", pp)
	}
	if incoming.Code != protocol.CodeResponse {
		return &eap.Payload{
			Code: protocol.CodeFailure,
			ID:   incoming.ID,
		}, fmt.Errorf("unexpected EAP code %d from peer", incoming.Code)
	}

	st := stm.GetEAPState(p.state)
	if st == nil {
		l.Debug("Root-EAP: blank state")
		st = protocol.BlankState(stm.GetEAPSettings())
	}

	nextChallengeToOffer, err := st.GetNextProtocol()
	if err != nil {
		return &eap.Payload{
			Code: protocol.CodeFailure,
			ID:   p.eap.ID,
		}, err
	}

	next := func() (*eap.Payload, error) {
		st.ProtocolIndex += 1
		stm.SetEAPState(p.state, st)
		return p.handleEAP(pp, stm, nil)
	}

	if n, ok := incoming.Payload.(*legacy_nak.Payload); ok {
		l.Debug("Root-EAP: received NAK, trying next protocol", "desired", n.DesiredType)
		incoming.Payload = nil
		return next()
	}

	np, t, err := eap.EmptyPayload(stm.GetEAPSettings(), nextChallengeToOffer)
	if err != nil {
		return &eap.Payload{
			Code: protocol.CodeFailure,
			ID:   incoming.ID,
		}, fmt.Errorf("load EAP payload type %d: %w", nextChallengeToOffer, err)
	}

	ctx := p.buildContext(parentContext, np, t, st, stm, l)
	if !np.Offerable() {
		ctx.Log().Debug("Root-EAP: protocol not offerable, skipping")
		return next()
	}
	ctx.Log().Debug("Root-EAP: Passing to protocol")

	// Decode the peer's payload only when it actually carries this method's data.
	// A different payload type is valid only when we are just now starting this
	// method (the peer is still answering the previous one); otherwise it is a
	// protocol error.
	sameType := samePayloadType(incoming.Payload, np)
	if !sameType && !ctx.IsProtocolStart(np.Type()) {
		return &eap.Payload{
			Code: protocol.CodeFailure,
			ID:   incoming.ID,
		}, fmt.Errorf("unexpected EAP payload type %T, expected %T", incoming.Payload, np)
	}
	if sameType {
		if err := np.Decode(incoming.RawPayload); err != nil {
			return &eap.Payload{
				Code: protocol.CodeFailure,
				ID:   incoming.ID,
			}, fmt.Errorf("decode EAP payload %T: %w", np, err)
		}
	}

	res := &eap.Payload{
		Code:    protocol.CodeRequest,
		ID:      p.eap.ID + 1,
		MsgType: t,
	}
	if payload := np.Handle(ctx); payload != nil {
		res.Payload = payload
	}
	stm.SetEAPState(p.state, st)
	if rm, ok := np.(protocol.ResponseModifier); ok {
		ctx.log.Debug("Root-EAP: Registered response modifier")
		p.responseModifiers = append(p.responseModifiers, rm)
	}
	if applyEndStatus(res, ctx.EndStatus()) {
		ctx.log.Debug("Root-EAP: Protocol ended, starting next protocol")
		return next()
	}
	return res, nil
}

// buildContext creates the protocol.Context for handling np. Inner methods (PEAP
// phase 2) derive from the parent context; outer methods get a fresh root
// context wired with the inner-EAP dispatch closure.
func (p *Packet) buildContext(parentContext *context, np protocol.Payload, t protocol.Type, st *protocol.State, stm protocol.StateManager, l protocol.Logger) *context {
	if parentContext != nil {
		ctx := parentContext.Inner(np, t).(*context)
		ctx.settings = stm.GetEAPSettings().ProtocolSettings[np.Type()]
		return ctx
	}
	ctx := &context{
		req:         p.r,
		rootPayload: p.eap,
		state:       p.state,
		session:     st,
		log:         l.With("type", fmt.Sprintf("%T", np), "code", t),
		settings:    stm.GetEAPSettings().ProtocolSettings[t],
	}
	ctx.handleInner = func(pp protocol.Payload, sm protocol.StateManager, ic protocol.Context) (protocol.Payload, error) {
		return p.handleEAP(pp, sm, ic.(*context))
	}
	return ctx
}

// samePayloadType reports whether the peer's decoded payload is the same concrete
// type as the method we are about to handle.
func samePayloadType(a, b protocol.Payload) bool {
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

// applyEndStatus maps a method's terminal Status onto the outbound EAP packet
// (Success/Failure echo the Response Identifier, RFC 3748 Section 4.2) and
// reports whether the driver should advance to the next protocol.
func applyEndStatus(res *eap.Payload, status protocol.Status) (advance bool) {
	switch status {
	case protocol.StatusSuccess:
		res.Code = protocol.CodeSuccess
		res.ID -= 1
	case protocol.StatusError:
		res.Code = protocol.CodeFailure
		res.ID -= 1
	case protocol.StatusNextProtocol:
		return true
	case protocol.StatusUnknown:
	}
	return false
}

// setMessageAuthenticator computes the RFC 2869 Message-Authenticator
// (HMAC-MD5 over the packet with the attribute zeroed, keyed by the RADIUS
// shared secret) and writes it back. It must be called last, after all other
// attributes are set, so the HMAC covers the complete packet.
func (p *Packet) setMessageAuthenticator(rp *radius.Packet) error {
	_ = rfc2869.MessageAuthenticator_Set(rp, make([]byte, 16))
	hash := hmac.New(md5.New, rp.Secret)
	encode, err := rp.MarshalBinary()
	if err != nil {
		return err
	}
	hash.Write(encode)
	_ = rfc2869.MessageAuthenticator_Set(rp, hash.Sum(nil))
	return nil
}
