package eap

import (
	"fmt"

	"github.com/Ctere1/radius-eap/protocol"
	"layeh.com/radius"
)

type context struct {
	req         *radius.Request
	rootPayload protocol.Payload
	typeState   map[protocol.Type]any
	log         protocol.Logger
	settings    interface{}
	parent      *context
	endStatus   protocol.Status
	handleInner func(protocol.Payload, protocol.StateManager, protocol.Context) (protocol.Payload, error)
	modifier    func(*radius.Packet, *radius.Packet) error
}

func (ctx *context) RootPayload() protocol.Payload            { return ctx.rootPayload }
func (ctx *context) Packet() *radius.Request                  { return ctx.req }
func (ctx *context) ProtocolSettings() any                    { return ctx.settings }
func (ctx *context) GetProtocolState(p protocol.Type) any     { return ctx.typeState[p] }
func (ctx *context) SetProtocolState(p protocol.Type, st any) { ctx.typeState[p] = st }
func (ctx *context) IsProtocolStart(p protocol.Type) bool     { return ctx.typeState[p] == nil }
func (ctx *context) Log() protocol.Logger                     { return ctx.log }
func (ctx *context) HandleInnerEAP(p protocol.Payload, st protocol.StateManager) (protocol.Payload, error) {
	return ctx.handleInner(p, st, ctx)
}
func (ctx *context) AddResponseModifier(mod func(*radius.Packet, *radius.Packet) error) {
	if ctx.parent != nil {
		ctx.parent.AddResponseModifier(mod)
	}
	ctx.modifier = mod
}
func (ctx *context) ModifyRADIUSResponse(r *radius.Packet, q *radius.Packet) error {
	if ctx.parent != nil {
		return ctx.parent.ModifyRADIUSResponse(r, q)
	}
	if ctx.modifier != nil {
		return ctx.modifier(r, q)
	}
	return nil
}
func (ctx *context) Inner(p protocol.Payload, t protocol.Type) protocol.Context {
	nctx := &context{
		req:         ctx.req,
		rootPayload: ctx.rootPayload,
		typeState:   ctx.typeState,
		log:         ctx.log.With("type", fmt.Sprintf("%T", p), "code", t),
		settings:    ctx.settings,
		parent:      ctx,
		handleInner: ctx.handleInner,
	}
	nctx.log.Debug("Creating inner context")
	return nctx
}
func (ctx *context) EndInnerProtocol(st protocol.Status) {
	ctx.log.Debug("Ending protocol")
	if ctx.parent != nil {
		ctx.parent.EndInnerProtocol(st)
		return
	}
	if ctx.endStatus != protocol.StatusUnknown {
		return
	}
	ctx.endStatus = st
}
