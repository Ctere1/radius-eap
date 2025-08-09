package tls

import (
	"beryju.io/radius-eap/protocol"
)

func (p *Payload) innerHandler(ctx protocol.Context) {
	d := make([]byte, 1024)
	if !ctx.IsProtocolStart(p.Inner.Type()) {
		ctx.Log().Debug("TLS: Reading from TLS for inner protocol")
		n, err := p.st.TLS.Read(d)
		if err != nil {
			ctx.Log().Warn("TLS: Failed to read from TLS connection", "error", err)
			ctx.EndInnerProtocol(protocol.StatusError)
			return
		}
		// Truncate data to the size we read
		d = d[:n]
	}
	err := p.Inner.Decode(d)
	if err != nil {
		ctx.Log().Warn("TLS: failed to decode inner protocol", "error", err)
		ctx.EndInnerProtocol(protocol.StatusError)
		return
	}
	pl := p.Inner.Handle(ctx.Inner(p.Inner, p.Inner.Type()))
	enc, err := pl.Encode()
	if err != nil {
		ctx.Log().Warn("TLS: failed to encode inner protocol", "error", err)
		ctx.EndInnerProtocol(protocol.StatusError)
		return
	}
	_, err = p.st.TLS.Write(enc)
	if err != nil {
		ctx.Log().Warn("TLS: failed to write to TLS", "error", err)
		ctx.EndInnerProtocol(protocol.StatusError)
		return
	}
}
