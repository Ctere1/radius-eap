package tls

import (
	"bytes"
	"errors"
	"io"

	"github.com/Ctere1/radius-eap/protocol"
)

func (p *Payload) innerHandler(ctx protocol.Context) {
	var d []byte
	if !ctx.IsProtocolStart(p.Inner.Type()) {
		ctx.Log().Debug("TLS: Reading from TLS for inner protocol")
		var readErr error
		d, readErr = readInnerTLSRecord(p.st.TLS)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				ctx.Log().Warn("TLS: inner protocol stream closed")
			} else {
				ctx.Log().Warn("TLS: Failed to read from TLS connection", "error", readErr)
			}
			ctx.EndInnerProtocol(protocol.StatusError)
			return
		}
		if len(d) == 0 {
			ctx.Log().Warn("TLS: inner protocol payload was empty")
			ctx.EndInnerProtocol(protocol.StatusError)
			return
		}
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

func readInnerTLSRecord(r io.Reader) ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if n > 0 {
		return bytes.Clone(buf[:n]), nil
	}
	if err != nil {
		return nil, err
	}
	return nil, io.ErrNoProgress
}
