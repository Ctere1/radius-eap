package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/Ctere1/radius-eap/debug"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/avast/retry-go/v4"
	"layeh.com/radius"
	"layeh.com/radius/vendors/microsoft"
)

const maxChunkSize = 1000
const staleConnectionTimeout = 10

const TypeTLS protocol.Type = 13

func Protocol() protocol.Payload {
	return &Payload{}
}

type Payload struct {
	Flags  Flag
	Length uint32
	Data   []byte

	st    *State
	Inner protocol.Payload
}

func (p *Payload) Type() protocol.Type {
	return TypeTLS
}

func (p *Payload) HasInner() protocol.Payload {
	return p.Inner
}

func (p *Payload) Offerable() bool {
	return true
}

func (p *Payload) Decode(raw []byte) error {
	if len(raw) < 1 {
		return errors.New("invalid TLS payload: missing flags")
	}
	p.Flags = Flag(raw[0])
	raw = raw[1:]
	if p.Flags&FlagLengthIncluded != 0 {
		if len(raw) < 4 {
			return errors.New("invalid size")
		}
		p.Length = binary.BigEndian.Uint32(raw)
		p.Data = raw[4:]
	} else {
		p.Data = raw[0:]
	}
	return nil
}

func (p *Payload) Encode() ([]byte, error) {
	l := 1
	if p.Flags&FlagLengthIncluded != 0 {
		l += 4
	}
	buff := make([]byte, len(p.Data)+l)
	buff[0] = byte(p.Flags)
	dataOffset := 1
	if p.Flags&FlagLengthIncluded != 0 {
		buff[1] = byte(p.Length >> 24)
		buff[2] = byte(p.Length >> 16)
		buff[3] = byte(p.Length >> 8)
		buff[4] = byte(p.Length)
		dataOffset = 5
	}
	if len(p.Data) > 0 {
		copy(buff[dataOffset:], p.Data)
	}
	return buff, nil
}

func (p *Payload) Handle(ctx protocol.Context) protocol.Payload {
	defer func() {
		ctx.SetProtocolState(TypeTLS, p.st)
	}()
	if ctx.IsProtocolStart(TypeTLS) {
		p.st = NewState(ctx).(*State)
		p.st.HandshakeCtx = ctx.Inner(nil, p.Type())
		p.st.Logger = ctx.Log()
		return &Payload{
			Flags: FlagTLSStart,
		}
	}
	p.st = ctx.GetProtocolState(TypeTLS).(*State)

	if p.st.TLS == nil {
		p.tlsInit(ctx)
	} else if len(p.Data) > 0 {
		ctx.Log().Debug("TLS: Updating buffer with new TLS data from packet")
		p.st.Conn.UpdateData(p.Data)
		p.updateExpectedWriterByteCount(ctx)
		if !p.st.Conn.NeedsMoreData() && !p.st.HandshakeDone {
			// Wait for outbound data to be available
			p.st.Conn.OutboundData()
		}
	}
	// If we need more data, send the client the go-ahead
	if p.st.Conn.NeedsMoreData() {
		return &Payload{
			Flags:  FlagNone,
			Length: 0,
			Data:   []byte{},
		}
	}
	if p.st.HasMore() {
		return p.sendNextChunk()
	}
	if p.st.Conn.writer.Len() == 0 && p.st.HandshakeDone {
		if p.Inner == nil && p.failOnUnexpectedPostHandshakeClientData(ctx) {
			return nil
		}
		if p.Inner != nil {
			ctx.Log().Debug("TLS: Handshake is done, delegating to inner protocol")
			p.innerHandler(ctx)
			return p.startChunkedTransfer(p.st.Conn.OutboundData())
		}
		defer p.st.ContextCancel()
		ctx.Log().Debug(
			"TLS: Handshake done, awaiting final status",
			"final_status", p.st.FinalStatus,
			"context_err", p.st.Context.Err(),
			"writer_len", p.st.Conn.writer.Len(),
			"reader_len", p.st.Conn.reader.Len(),
		)
		// If we don't have a final status from the handshake finished function, stall for time
		pst, err := retry.DoWithData(
			func() (protocol.Status, error) {
				ctx.Log().Debug(
					"TLS: polling final status",
					"final_status", p.st.FinalStatus,
					"context_err", p.st.Context.Err(),
				)
				if p.st.FinalStatus == protocol.StatusUnknown {
					return p.st.FinalStatus, errStall
				}
				return p.st.FinalStatus, nil
			},
			retry.Context(p.st.Context),
			retry.Delay(10*time.Microsecond),
			retry.DelayType(retry.BackOffDelay),
			retry.MaxDelay(100*time.Millisecond),
			retry.Attempts(0),
		)
		if err != nil || pst == protocol.StatusUnknown {
			ctx.Log().Warn(
				"TLS: final status unresolved after handshake; converting to error to avoid invalid bare EAP request",
				"final_status", pst,
				"retry_error", err,
				"context_err", p.st.Context.Err(),
				"writer_len", p.st.Conn.writer.Len(),
				"reader_len", p.st.Conn.reader.Len(),
			)
			pst = protocol.StatusError
			p.st.FinalStatus = protocol.StatusError
		}
		ctx.EndInnerProtocol(pst)
		return nil
	}
	return p.startChunkedTransfer(p.st.Conn.OutboundData())
}

func (p *Payload) failOnUnexpectedPostHandshakeClientData(ctx protocol.Context) bool {
	if p.st == nil || p.st.Conn == nil {
		return false
	}

	unread := p.st.Conn.reader.Bytes()
	if len(unread) == 0 {
		return false
	}

	logArgs := []any{"length", len(unread), "preview", debug.FormatBytes(unread)}
	if hasTLSAlertRecord(unread) {
		ctx.Log().Warn("TLS: client sent post-handshake TLS alert; rejecting exchange", logArgs...)
		p.st.FinalStatus = protocol.StatusError
		if p.st.ContextCancel != nil {
			p.st.ContextCancel()
		}
		ctx.EndInnerProtocol(protocol.StatusError)
		return true
	}

	if hasOnlyTLSApplicationDataRecords(unread) {
		ctx.Log().Warn("TLS: tolerating benign post-handshake client TLS application data", logArgs...)
		p.st.Conn.reader.Reset()
		return false
	}

	ctx.Log().Warn("TLS: unexpected unread post-handshake client TLS data; rejecting exchange", logArgs...)
	p.st.FinalStatus = protocol.StatusError
	if p.st.ContextCancel != nil {
		p.st.ContextCancel()
	}
	ctx.EndInnerProtocol(protocol.StatusError)
	return true
}

func (p *Payload) ModifyRADIUSResponse(r *radius.Packet, q *radius.Packet) error {
	if r.Code != radius.CodeAccessAccept {
		return nil
	}
	if p.st == nil || !p.st.HandshakeDone {
		return nil
	}
	p.st.Logger.Debug("TLS: Adding MPPE Keys")
	// TLS overrides other protocols' MPPE keys
	if len(microsoft.MSMPPERecvKey_Get(r, q)) > 0 {
		microsoft.MSMPPERecvKey_Del(r)
	}
	if len(microsoft.MSMPPESendKey_Get(r, q)) > 0 {
		microsoft.MSMPPESendKey_Del(r)
	}
	err := microsoft.MSMPPERecvKey_Set(r, p.st.MPPEKey[:32])
	if err != nil {
		return err
	}
	err = microsoft.MSMPPESendKey_Set(r, p.st.MPPEKey[64:64+32])
	if err != nil {
		return err
	}
	if err = microsoft.MSMPPEEncryptionPolicy_Set(r, microsoft.MSMPPEEncryptionPolicy_Value_EncryptionRequired); err != nil {
		return err
	}
	if err = microsoft.MSMPPEEncryptionTypes_Set(r, microsoft.MSMPPEEncryptionTypes_Value_RC4128bitAllowed); err != nil {
		return err
	}
	return p.st.HandshakeCtx.ModifyRADIUSResponse(r, q)
}

func (p *Payload) tlsInit(ctx protocol.Context) {
	ctx.Log().Debug("TLS: no TLS connection in state yet, starting connection")
	p.st.Context, p.st.ContextCancel = context.WithTimeout(context.Background(), staleConnectionTimeout*time.Second)
	p.st.Conn = NewBuffConn(p.Data, p.st.Context, ctx)
	p.updateExpectedWriterByteCount(ctx)
	tlsSettings, ok := ctx.ProtocolSettings().(TLSConfig)
	if !ok || tlsSettings.TLSConfig() == nil {
		ctx.Log().Error("TLS: invalid protocol settings")
		p.st.FinalStatus = protocol.StatusError
		ctx.EndInnerProtocol(protocol.StatusError)
		return
	}
	cfg := tlsSettings.TLSConfig().Clone()
	settings, _ := ctx.ProtocolSettings().(Settings)
	applyContextTLSHooks(cfg, ctx, settings)

	if klp, ok := os.LookupEnv("SSLKEYLOGFILE"); ok {
		kl, err := os.OpenFile(klp, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			ctx.Log().Warn("TLS: failed to open SSLKEYLOGFILE", "path", klp, "error", err)
		} else {
			cfg.KeyLogWriter = kl
		}
	}

	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		ctx.Log().Debug("TLS: ClientHello received", "server_name", chi.ServerName, "remote_addr", chi.Conn.RemoteAddr())
		p.st.ClientHello = chi
		return nil, nil
	}
	p.st.TLS = tls.Server(p.st.Conn, cfg)
	_ = p.st.TLS.SetDeadline(time.Now().Add(staleConnectionTimeout * time.Second))
	go func() {
		err := p.st.TLS.HandshakeContext(p.st.Context)
		if err != nil {
			ctx.Log().Debug("TLS: Handshake error", "error", err)
			p.st.FinalStatus = protocol.StatusError
			ctx.EndInnerProtocol(protocol.StatusError)
			return
		}
		ctx.Log().Debug("TLS: handshake done")
		p.tlsHandshakeFinished(ctx)
	}()
}

func applyContextTLSHooks(cfg *tls.Config, ctx protocol.Context, settings Settings) {
	if cfg == nil {
		return
	}

	if settings.VerifyPeerCertificate != nil {
		cfg.VerifyPeerCertificate = chainVerifyPeerCertificate(cfg.VerifyPeerCertificate, ctx, settings.VerifyPeerCertificate)
	}
	if settings.VerifyConnection != nil {
		cfg.VerifyConnection = chainVerifyConnection(cfg.VerifyConnection, ctx, settings.VerifyConnection)
	}
}

func chainVerifyPeerCertificate(
	original func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error,
	ctx protocol.Context,
	withContext func(ctx protocol.Context, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error,
) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if original != nil {
			if err := original(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		return withContext(ctx, rawCerts, verifiedChains)
	}
}

func chainVerifyConnection(
	original func(cs tls.ConnectionState) error,
	ctx protocol.Context,
	withContext func(ctx protocol.Context, cs tls.ConnectionState) error,
) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if original != nil {
			if err := original(cs); err != nil {
				return err
			}
		}
		return withContext(ctx, cs)
	}
}

func (p *Payload) tlsHandshakeFinished(ctx protocol.Context) {
	cs := p.st.TLS.ConnectionState()
	label := "client EAP encryption"
	var context []byte
	switch cs.Version {
	case tls.VersionTLS10:
		ctx.Log().Debug("TLS: Version(1.0)", "ver", cs.Version)
	case tls.VersionTLS11:
		ctx.Log().Debug("TLS: Version(1.1)", "ver", cs.Version)
	case tls.VersionTLS12:
		ctx.Log().Debug("TLS: Version(1.2)", "ver", cs.Version)
	case tls.VersionTLS13:
		ctx.Log().Debug("TLS: Version(1.3)", "ver", cs.Version)
		label = "EXPORTER_EAP_TLS_Key_Material"
		context = []byte{byte(TypeTLS)}
	}
	ksm, err := cs.ExportKeyingMaterial(label, context, 64+64)
	if err != nil {
		ctx.Log().Warn("failed to export keying material", "error", err)
		p.st.ContextCancel()
		ctx.EndInnerProtocol(protocol.StatusError)
		return
	}
	p.st.MPPEKey = ksm
	p.st.HandshakeDone = true
	if p.Inner == nil {
		settings, ok := ctx.ProtocolSettings().(Settings)
		if !ok || settings.HandshakeSuccessful == nil {
			ctx.Log().Error("TLS: missing handshake callback in protocol settings")
			p.st.FinalStatus = protocol.StatusError
			ctx.EndInnerProtocol(protocol.StatusError)
			return
		}
		p.st.FinalStatus = settings.HandshakeSuccessful(p.st.HandshakeCtx, cs.PeerCertificates)
	}
}

func (p *Payload) startChunkedTransfer(data []byte) *Payload {
	if len(data) > maxChunkSize {
		p.st.Logger.Debug("TLS: Data needs to be chunked", "length", len(data))
		p.st.RemainingChunks = append(p.st.RemainingChunks, slices.Collect(slices.Chunk(data, maxChunkSize))...)
		p.st.TotalPayloadSize = len(data)
		p.st.IncludeLengthInNextFragment = true
		return p.sendNextChunk()
	}
	p.st.Logger.Debug("TLS: Sending data un-chunked", "length", len(data))
	p.st.Conn.writer.Reset()
	return &Payload{
		Flags:  FlagLengthIncluded,
		Length: uint32(len(data)),
		Data:   data,
	}
}

func (p *Payload) sendNextChunk() *Payload {
	nextChunk := p.st.RemainingChunks[0]
	p.st.Logger.Debug("TLS: Sending next chunk", "preview", debug.FormatBytes(nextChunk), "length", len(nextChunk))
	p.st.RemainingChunks = p.st.RemainingChunks[1:]
	flags := FlagNone
	if p.st.IncludeLengthInNextFragment {
		flags |= FlagLengthIncluded
		p.st.IncludeLengthInNextFragment = false
	}
	if p.st.HasMore() {
		p.st.Logger.Debug("TLS: More chunks left", "chunks", len(p.st.RemainingChunks))
		flags |= FlagMoreFragments
	} else {
		// Last chunk, reset the connection buffers and pending payload size
		defer func() {
			p.st.Logger.Debug("TLS: Sent last chunk")
			p.st.Conn.writer.Reset()
			p.st.TotalPayloadSize = 0
			p.st.IncludeLengthInNextFragment = false
		}()
	}
	p.st.Logger.Debug("TLS: Total payload size", "length", p.st.TotalPayloadSize)
	return &Payload{
		Flags:  flags,
		Length: uint32(p.st.TotalPayloadSize),
		Data:   nextChunk,
	}
}

func (p *Payload) updateExpectedWriterByteCount(ctx protocol.Context) {
	if p.Flags&FlagLengthIncluded == 0 || p.st == nil || p.st.Conn == nil {
		return
	}
	p.st.Conn.SetExpectedWriterByteCount(int(p.Length), len(p.Data))
	if p.st.Conn.expectedWriterByteCount > 0 {
		ctx.Log().Debug("TLS: Expecting total bytes, will buffer", "total", p.Length)
	}
}

func hasTLSAlertRecord(data []byte) bool {
	for len(data) >= 5 {
		recordLength := int(binary.BigEndian.Uint16(data[3:5]))
		totalLength := 5 + recordLength
		if len(data) < totalLength {
			return false
		}
		if data[0] == 0x15 {
			return true
		}
		data = data[totalLength:]
	}
	return false
}

func hasOnlyTLSApplicationDataRecords(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for len(data) >= 5 {
		recordLength := int(binary.BigEndian.Uint16(data[3:5]))
		totalLength := 5 + recordLength
		if len(data) < totalLength {
			return false
		}
		if data[0] != 0x17 {
			return false
		}
		data = data[totalLength:]
	}
	return len(data) == 0
}

func (p *Payload) String() string {
	return fmt.Sprintf(
		"<TLS Packet HandshakeDone=%t, FinalStatus=%d, ClientHello=%v>",
		p.st.HandshakeDone,
		p.st.FinalStatus,
		p.st.ClientHello,
	)
}
