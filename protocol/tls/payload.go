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
	if p.Flags&FlagTLSStart != 0 {
		return errors.New("invalid TLS payload: unexpected start flag in peer packet")
	}
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

// Handle advances the EAP-TLS exchange by one RADIUS round-trip: on first call
// it starts the TLS handshake (tlsInit), then on each call it feeds the
// reassembled peer flight to the background handshake goroutine, waits for the
// goroutine's response without polling, fragments and returns the outbound
// flight, and on completion resolves the final status — or, when wrapped by
// PEAP, delegates the protected channel to the inner protocol. See _RFC.md for
// the concurrency model.
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

	if p.st.TLS == nil && !p.st.HandshakeDoneValue() {
		// First peer flight (ClientHello). Reassemble any fragments before
		// starting the TLS state machine.
		flight, needMore, err := p.st.reassembler.accept(p.Flags, p.Length, p.Data, maxTLSMessageSize(ctx))
		if err != nil {
			return p.failReassembly(ctx, err)
		}
		if needMore {
			return ackPayload()
		}
		if !p.tlsInit(ctx) {
			return nil
		}
		p.feedAndWait(flight)
	} else if len(p.Data) > 0 {
		ctx.Log().Debug("TLS: Updating buffer with new TLS data from packet")
		flight, needMore, err := p.st.reassembler.accept(p.Flags, p.Length, p.Data, maxTLSMessageSize(ctx))
		if err != nil {
			return p.failReassembly(ctx, err)
		}
		if needMore {
			// Acknowledge the partial fragment and wait for the rest.
			return ackPayload()
		}
		p.feedAndWait(flight)
	}

	if p.st.HasMore() {
		return p.sendNextChunk()
	}
	if p.st.Conn.OutboundLen() == 0 && p.st.HandshakeDoneValue() {
		if p.Inner == nil && p.failOnUnexpectedPostHandshakeClientData(ctx) {
			return nil
		}
		if p.Inner != nil {
			ctx.Log().Debug("TLS: Handshake is done, delegating to inner protocol")
			if !p.innerHandler(ctx) {
				return nil
			}
			return p.startChunkedTransfer(p.st.Conn.HarvestFlight())
		}
		defer p.st.ContextCancel()
		ctx.Log().Debug(
			"TLS: Handshake done, awaiting final status",
			"final_status", p.st.FinalStatusValue(),
			"context_err", p.st.Context.Err(),
			"outbound_len", p.st.Conn.OutboundLen(),
			"inbound_len", p.st.Conn.InboundLen(),
		)
		pst := p.awaitFinalStatus(ctx)
		ctx.EndInnerProtocol(pst)
		return nil
	}
	return p.outboundPayload(ctx)
}

// ackPayload returns the empty EAP-TLS acknowledgement used to request the next
// peer fragment.
func ackPayload() *Payload {
	return &Payload{
		Flags:  FlagNone,
		Length: 0,
		Data:   []byte{},
	}
}

// feedAndWait delivers a complete peer flight to the TLS goroutine and, while
// the handshake is still in progress, waits (without polling) until that
// goroutine has produced its response flight or reached a terminal state.
func (p *Payload) feedAndWait(flight []byte) {
	p.st.Conn.FeedFlight(flight)
	if !p.st.HandshakeDoneValue() {
		p.st.Conn.WaitOutbound(p.st.HandshakeDoneCh, p.st.HandshakeErrCh)
	}
}

// failReassembly aborts the exchange when a peer message violates the configured
// maximum size (DoS hardening) or is otherwise malformed.
func (p *Payload) failReassembly(ctx protocol.Context, err error) protocol.Payload {
	ctx.Log().Warn("TLS: rejecting fragmented message", "error", err)
	p.st.SetFinalStatus(protocol.StatusError)
	if p.st.ContextCancel != nil {
		p.st.ContextCancel()
	}
	p.st.signalHandshakeError()
	ctx.EndInnerProtocol(protocol.StatusError)
	return nil
}

// awaitFinalStatus blocks (without polling) until the background handshake
// goroutine has published a final status, then returns it. An unresolved status
// is converted to an error to avoid emitting an invalid bare EAP request.
func (p *Payload) awaitFinalStatus(ctx protocol.Context) protocol.Status {
	if p.st.FinalStatusValue() == protocol.StatusUnknown {
		select {
		case <-p.st.HandshakeDoneCh:
		case <-p.st.HandshakeErrCh:
		case <-p.st.Context.Done():
		}
	}
	pst := p.st.FinalStatusValue()
	if pst == protocol.StatusUnknown {
		ctx.Log().Warn(
			"TLS: final status unresolved after handshake; converting to error to avoid invalid bare EAP request",
			"context_err", p.st.Context.Err(),
			"outbound_len", p.st.Conn.OutboundLen(),
			"inbound_len", p.st.Conn.InboundLen(),
		)
		pst = protocol.StatusError
		p.st.SetFinalStatus(protocol.StatusError)
	}
	return pst
}

// maxTLSMessageSize returns the consumer-configured maximum reassembled EAP-TLS
// message size, if the protocol settings expose one (both tls.Settings and
// peap.Settings may implement it); otherwise 0 selects the package default.
func maxTLSMessageSize(ctx protocol.Context) int {
	if m, ok := ctx.ProtocolSettings().(interface{ MaxTLSMessageSize() int }); ok {
		return m.MaxTLSMessageSize()
	}
	return 0
}

func (p *Payload) failOnUnexpectedPostHandshakeClientData(ctx protocol.Context) bool {
	if p.st == nil || p.st.Conn == nil {
		return false
	}

	unread := p.st.Conn.PeekInbound()
	if len(unread) == 0 {
		return false
	}

	logArgs := []any{"length", len(unread), "preview", debug.FormatBytes(unread)}
	if hasTLSAlertRecord(unread) {
		ctx.Log().Warn("TLS: client sent post-handshake TLS alert; rejecting exchange", logArgs...)
		p.st.SetFinalStatus(protocol.StatusError)
		if p.st.ContextCancel != nil {
			p.st.ContextCancel()
		}
		ctx.EndInnerProtocol(protocol.StatusError)
		return true
	}

	if hasOnlyTLSApplicationDataRecords(unread) {
		ctx.Log().Warn("TLS: tolerating benign post-handshake client TLS application data", logArgs...)
		p.st.Conn.ResetInbound()
		return false
	}

	ctx.Log().Warn("TLS: unexpected unread post-handshake client TLS data; rejecting exchange", logArgs...)
	p.st.SetFinalStatus(protocol.StatusError)
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
	if p.st == nil || !p.st.HandshakeDoneValue() {
		return nil
	}
	p.st.Logger.Debug("TLS: Adding MPPE Keys")
	// TLS overrides other protocols' MPPE keys.
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
	return p.st.HandshakeCtx.ModifyRADIUSResponse(r, q)
}

func (p *Payload) tlsInit(ctx protocol.Context) bool {
	ctx.Log().Debug("TLS: no TLS connection in state yet, starting connection")
	p.st.Context, p.st.ContextCancel = context.WithTimeout(context.Background(), staleConnectionTimeout*time.Second)
	p.st.Conn = NewBuffConn(p.st.Context, ctx)
	tlsSettings, ok := ctx.ProtocolSettings().(TLSConfig)
	if !ok || tlsSettings.TLSConfig() == nil {
		ctx.Log().Error("TLS: invalid protocol settings")
		p.st.SetFinalStatus(protocol.StatusError)
		p.st.signalHandshakeError()
		ctx.EndInnerProtocol(protocol.StatusError)
		return false
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
			p.st.SetFinalStatus(protocol.StatusError)
			if p.st.ContextCancel != nil {
				p.st.ContextCancel()
			}
			p.st.signalHandshakeError()
			ctx.EndInnerProtocol(protocol.StatusError)
			return
		}
		ctx.Log().Debug("TLS: handshake done")
		p.tlsHandshakeFinished(ctx)
	}()
	return true
}

func (p *Payload) outboundPayload(ctx protocol.Context) protocol.Payload {
	p.st.Conn.WaitOutbound(p.st.HandshakeDoneCh, p.st.HandshakeErrCh)
	if p.st.FinalStatusValue() == protocol.StatusError && !p.st.HandshakeDoneValue() {
		ctx.EndInnerProtocol(protocol.StatusError)
		return nil
	}
	out := p.st.Conn.HarvestFlight()
	if len(out) == 0 {
		// WaitOutbound returned with no bytes to send. Never emit a bare
		// zero-length EAP-TLS data packet (FlagLengthIncluded, Length 0) — that
		// is an invalid record-less request that stalls the supplicant. Resolve
		// through the terminal paths instead, mirroring the handshake-done branch
		// in Handle.
		if p.st.HandshakeDoneValue() {
			if p.Inner == nil && p.failOnUnexpectedPostHandshakeClientData(ctx) {
				return nil
			}
			defer p.st.ContextCancel()
			pst := p.awaitFinalStatus(ctx)
			ctx.EndInnerProtocol(pst)
			return nil
		}
		// Woke without outbound and the handshake is neither done nor errored:
		// the wait ended on context cancellation / connection close (the stale
		// connection timeout backstop). End as an error rather than send an
		// invalid bare request.
		ctx.Log().Warn(
			"TLS: outbound wait ended with no data and handshake not done; ending as error",
			"context_err", p.st.Context.Err(),
			"inbound_len", p.st.Conn.InboundLen(),
		)
		p.st.SetFinalStatus(protocol.StatusError)
		if p.st.ContextCancel != nil {
			p.st.ContextCancel()
		}
		ctx.EndInnerProtocol(protocol.StatusError)
		return nil
	}
	return p.startChunkedTransfer(out)
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
		if p.st.ContextCancel != nil {
			p.st.ContextCancel()
		}
		p.st.SetFinalStatus(protocol.StatusError)
		p.st.signalHandshakeError()
		ctx.EndInnerProtocol(protocol.StatusError)
		return
	}
	p.st.MPPEKey = ksm

	// For EAP-TLS (no inner method) the TLS handshake authenticates the peer, but
	// the consumer's HandshakeSuccessful callback still makes the authorization
	// decision (revoked cert, disabled user, policy reject, ...). Run it BEFORE
	// emitting any result indication so we never send the RFC 9190 Section 2.5 protected
	// success commitment to a peer we are about to reject — doing so would tell a
	// TLS 1.3 supplicant (e.g. Windows 11) that authentication succeeded just
	// before the EAP-Failure, corrupting its state machine.
	if p.Inner == nil {
		settings, ok := ctx.ProtocolSettings().(Settings)
		if !ok || settings.HandshakeSuccessful == nil {
			ctx.Log().Error("TLS: missing handshake callback in protocol settings")
			if p.st.ContextCancel != nil {
				p.st.ContextCancel()
			}
			p.st.SetFinalStatus(protocol.StatusError)
			p.st.signalHandshakeError()
			ctx.EndInnerProtocol(protocol.StatusError)
			return
		}
		status := settings.HandshakeSuccessful(p.st.HandshakeCtx, cs.PeerCertificates)
		if status == protocol.StatusSuccess {
			// RFC 9190 Section 2.5: send the TLS 1.3 protected success indication only
			// once the peer is both authenticated and authorized.
			if err := p.queueProtectedSuccessIndicator(ctx, cs); err != nil {
				ctx.Log().Warn("failed to queue protected success indication", "error", err)
				if p.st.ContextCancel != nil {
					p.st.ContextCancel()
				}
				p.st.SetFinalStatus(protocol.StatusError)
				p.st.signalHandshakeError()
				ctx.EndInnerProtocol(protocol.StatusError)
				return
			}
		}
		p.st.SetFinalStatus(status)
	}
	p.st.SetHandshakeDone(true)
	// Publish completion last, after MPPE keys and final status are set, so a
	// handler observing the closed channel always sees a consistent state.
	p.st.signalHandshakeDone()
}

func (p *Payload) queueProtectedSuccessIndicator(ctx protocol.Context, cs tls.ConnectionState) error {
	if p.Inner != nil || cs.Version != tls.VersionTLS13 {
		return nil
	}
	ctx.Log().Debug("TLS: queueing TLS 1.3 protected success indication")
	_, err := p.st.TLS.Write([]byte{0x00})
	return err
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
		// Last chunk: clear the pending payload size and fragmentation markers.
		defer func() {
			p.st.Logger.Debug("TLS: Sent last chunk")
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
		p.st.HandshakeDoneValue(),
		p.st.FinalStatusValue(),
		p.st.ClientHello,
	)
}
