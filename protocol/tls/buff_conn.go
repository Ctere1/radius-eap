package tls

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Ctere1/radius-eap/protocol"
)

// BuffConn is an in-memory net.Conn that bridges a sequence of short-lived EAP
// handler invocations with the single long-lived crypto/tls handshake goroutine
// started in tlsInit.
//
// Threading model:
//   - The TLS goroutine is the SOLE caller of Read/Write/Close/deadline setters.
//   - Handler goroutines are the SOLE callers of FeedFlight/WaitOutbound/
//     HarvestFlight and the inspection helpers.
//
// Every field is guarded by mu. State changes are published by replacing the
// notify channel (broadcastLocked), which both Read and WaitOutbound select on;
// this gives condition-variable semantics that also compose with context
// cancellation and deadlines. The previous implementation shared two
// *bytes.Buffer values and a pair of non-atomic counters across both goroutines
// and relied on retry/backoff timing for correctness, which is a data race.
type BuffConn struct {
	mu sync.Mutex

	// inbound holds peer -> TLS bytes that have been fed but not yet consumed.
	inbound []byte
	// outbound holds TLS -> peer bytes written since the last harvest.
	outbound []byte
	// readWaiting is true while the TLS goroutine is parked in Read with no
	// inbound data, i.e. it has consumed everything and now needs the next peer
	// flight. It is reset by FeedFlight (which supplies that data).
	readWaiting bool

	// notify is closed (and replaced) on every state change to wake any waiter.
	notify chan struct{}
	// closed is closed exactly once by Close; it unblocks every parked Read and
	// every WaitOutbound.
	closed    chan struct{}
	closeOnce sync.Once

	ctx context.Context

	readDeadline  time.Time
	writeDeadline time.Time

	log protocol.Logger
}

// WaitOutcome reports why WaitOutbound returned.
type WaitOutcome int

const (
	// WaitFlightBoundary: the TLS goroutine produced outbound data and/or is
	// parked waiting for the next peer flight. The caller should harvest.
	WaitFlightBoundary WaitOutcome = iota
	// WaitHandshakeDone: the handshake completed successfully.
	WaitHandshakeDone
	// WaitError: the handshake goroutine reported an error.
	WaitError
	// WaitTimeout: the stale-connection context expired.
	WaitTimeout
	// WaitClosed: the conn was closed.
	WaitClosed
)

// NewBuffConn creates an empty conn. Peer data (including the first ClientHello
// flight) is delivered exclusively through FeedFlight so there is a single
// ingestion path.
func NewBuffConn(ctx context.Context, cctx protocol.Context) *BuffConn {
	return &BuffConn{
		notify: make(chan struct{}),
		closed: make(chan struct{}),
		ctx:    ctx,
		log:    cctx.Log(),
	}
}

// broadcastLocked wakes every goroutine waiting on the current notify channel.
// The caller must hold mu.
func (c *BuffConn) broadcastLocked() {
	close(c.notify)
	c.notify = make(chan struct{})
}

// Read implements net.Conn for the TLS goroutine. It returns buffered inbound
// bytes immediately (supporting short reads); otherwise it records that it is
// waiting, wakes any pending WaitOutbound, and parks until more data arrives,
// the conn is closed, the context is cancelled, or the read deadline fires.
func (c *BuffConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.inbound) > 0 {
			n := copy(p, c.inbound)
			c.inbound = c.inbound[n:]
			c.readWaiting = false
			remaining := len(c.inbound)
			c.mu.Unlock()
			c.log.Debug("TLS(buffcon): Read", "n", n, "into", len(p), "remaining", remaining)
			return n, nil
		}
		c.readWaiting = true
		c.broadcastLocked()
		wait := c.notify
		dl := c.readDeadline
		c.mu.Unlock()

		var timeout <-chan time.Time
		if !dl.IsZero() {
			timer := time.NewTimer(time.Until(dl))
			defer timer.Stop()
			timeout = timer.C
		}

		select {
		case <-wait:
			// State changed; re-check inbound under the lock.
		case <-c.closed:
			return 0, io.EOF
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Write implements net.Conn for the TLS goroutine. It appends to the outbound
// buffer, wakes any pending WaitOutbound, and never blocks.
func (c *BuffConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.outbound = append(c.outbound, p...)
	c.broadcastLocked()
	c.mu.Unlock()
	c.log.Debug("TLS(buffcon): Write", "n", len(p))
	return len(p), nil
}

// FeedFlight delivers one complete, reassembled peer flight (EAP fragmentation
// already stripped by the payload layer) and wakes a parked Read. It resets the
// read-waiting state because it provides exactly the data the TLS goroutine was
// waiting for, which prevents a later WaitOutbound from observing a stale
// "waiting" signal from before this flight.
func (c *BuffConn) FeedFlight(data []byte) {
	if len(data) == 0 {
		return
	}
	c.mu.Lock()
	c.inbound = append(c.inbound, data...)
	c.readWaiting = false
	total := len(c.inbound)
	c.broadcastLocked()
	c.mu.Unlock()
	c.log.Debug("TLS(buffcon): FeedFlight", "n", len(data), "buffered", total)
}

// WaitOutbound blocks until the TLS goroutine has produced outbound bytes, is
// parked waiting for the next peer flight, the handshake finished (done), the
// handshake errored (errc), the context expired, or the conn closed. It never
// busy-polls. done and errc may be nil (those arms simply never fire).
func (c *BuffConn) WaitOutbound(done, errc <-chan struct{}) WaitOutcome {
	c.mu.Lock()
	for {
		if len(c.outbound) > 0 {
			c.mu.Unlock()
			return WaitFlightBoundary
		}
		if c.readWaiting && len(c.inbound) == 0 {
			c.mu.Unlock()
			return WaitFlightBoundary
		}
		wait := c.notify
		c.mu.Unlock()

		select {
		case <-wait:
			c.mu.Lock()
		case <-done:
			return WaitHandshakeDone
		case <-errc:
			return WaitError
		case <-c.ctx.Done():
			return WaitTimeout
		case <-c.closed:
			return WaitClosed
		}
	}
}

// HarvestFlight atomically drains and returns the accumulated outbound bytes.
func (c *BuffConn) HarvestFlight() []byte {
	c.mu.Lock()
	out := c.outbound
	c.outbound = nil
	c.mu.Unlock()
	return out
}

// OutboundLen reports how many outbound bytes are buffered.
func (c *BuffConn) OutboundLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.outbound)
}

// InboundLen reports how many inbound bytes are buffered (unconsumed by TLS).
func (c *BuffConn) InboundLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inbound)
}

// PeekInbound returns a copy of the unconsumed inbound bytes.
func (c *BuffConn) PeekInbound() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.inbound)
}

// ResetInbound discards any unconsumed inbound bytes.
func (c *BuffConn) ResetInbound() {
	c.mu.Lock()
	c.inbound = nil
	c.mu.Unlock()
}

// ResetOutbound discards any unharvested outbound bytes.
func (c *BuffConn) ResetOutbound() {
	c.mu.Lock()
	c.outbound = nil
	c.mu.Unlock()
}

// ReadWaiting reports whether the TLS goroutine is currently parked waiting for
// more peer data. Intended for tests.
func (c *BuffConn) ReadWaiting() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readWaiting
}

func (c *BuffConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *BuffConn) LocalAddr() net.Addr  { return inMemAddr{} }
func (c *BuffConn) RemoteAddr() net.Addr { return inMemAddr{} }

func (c *BuffConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.broadcastLocked()
	c.mu.Unlock()
	return nil
}

func (c *BuffConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.broadcastLocked()
	c.mu.Unlock()
	return nil
}

func (c *BuffConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// inMemAddr is a placeholder net.Addr for the in-memory conn.
type inMemAddr struct{}

func (inMemAddr) Network() string { return "eap-tls" }
func (inMemAddr) String() string  { return "buffconn" }
