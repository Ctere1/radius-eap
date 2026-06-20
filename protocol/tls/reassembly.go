package tls

import "fmt"

// defaultMaxTLSMessageSize bounds a single reassembled EAP-TLS message (one
// peer "flight" spread across L/M fragments). RFC 5216 does not mandate a value
// but recommends a configurable maximum to prevent unbounded buffering by a
// malicious peer. 64 KiB comfortably fits real client certificate chains while
// capping memory per session.
const defaultMaxTLSMessageSize = 64 * 1024

// inboundReassembler reassembles a peer EAP-TLS message that is fragmented
// across multiple packets using the RFC 5216 Length (L) and More (M) flags.
//
// It is owned by the payload layer (carried in State) rather than the conn so
// that the conn stays a pure byte pipe with no knowledge of EAP framing.
type inboundReassembler struct {
	expected int    // total declared size from the L flag, 0 until known
	buf      []byte // accumulated fragment bytes
}

// accept consumes one inbound fragment. When the message is complete it returns
// the full reassembled payload with needMore=false; otherwise it returns
// needMore=true and the caller must acknowledge with an empty payload and wait
// for the next fragment. max is the maximum allowed reassembled size (0 selects
// defaultMaxTLSMessageSize). An error is returned if the declared or
// accumulated size exceeds max, so the caller can fail the exchange.
func (r *inboundReassembler) accept(flags Flag, length uint32, data []byte, max int) (complete []byte, needMore bool, err error) {
	if max <= 0 {
		max = defaultMaxTLSMessageSize
	}

	if flags&FlagLengthIncluded != 0 {
		if length > uint32(max) {
			return nil, false, fmt.Errorf("declared TLS message size %d exceeds maximum %d", length, max)
		}
		if r.expected == 0 {
			r.expected = int(length)
		}
	}

	if len(r.buf)+len(data) > max {
		return nil, false, fmt.Errorf("reassembled TLS message size %d exceeds maximum %d", len(r.buf)+len(data), max)
	}
	r.buf = append(r.buf, data...)

	// The peer signals more fragments are coming.
	if flags&FlagMoreFragments != 0 {
		return nil, true, nil
	}
	// A declared length we have not reached yet means more is still expected
	// even without the M flag (defensive against non-conformant peers).
	if r.expected > 0 && len(r.buf) < r.expected {
		return nil, true, nil
	}

	complete = r.buf
	r.buf = nil
	r.expected = 0
	return complete, false, nil
}
