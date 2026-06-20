package eap

import (
	"fmt"

	"github.com/Ctere1/radius-eap/protocol"
)

// EmptyPayload resolves an offered EAP Type to a fresh method payload (EAP type
// negotiation, RFC 3748 Section 5). It returns the constructor whose Type matches, or —
// for a tunneling method that wraps an inner payload (e.g. PEAP, a tls.Payload
// whose HasInner is the PEAP payload) — the outer payload together with the
// inner Type code that must appear on the wire. It errors on an unsupported type.
func EmptyPayload(settings protocol.Settings, t protocol.Type) (protocol.Payload, protocol.Type, error) {
	for _, cons := range settings.Protocols {
		np := cons()
		if np.Type() == t {
			return np, np.Type(), nil
		}
		// If the protocol has an inner protocol, return the original type but the code for the inner protocol
		if i, ok := np.(protocol.Inner); ok {
			if ii := i.HasInner(); ii != nil {
				return np, ii.Type(), nil
			}
		}
	}
	return nil, protocol.Type(0), fmt.Errorf("unsupported EAP type %d", t)
}
