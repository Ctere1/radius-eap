package peap

import "github.com/Ctere1/radius-eap/protocol"

type State struct {
	SubState map[string]*protocol.State
}
