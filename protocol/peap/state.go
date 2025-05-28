package peap

import "beryju.io/radius-eap/protocol"

type State struct {
	SubState map[string]*protocol.State
}
