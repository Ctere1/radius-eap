package eap

import (
	"testing"

	"github.com/Ctere1/radius-eap/protocol"
	eapprotocol "github.com/Ctere1/radius-eap/protocol/eap"
	"github.com/Ctere1/radius-eap/protocol/identity"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

type stateSelectionStateManager struct {
	state    map[string]*protocol.State
	settings protocol.Settings
}

func (s *stateSelectionStateManager) GetEAPSettings() protocol.Settings { return s.settings }
func (s *stateSelectionStateManager) GetEAPState(key string) *protocol.State {
	if s.state == nil {
		return nil
	}
	return s.state[key]
}
func (s *stateSelectionStateManager) SetEAPState(key string, st *protocol.State) {
	if s.state == nil {
		s.state = map[string]*protocol.State{}
	}
	s.state[key] = st
}

func TestSelectRequestState_ReusesKnownState(t *testing.T) {
	req := &radius.Request{Packet: radius.New(radius.CodeAccessRequest, []byte("secret"))}
	if err := rfc2865.State_SetString(req.Packet, "known-state"); err != nil {
		t.Fatalf("set state: %v", err)
	}

	selected := selectRequestState(req, &stateSelectionStateManager{
		state: map[string]*protocol.State{"known-state": {}},
	})

	if selected != "known-state" {
		t.Fatalf("expected known state to be reused, got %q", selected)
	}
}

func TestSelectRequestState_RotatesUnknownState(t *testing.T) {
	req := &radius.Request{Packet: radius.New(radius.CodeAccessRequest, []byte("secret"))}
	if err := rfc2865.State_SetString(req.Packet, "unknown-state"); err != nil {
		t.Fatalf("set state: %v", err)
	}

	selected := selectRequestState(req, &stateSelectionStateManager{})

	if selected == "" {
		t.Fatal("expected generated state to be non-empty")
	}
	if selected == "unknown-state" {
		t.Fatal("expected unknown client-supplied state to be rotated")
	}
}

const terminalProtocolType protocol.Type = 254

type terminalPayload struct {
	status protocol.Status
}

func (p *terminalPayload) Decode([]byte) error     { return nil }
func (p *terminalPayload) Encode() ([]byte, error) { return nil, nil }
func (p *terminalPayload) Type() protocol.Type     { return terminalProtocolType }
func (p *terminalPayload) Offerable() bool         { return true }
func (p *terminalPayload) String() string          { return "terminal" }
func (p *terminalPayload) Handle(ctx protocol.Context) protocol.Payload {
	if p.status != protocol.StatusUnknown {
		ctx.EndInnerProtocol(p.status)
		return nil
	}
	return &terminalPayload{}
}

type recordingResponseWriter struct {
	packet *radius.Packet
}

func (w *recordingResponseWriter) Write(packet *radius.Packet) error {
	w.packet = packet
	return nil
}

func TestHandleRadiusPacket_StateOnlyOnChallenges(t *testing.T) {
	tests := []struct {
		name         string
		status       protocol.Status
		wantCode     radius.Code
		wantStateSet bool
		wantEAPCode  protocol.Code
	}{
		{
			name:         "challenge",
			status:       protocol.StatusUnknown,
			wantCode:     radius.CodeAccessChallenge,
			wantStateSet: true,
			wantEAPCode:  protocol.CodeRequest,
		},
		{
			name:         "accept",
			status:       protocol.StatusSuccess,
			wantCode:     radius.CodeAccessAccept,
			wantStateSet: false,
			wantEAPCode:  protocol.CodeSuccess,
		},
		{
			name:         "reject",
			status:       protocol.StatusError,
			wantCode:     radius.CodeAccessReject,
			wantStateSet: false,
			wantEAPCode:  protocol.CodeFailure,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			settings := protocol.Settings{
				Logger: DefaultLogger(),
				Protocols: []protocol.ProtocolConstructor{
					func() protocol.Payload { return &terminalPayload{status: tc.status} },
				},
				ProtocolPriority: []protocol.Type{terminalProtocolType},
			}
			sm := &stateSelectionStateManager{settings: settings}
			req := &radius.Request{
				Packet: radius.New(radius.CodeAccessRequest, []byte("secret")),
			}
			w := &recordingResponseWriter{}
			p := &Packet{
				r: req,
				eap: &eapprotocol.Payload{
					Code:     protocol.CodeResponse,
					ID:       7,
					MsgType:  terminalProtocolType,
					Payload:  &terminalPayload{status: tc.status},
					Settings: settings,
				},
				stm:               sm,
				responseModifiers: []protocol.ResponseModifier{},
			}

			p.HandleRadiusPacket(w, req)

			if w.packet == nil {
				t.Fatal("expected response packet to be written")
			}
			if w.packet.Code != tc.wantCode {
				t.Fatalf("expected RADIUS code %d, got %d", tc.wantCode, w.packet.Code)
			}
			state := rfc2865.State_GetString(w.packet)
			if tc.wantStateSet && state == "" {
				t.Fatal("expected challenge response to carry state")
			}
			if !tc.wantStateSet && state != "" {
				t.Fatalf("expected final response to omit state, got %q", state)
			}

			rawEAP := rfc2869.EAPMessage_Get(w.packet)
			if len(rawEAP) == 0 {
				t.Fatal("expected encapsulated EAP response")
			}
			ep := &eapprotocol.Payload{Settings: settings}
			if err := ep.Decode(rawEAP); err != nil {
				t.Fatalf("decode EAP response: %v", err)
			}
			if ep.Code != tc.wantEAPCode {
				t.Fatalf("expected EAP code %d, got %d", tc.wantEAPCode, ep.Code)
			}
		})
	}
}

func TestHandleRadiusPacket_RejectsUnexpectedPayloadType(t *testing.T) {
	settings := protocol.Settings{
		Logger: DefaultLogger(),
		Protocols: []protocol.ProtocolConstructor{
			func() protocol.Payload { return &terminalPayload{status: protocol.StatusUnknown} },
			identity.Protocol,
		},
		ProtocolPriority: []protocol.Type{terminalProtocolType},
	}
	existingState := protocol.BlankState(settings)
	existingState.TypeState[terminalProtocolType] = struct{}{}
	sm := &stateSelectionStateManager{
		settings: settings,
		state: map[string]*protocol.State{
			"known-state": existingState,
		},
	}
	req := &radius.Request{
		Packet: radius.New(radius.CodeAccessRequest, []byte("secret")),
	}
	if err := rfc2865.State_SetString(req.Packet, "known-state"); err != nil {
		t.Fatalf("set state: %v", err)
	}
	w := &recordingResponseWriter{}
	p := &Packet{
		r: req,
		eap: &eapprotocol.Payload{
			Code:       protocol.CodeResponse,
			ID:         9,
			MsgType:    identity.TypeIdentity,
			Payload:    &identity.Payload{},
			RawPayload: []byte("user"),
			Settings:   settings,
		},
		stm:               sm,
		responseModifiers: []protocol.ResponseModifier{},
	}

	p.HandleRadiusPacket(w, req)

	if w.packet == nil {
		t.Fatal("expected response packet to be written")
	}
	if w.packet.Code != radius.CodeAccessReject {
		t.Fatalf("expected Access-Reject, got %d", w.packet.Code)
	}
	rawEAP := rfc2869.EAPMessage_Get(w.packet)
	if len(rawEAP) == 0 {
		t.Fatal("expected encapsulated EAP failure")
	}
	ep := &eapprotocol.Payload{Settings: settings}
	if err := ep.Decode(rawEAP); err != nil {
		t.Fatalf("decode EAP response: %v", err)
	}
	if ep.Code != protocol.CodeFailure {
		t.Fatalf("expected EAP failure, got %d", ep.Code)
	}
}

func TestHandleRadiusPacket_RejectsMisconfiguredProtocolPriority(t *testing.T) {
	settings := protocol.Settings{
		Logger:           DefaultLogger(),
		Protocols:        []protocol.ProtocolConstructor{identity.Protocol},
		ProtocolPriority: []protocol.Type{terminalProtocolType},
	}
	sm := &stateSelectionStateManager{settings: settings}
	req := &radius.Request{
		Packet: radius.New(radius.CodeAccessRequest, []byte("secret")),
	}
	w := &recordingResponseWriter{}
	p := &Packet{
		r: req,
		eap: &eapprotocol.Payload{
			Code:       protocol.CodeResponse,
			ID:         11,
			MsgType:    identity.TypeIdentity,
			Payload:    &identity.Payload{},
			RawPayload: []byte("user"),
			Settings:   settings,
		},
		stm:               sm,
		responseModifiers: []protocol.ResponseModifier{},
	}

	p.HandleRadiusPacket(w, req)

	if w.packet == nil {
		t.Fatal("expected response packet to be written")
	}
	if w.packet.Code != radius.CodeAccessReject {
		t.Fatalf("expected Access-Reject, got %d", w.packet.Code)
	}
}
