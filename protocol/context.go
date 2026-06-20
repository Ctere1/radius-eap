package protocol

import (
	"layeh.com/radius"
)

type Status int

const (
	StatusUnknown Status = iota
	StatusSuccess
	StatusError
	StatusNextProtocol
)

type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	With(args ...interface{}) Logger
}

type Context interface {
	Packet() *radius.Request
	RootPayload() Payload
	State() string

	ProtocolSettings() interface{}

	GetProtocolState(p Type) interface{}
	SetProtocolState(p Type, s interface{})
	IsProtocolStart(p Type) bool

	// SessionValue / SetSessionValue access the session-scoped store shared by
	// every protocol handled under the same RADIUS State (see State.SessionData).
	SessionValue(key string) any
	SetSessionValue(key string, value any)

	ResponseModifier
	AddResponseModifier(func(r, q *radius.Packet) error)

	HandleInnerEAP(Payload, StateManager) (Payload, error)
	Inner(Payload, Type) Context
	EndInnerProtocol(Status)

	Log() Logger
}
