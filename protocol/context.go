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

	ProtocolSettings() interface{}

	GetProtocolState(p Type) interface{}
	SetProtocolState(p Type, s interface{})
	IsProtocolStart(p Type) bool

	ResponseModifier
	AddResponseModifier(func(r, q *radius.Packet) error)

	HandleInnerEAP(Payload, StateManager) (Payload, error)
	Inner(Payload, Type) Context
	EndInnerProtocol(Status)

	Log() Logger
}
