package eap

import (
	"log/slog"

	"github.com/Ctere1/radius-eap/protocol"
)

type stdLogger struct {
	l *slog.Logger
}

func DefaultLogger() *stdLogger {
	return &stdLogger{
		l: slog.Default(),
	}
}

func (l *stdLogger) With(args ...interface{}) protocol.Logger {
	return &stdLogger{
		l: l.l.With(args...),
	}
}
func (l *stdLogger) Debug(msg string, args ...interface{}) {
	l.l.Debug(msg, args...)
}
func (l *stdLogger) Info(msg string, args ...interface{}) {
	l.l.Info(msg, args...)
}
func (l *stdLogger) Warn(msg string, args ...interface{}) {
	l.l.Warn(msg, args...)
}
func (l *stdLogger) Error(msg string, args ...interface{}) {
	l.l.Error(msg, args...)
}
