package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// StatusUnknown MUST be the zero value: BlankState and freshly-created contexts
// rely on an unset status meaning "no decision yet".
func TestStatusZeroValueIsUnknown(t *testing.T) {
	var s Status
	assert.Equal(t, StatusUnknown, s)
	assert.Equal(t, Status(0), StatusUnknown)
}

func TestStatusValuesAreDistinct(t *testing.T) {
	seen := map[Status]bool{}
	for _, s := range []Status{StatusUnknown, StatusSuccess, StatusError, StatusNextProtocol} {
		assert.False(t, seen[s], "status values must be distinct")
		seen[s] = true
	}
}

// Compile-time contract guard for the Logger interface.
type stubLogger struct{}

func (stubLogger) Debug(string, ...interface{}) {}
func (stubLogger) Info(string, ...interface{})  {}
func (stubLogger) Warn(string, ...interface{})  {}
func (stubLogger) Error(string, ...interface{}) {}
func (stubLogger) With(...interface{}) Logger   { return stubLogger{} }

func TestLoggerInterfaceContract(t *testing.T) {
	var _ Logger = stubLogger{}
}
