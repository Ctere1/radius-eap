package tests

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func EAPOLTest(t *testing.T, config string) ([]string, int) {
	tester := exec.Command(
		"eapol_test",
		"-s",
		"foo",
		"-c",
		config,
	)
	cwd, err := os.Getwd()
	assert.NoError(t, err)
	tester.Dir = cwd
	o, _ := tester.Output()
	ec := tester.ProcessState.ExitCode()
	return strings.Split(string(o), "\n"), ec
}
