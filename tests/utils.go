package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func EAPOLTest(t *testing.T, config string) ([]string, int) {
	t.Helper()
	requireEAPOLTest(t)
	requireTestAsset(t, config)
	requireTestAsset(t, filepath.Join("certs", "ca.pem"))

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

func requireEAPOLTest(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("eapol_test"); err != nil {
		t.Skip("skipping EAP integration test: eapol_test is not installed")
	}
}

func requireTestAsset(t *testing.T, relativePath string) {
	t.Helper()
	if _, err := os.Stat(relativePath); err != nil {
		t.Skipf("skipping EAP integration test: missing test asset %q", relativePath)
	}
}
