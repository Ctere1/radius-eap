package tests

import (
	"context"
	ttls "crypto/tls"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eap "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/Ctere1/radius-eap/protocol/identity"
	"github.com/Ctere1/radius-eap/protocol/legacy_nak"
	"github.com/Ctere1/radius-eap/protocol/tls"
)

// TestEAP_TLS_Load is an on-demand load / stress test. It drives many concurrent
// EAP-TLS authentications through real eapol_test processes against a single
// server instance and reports throughput and latency percentiles. Run under
// -race it also exercises the server's concurrency safety (the per-session State
// store and the background TLS handshake goroutine) under genuine parallel load.
//
// It is gated behind EAP_LOAD so it never runs in normal CI. Enable it with, e.g.:
//
//	EAP_LOAD=1 EAP_LOAD_CONCURRENCY=50 EAP_LOAD_TOTAL=1000 \
//	  go test ./tests/ -run TestEAP_TLS_Load -timeout 15m -v
//
// Add -race to validate concurrency safety (slower; use a smaller TOTAL).
//
// Tunables (env):
//   - EAP_LOAD_CONCURRENCY   parallel eapol_test workers           (default 50)
//   - EAP_LOAD_TOTAL         total authentications to run          (default 500)
//   - EAP_LOAD_MAX_FAIL_PCT  max tolerated failure rate, percent   (default 1.0)
func TestEAP_TLS_Load(t *testing.T) {
	if os.Getenv("EAP_LOAD") == "" {
		t.Skip("EAP-TLS load test disabled; set EAP_LOAD=1 to run")
	}
	requireEAPOLTest(t)
	requireTestAsset(t, "config/eap_tls.conf")
	requireTestAsset(t, filepath.Join("certs", "ca.pem"))

	concurrency := loadEnvInt(t, "EAP_LOAD_CONCURRENCY", 50)
	total := loadEnvInt(t, "EAP_LOAD_TOTAL", 500)
	if concurrency > total {
		concurrency = total
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	s := NewTestServer(t)
	s.config = protocol.Settings{
		Logger: eap.DefaultLogger(),
		Protocols: []protocol.ProtocolConstructor{
			identity.Protocol,
			legacy_nak.Protocol,
			tls.Protocol,
		},
		ProtocolPriority: []protocol.Type{identity.TypeIdentity, tls.TypeTLS},
		ProtocolSettings: map[protocol.Type]interface{}{
			tls.TypeTLS: tls.Settings{
				Config: &ttls.Config{
					Certificates: []ttls.Certificate{s.cert},
					ClientAuth:   ttls.RequireAnyClientCert,
					MinVersion:   eapTLSIntegrationVersion,
					MaxVersion:   eapTLSIntegrationVersion,
				},
				HandshakeSuccessful: func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status {
					return protocol.StatusSuccess
				},
			},
		},
	}

	ctx, canc := context.WithCancel(context.Background())
	s.Run(ctx)
	t.Cleanup(canc)
	time.Sleep(200 * time.Millisecond) // give the listener a moment to bind

	var (
		issued    int64
		okCount   int64
		failCount int64
		latMu     sync.Mutex
		lats      = make([]time.Duration, 0, total)
	)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for atomic.AddInt64(&issued, 1) <= int64(total) {
				t0 := time.Now()
				ok := runEAPOLOnce(cwd, "config/eap_tls.conf")
				d := time.Since(t0)

				latMu.Lock()
				lats = append(lats, d)
				latMu.Unlock()

				if ok {
					atomic.AddInt64(&okCount, 1)
				} else {
					atomic.AddInt64(&failCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	okN := atomic.LoadInt64(&okCount)
	failN := atomic.LoadInt64(&failCount)
	done := okN + failN
	throughput := float64(done) / elapsed.Seconds()

	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	pct := func(p float64) time.Duration {
		if len(lats) == 0 {
			return 0
		}
		idx := int(p / 100 * float64(len(lats)))
		if idx >= len(lats) {
			idx = len(lats) - 1
		}
		return lats[idx]
	}

	t.Logf("EAP-TLS load: total=%d concurrency=%d elapsed=%s", done, concurrency, elapsed.Round(time.Millisecond))
	t.Logf("  success=%d failure=%d success_rate=%.2f%%", okN, failN, 100*float64(okN)/float64(done))
	t.Logf("  throughput=%.1f auth/s", throughput)
	t.Logf("  latency p50=%s p95=%s p99=%s max=%s",
		pct(50).Round(time.Millisecond), pct(95).Round(time.Millisecond),
		pct(99).Round(time.Millisecond), pct(100).Round(time.Millisecond))

	// A load run is only meaningful if the server actually authenticated; a high
	// failure rate means a regression (e.g. the handshake-completion race under
	// load) rather than a benign result, so fail rather than bury it in numbers.
	if okN == 0 {
		t.Fatalf("EAP-TLS load: zero successful authentications out of %d", done)
	}
	maxFailPct := 1.0
	if v := os.Getenv("EAP_LOAD_MAX_FAIL_PCT"); v != "" {
		if f, perr := strconv.ParseFloat(v, 64); perr == nil {
			maxFailPct = f
		}
	}
	if failPct := 100 * float64(failN) / float64(done); failPct > maxFailPct {
		t.Fatalf("EAP-TLS load: failure rate %.2f%% exceeds allowed %.2f%%", failPct, maxFailPct)
	}
}

// loadEnvInt reads a positive integer from env var key, or returns def when unset.
func loadEnvInt(t *testing.T, key string, def int) int {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		t.Fatalf("invalid %s=%q: must be a positive integer", key, v)
	}
	return n
}

// runEAPOLOnce runs a single eapol_test EAP-TLS authentication against the local
// server (127.0.0.1:1812, shared secret "foo") and reports success (exit 0). It
// never touches *testing.T, so it is safe to call from many goroutines.
func runEAPOLOnce(cwd, config string) bool {
	cmd := exec.Command("eapol_test", "-s", "foo", "-c", config)
	cmd.Dir = cwd
	_ = cmd.Run()
	return cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0
}
