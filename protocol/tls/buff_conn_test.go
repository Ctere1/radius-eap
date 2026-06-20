package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	eap "github.com/Ctere1/radius-eap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bridgeConn pumps one complete flight at a time between a BuffConn and its peer
// using the production handler-facing API (FeedFlight/WaitOutbound/HarvestFlight).
// It returns the bytes harvested, or nil once the owning handshake has finished.
func pump(t *testing.T, from *BuffConn, done <-chan struct{}) ([]byte, bool) {
	t.Helper()
	switch from.WaitOutbound(done, nil) {
	case WaitFlightBoundary:
		return from.HarvestFlight(), false
	case WaitHandshakeDone:
		return from.HarvestFlight(), true
	default:
		return nil, true
	}
}

// TestBuffConnDrivesRealTLSHandshake runs a complete mutual-auth TLS handshake
// where BOTH endpoints speak through a BuffConn driven exactly as the EAP
// handler drives it in production. Running it under -race proves the channel
// handoff is free of data races, and the key-export assertion proves it is
// functionally correct.
func TestBuffConnDrivesRealTLSHandshake(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			caPEM, caKeyPEM, caCert := generateCertificateAuthority(t)
			serverCert := generateLeafCertificate(t, caPEM, caKeyPEM, caCert, "server.test", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
			clientCert := generateLeafCertificate(t, caPEM, caKeyPEM, caCert, "client.test", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			roots := x509.NewCertPool()
			require.True(t, roots.AppendCertsFromPEM(caPEM))

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			cctx := testContext{log: eap.DefaultLogger()}
			serverBC := NewBuffConn(ctx, cctx)
			clientBC := NewBuffConn(ctx, cctx)

			serverConn := tls.Server(serverBC, &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    roots,
				MinVersion:   version,
				MaxVersion:   version,
			})
			clientConn := tls.Client(clientBC, &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      roots,
				ServerName:   "server.test",
				MinVersion:   version,
				MaxVersion:   version,
			})

			serverDone := make(chan struct{})
			clientDone := make(chan struct{})
			var serverErr, clientErr error
			go func() { serverErr = serverConn.HandshakeContext(ctx); close(serverDone) }()
			go func() { clientErr = clientConn.HandshakeContext(ctx); close(clientDone) }()

			clientFinished, serverFinished := false, false
			for !clientFinished || !serverFinished {
				select {
				case <-ctx.Done():
					t.Fatal("handshake stalled")
				default:
				}
				if !clientFinished {
					flight, fin := pump(t, clientBC, clientDone)
					if len(flight) > 0 {
						serverBC.FeedFlight(flight)
					}
					clientFinished = fin
				}
				if !serverFinished {
					flight, fin := pump(t, serverBC, serverDone)
					if len(flight) > 0 {
						clientBC.FeedFlight(flight)
					}
					serverFinished = fin
				}
			}

			<-serverDone
			<-clientDone
			require.NoError(t, serverErr)
			require.NoError(t, clientErr)

			cs := serverConn.ConnectionState()
			require.True(t, cs.HandshakeComplete)
			assert.Equal(t, version, cs.Version)
			require.NotEmpty(t, cs.PeerCertificates)
			assert.Equal(t, "client.test", cs.PeerCertificates[0].Subject.CommonName)

			// Both sides must derive identical EAP keying material.
			scs := serverConn.ConnectionState()
			ccs := clientConn.ConnectionState()
			serverKM, err := scs.ExportKeyingMaterial("test", nil, 32)
			require.NoError(t, err)
			clientKM, err := ccs.ExportKeyingMaterial("test", nil, 32)
			require.NoError(t, err)
			assert.Equal(t, serverKM, clientKM)
		})
	}
}

// TestBuffConnConcurrentFeedHarvest exercises concurrent producers/consumers and
// asserts byte conservation. Most valuable under -race.
func TestBuffConnConcurrentFeedHarvest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bc := NewBuffConn(ctx, testContext{log: eap.DefaultLogger()})

	const rounds = 200
	payload := bytes.Repeat([]byte{0xAB}, 64)

	// "TLS goroutine": copy everything fed inbound straight to outbound.
	var copied int
	tlsDone := make(chan struct{})
	go func() {
		defer close(tlsDone)
		buf := make([]byte, 128)
		for copied < rounds*len(payload) {
			n, err := bc.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = bc.Write(buf[:n])
				copied += n
			}
		}
	}()

	// Feeder goroutine.
	go func() {
		for i := 0; i < rounds; i++ {
			bc.FeedFlight(bytes.Clone(payload))
		}
	}()

	// Harvester on the main goroutine.
	var harvested int
	deadline := time.After(10 * time.Second)
	for harvested < rounds*len(payload) {
		select {
		case <-deadline:
			t.Fatalf("harvested only %d of %d bytes", harvested, rounds*len(payload))
		default:
		}
		bc.WaitOutbound(nil, nil)
		harvested += len(bc.HarvestFlight())
	}
	assert.Equal(t, rounds*len(payload), harvested)
	cancel()
	<-tlsDone
}

func TestBuffConnContextCancelUnblocksRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	bc := NewBuffConn(ctx, testContext{log: eap.DefaultLogger()})

	errc := make(chan error, 1)
	go func() {
		_, err := bc.Read(make([]byte, 16))
		errc <- err
	}()

	cancel()
	select {
	case err := <-errc:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock on context cancel")
	}
}

func TestBuffConnDeadlineUnblocksRead(t *testing.T) {
	bc := NewBuffConn(context.Background(), testContext{log: eap.DefaultLogger()})
	require.NoError(t, bc.SetReadDeadline(time.Now().Add(20*time.Millisecond)))

	errc := make(chan error, 1)
	go func() {
		_, err := bc.Read(make([]byte, 16))
		errc <- err
	}()

	select {
	case err := <-errc:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock on deadline")
	}
}

func TestBuffConnCloseUnblocksRead(t *testing.T) {
	bc := NewBuffConn(context.Background(), testContext{log: eap.DefaultLogger()})

	errc := make(chan error, 1)
	go func() {
		_, err := bc.Read(make([]byte, 16))
		errc <- err
	}()

	require.NoError(t, bc.Close())
	select {
	case err := <-errc:
		assert.True(t, errors.Is(err, io.EOF))
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock on close")
	}
}

func TestBuffConnPartialReads(t *testing.T) {
	bc := NewBuffConn(context.Background(), testContext{log: eap.DefaultLogger()})
	bc.FeedFlight([]byte{1, 2, 3, 4, 5})

	buf := make([]byte, 2)
	n, err := bc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []byte{1, 2}, buf[:n])

	n, err = bc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []byte{3, 4}, buf[:n])

	n, err = bc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []byte{5}, buf[:n])
	assert.Zero(t, bc.InboundLen())
}

// TestWaitOutboundIgnoresTransientReadPark is the regression guard for the
// intermittent EAP-TLS stall fixed in v0.2.2. A parked Read with empty
// inbound/outbound is NOT a flight boundary: crypto/tls parks in Read mid-
// handshake (notably a TLS 1.2 full handshake reads the client Finished before
// writing the server Finished), and treating that as a boundary harvested an
// empty outbound and emitted a bare zero-length EAP-TLS request that stalled the
// supplicant. WaitOutbound must keep blocking until real outbound bytes appear.
func TestWaitOutboundIgnoresTransientReadPark(t *testing.T) {
	bc := NewBuffConn(context.Background(), testContext{log: eap.DefaultLogger()})

	// Simulate the crypto/tls goroutine parking in Read with empty inbound.
	read := make(chan struct{})
	go func() {
		_, _ = bc.Read(make([]byte, 8))
		close(read)
	}()
	require.Eventually(t, bc.ReadWaiting, time.Second, time.Millisecond)

	// WaitOutbound must NOT report a boundary yet — there is no outbound.
	done := make(chan struct{})
	errc := make(chan struct{})
	got := make(chan WaitOutcome, 1)
	go func() { got <- bc.WaitOutbound(done, errc) }()
	select {
	case oc := <-got:
		t.Fatalf("WaitOutbound returned %v during a transient read-park; expected it to block", oc)
	case <-time.After(100 * time.Millisecond):
		// Correct: still blocked because no outbound bytes exist.
	}

	// Once the server writes its flight, WaitOutbound must wake with a boundary.
	if _, err := bc.Write([]byte{0x16, 0x03, 0x03}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case oc := <-got:
		assert.Equal(t, WaitFlightBoundary, oc)
	case <-time.After(time.Second):
		t.Fatal("WaitOutbound did not wake after the outbound Write")
	}

	bc.FeedFlight([]byte{0x01}) // unpark the Read goroutine
	select {
	case <-read:
	case <-time.After(time.Second):
		t.Fatal("Read did not complete after FeedFlight")
	}
}
