package tls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	eap "github.com/Ctere1/radius-eap"
	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
)

type testContext struct {
	log           protocol.Logger
	settings      interface{}
	packet        *radius.Request
	protocolState map[protocol.Type]interface{}
	endStatus     protocol.Status
}

func (t testContext) Packet() *radius.Request { return t.packet }

func (t testContext) RootPayload() protocol.Payload { return nil }

func (t testContext) ProtocolSettings() interface{} { return t.settings }

func (t testContext) GetProtocolState(tp protocol.Type) interface{} {
	if t.protocolState == nil {
		return nil
	}
	return t.protocolState[tp]
}

func (t testContext) SetProtocolState(tp protocol.Type, state interface{}) {
	if t.protocolState == nil {
		return
	}
	t.protocolState[tp] = state
}

func (t testContext) IsProtocolStart(protocol.Type) bool { return false }

func (t testContext) ModifyRADIUSResponse(r, q *radius.Packet) error { return nil }

func (t testContext) AddResponseModifier(func(r, q *radius.Packet) error) {}

func (t testContext) HandleInnerEAP(protocol.Payload, protocol.StateManager) (protocol.Payload, error) {
	return nil, nil
}

func (t testContext) Inner(protocol.Payload, protocol.Type) protocol.Context { return t }

func (t testContext) EndInnerProtocol(protocol.Status) {}

func (t testContext) Log() protocol.Logger { return t.log }

func TestPayloadEncodeWithoutLengthIncludedCopiesData(t *testing.T) {
	p := &Payload{
		Flags: FlagMoreFragments,
		Data:  []byte{0x01, 0x02, 0x03},
	}

	raw, err := p.Encode()
	assert.NoError(t, err)
	assert.Equal(t, []byte{byte(FlagMoreFragments), 0x01, 0x02, 0x03}, raw)
}

func TestSetExpectedWriterByteCountTracksInitialFragment(t *testing.T) {
	conn := &BuffConn{
		reader:           bytes.NewBuffer(make([]byte, 900)),
		writer:           bytes.NewBuffer(nil),
		ctx:              context.Background(),
		writtenByteCount: 900,
		log:              eap.DefaultLogger(),
	}
	p := &Payload{
		Flags:  FlagLengthIncluded | FlagMoreFragments,
		Length: 1800,
		st: &State{
			Conn: conn,
		},
	}

	p.updateExpectedWriterByteCount(testContext{log: eap.DefaultLogger()})

	assert.Equal(t, 1800, conn.expectedWriterByteCount)

	conn.writtenByteCount = 1800
	p.updateExpectedWriterByteCount(testContext{log: eap.DefaultLogger()})
	assert.Zero(t, conn.expectedWriterByteCount)
}

func TestHandleReturnsEmptyAckForIncompletePeerFragment(t *testing.T) {
	conn := &BuffConn{
		reader: bytes.NewBuffer(nil),
		writer: bytes.NewBuffer(nil),
		ctx:    context.Background(),
		log:    eap.DefaultLogger(),
	}
	st := &State{
		Conn:   conn,
		TLS:    &tls.Conn{},
		Logger: eap.DefaultLogger(),
	}
	ctx := testContext{
		log: eap.DefaultLogger(),
		protocolState: map[protocol.Type]interface{}{
			TypeTLS: st,
		},
	}
	p := &Payload{
		Flags:  FlagLengthIncluded | FlagMoreFragments,
		Length: 1800,
		Data:   bytes.Repeat([]byte{0x01}, 900),
	}

	res := p.Handle(ctx)
	ack, ok := res.(*Payload)
	require.True(t, ok)

	assert.Equal(t, FlagNone, ack.Flags)
	assert.Zero(t, ack.Length)
	assert.Empty(t, ack.Data)
	assert.Equal(t, 1800, conn.expectedWriterByteCount)
	assert.True(t, conn.NeedsMoreData())
}

func TestSendNextChunkOnlyFirstFragmentIncludesLength(t *testing.T) {
	conn := &BuffConn{
		reader: bytes.NewBuffer(nil),
		writer: bytes.NewBuffer(nil),
		ctx:    context.Background(),
		log:    eap.DefaultLogger(),
	}
	p := &Payload{
		st: &State{
			Logger:                      eap.DefaultLogger(),
			Conn:                        conn,
			RemainingChunks:             [][]byte{bytes.Repeat([]byte{0x01}, 1000), bytes.Repeat([]byte{0x02}, 1000), bytes.Repeat([]byte{0x03}, 500)},
			TotalPayloadSize:            2500,
			IncludeLengthInNextFragment: true,
		},
	}

	first := p.sendNextChunk()
	second := p.sendNextChunk()
	third := p.sendNextChunk()

	assert.Equal(t, FlagLengthIncluded|FlagMoreFragments, first.Flags)
	assert.Equal(t, FlagMoreFragments, second.Flags)
	assert.Equal(t, FlagNone, third.Flags)
	assert.EqualValues(t, 2500, first.Length)
	assert.EqualValues(t, 2500, second.Length)
	assert.EqualValues(t, 2500, third.Length)
	assert.Zero(t, p.st.TotalPayloadSize)
	assert.False(t, p.st.IncludeLengthInNextFragment)
}

func TestTLSHandshakeFinishedExportsKeysForTLS12AndTLS13(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			serverConn, clientConn := newMutualTLSPair(t, version)
			t.Cleanup(func() {
				_ = serverConn.Close()
				_ = clientConn.Close()
			})

			innerCtx := testContext{log: eap.DefaultLogger()}
			called := false
			p := &Payload{
				st: &State{
					TLS:           serverConn,
					HandshakeCtx:  innerCtx,
					ContextCancel: func() {},
				},
			}
			ctx := testContext{
				log: eap.DefaultLogger(),
				settings: Settings{
					Config: &tls.Config{},
					HandshakeSuccessful: func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status {
						called = true
						require.NotEmpty(t, certs)
						assert.Equal(t, "client.test", certs[0].Subject.CommonName)
						return protocol.StatusSuccess
					},
				},
			}

			p.tlsHandshakeFinished(ctx)

			assert.True(t, called)
			assert.True(t, p.st.HandshakeDone)
			assert.Len(t, p.st.MPPEKey, 128)
			assert.Equal(t, protocol.StatusSuccess, p.st.FinalStatus)
		})
	}
}

func newMutualTLSPair(t *testing.T, version uint16) (*tls.Conn, *tls.Conn) {
	t.Helper()

	caPEM, caKeyPEM, caCert := generateCertificateAuthority(t)
	serverCert := generateLeafCertificate(t, caPEM, caKeyPEM, caCert, "server.test", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCert := generateLeafCertificate(t, caPEM, caKeyPEM, caCert, "client.test", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	rootCAs := x509.NewCertPool()
	require.True(t, rootCAs.AppendCertsFromPEM(caPEM))

	serverSide, clientSide := net.Pipe()
	serverConn := tls.Server(serverSide, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
		MinVersion:   version,
		MaxVersion:   version,
	})
	clientConn := tls.Client(clientSide, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCAs,
		ServerName:   "server.test",
		MinVersion:   version,
		MaxVersion:   version,
	})

	errCh := make(chan error, 2)
	go func() { errCh <- serverConn.Handshake() }()
	go func() { errCh <- clientConn.Handshake() }()

	require.NoError(t, <-errCh)
	require.NoError(t, <-errCh)

	return serverConn, clientConn
}

func generateCertificateAuthority(t *testing.T) ([]byte, []byte, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM, cert
}

func generateLeafCertificate(t *testing.T, caPEM, caKeyPEM []byte, caCert *x509.Certificate, commonName string, extUsages []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	require.NotNil(t, caKeyBlock)
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	require.NoError(t, err)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  extUsages,
		DNSNames:     []string{commonName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPEM = append(certPEM, caPEM...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}
