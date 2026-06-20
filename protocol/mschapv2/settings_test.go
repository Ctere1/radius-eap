package mschapv2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DebugStaticCredentials builds an AuthenticateRequest handler from a fixed
// username/password, computing the MS-CHAPv2 NT-Response and MPPE keys per
// RFC 2759 (NT-Response, Authenticator-Response) and RFC 3079 (MPPE keys).
func TestDebugStaticCredentialsComputesRFC2759Material(t *testing.T) {
	authFn := DebugStaticCredentials([]byte("alice"), []byte("s3cret"))

	req := AuthRequest{
		Challenge:     bytesSeq(0x10, challengeValueSize), // server (authenticator) challenge
		PeerChallenge: bytesSeq(0x20, challengeValueSize), // peer challenge
	}

	resp, err := authFn(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Len(t, resp.NTResponse, responseNTResponseSize, "NT-Response is 24 octets (RFC 2759)")
	assert.Len(t, resp.RecvKey, 16, "MPPE recv key is 16 octets (RFC 3079)")
	assert.Len(t, resp.SendKey, 16, "MPPE send key is 16 octets (RFC 3079)")
	assert.NotEqual(t, resp.RecvKey, resp.SendKey, "send/recv keys must differ")
	assert.True(t, strings.HasPrefix(resp.AuthenticatorResponse, "S="), "Authenticator-Response is the S=... string")
}

func TestDebugStaticCredentialsIsDeterministic(t *testing.T) {
	authFn := DebugStaticCredentials([]byte("bob"), []byte("pw"))
	req := AuthRequest{Challenge: bytesSeq(1, challengeValueSize), PeerChallenge: bytesSeq(2, challengeValueSize)}

	a, err := authFn(req)
	require.NoError(t, err)
	b, err := authFn(req)
	require.NoError(t, err)

	assert.Equal(t, a.NTResponse, b.NTResponse)
	assert.Equal(t, a.AuthenticatorResponse, b.AuthenticatorResponse)
}

func TestDebugStaticCredentialsDiffersByPeerChallenge(t *testing.T) {
	authFn := DebugStaticCredentials([]byte("carol"), []byte("pw"))
	base := AuthRequest{Challenge: bytesSeq(1, challengeValueSize), PeerChallenge: bytesSeq(2, challengeValueSize)}
	other := AuthRequest{Challenge: base.Challenge, PeerChallenge: bytesSeq(9, challengeValueSize)}

	a, err := authFn(base)
	require.NoError(t, err)
	b, err := authFn(other)
	require.NoError(t, err)

	assert.NotEqual(t, a.NTResponse, b.NTResponse, "a different peer challenge yields a different NT-Response")
}

func bytesSeq(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}
