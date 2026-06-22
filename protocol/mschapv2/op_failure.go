package mschapv2

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/gorilla/securecookie"
)

// errAuthenticationFailure is RFC 2759 ERROR_AUTHENTICATION_FAILURE, sent in the
// MS-CHAP-V2 Failure message's "E=" field when a supplicant presents wrong
// credentials.
const errAuthenticationFailure = 691

// FailureRequest is the MS-CHAP-V2 Failure packet the server sends to a peer that
// failed authentication (draft-kamath-pppext-eap-mschapv2 §4, RFC 2759 §6). Unlike
// a Challenge it carries no challenge value; its body is the formatted
// "E=<err> R=<retry> C=<challenge> V=<ver> M=<message>" string.
type FailureRequest struct {
	*Payload
	Message string
}

// Encode serialises the Failure packet: OpCode, MS-CHAPv2 ID, MS-Length, then the
// message body (mirrors SuccessRequest.Encode, which also omits the value-size
// byte that only a Challenge needs).
func (fr *FailureRequest) Encode() ([]byte, error) {
	encoded := []byte{
		byte(OpFailure),
		fr.MSCHAPv2ID,
		0,
		0,
	}
	encoded = append(encoded, []byte(fr.Message)...)
	fr.MSLength = uint16(len(encoded))
	binary.BigEndian.PutUint16(encoded[2:], fr.MSLength)
	return encoded, nil
}

// formatFailureMessage builds the RFC 2759 §6 Failure message. R=0 marks the
// failure as non-retryable; C carries a fresh 16-byte challenge in hex (required
// by the format even when retries are disabled); V=3 is the MS-CHAP-V2 version.
func formatFailureMessage(message string) string {
	challenge := securecookie.GenerateRandomKey(challengeValueSize)
	return fmt.Sprintf("E=%d R=0 C=%s V=3 M=%s",
		errAuthenticationFailure, hex.EncodeToString(challenge), message)
}
