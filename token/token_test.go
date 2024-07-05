package token

import (
	"testing"
)

// Creates a token, and verifies it.
// Verification can be done either by the Origin or the Client.
func TestTokenCreationBasic(t *testing.T) {
	// Generating Issuer key material
	pk, sk := Keygen()

	// +--------+            +--------+         +--------+
	// | Origin |            | Client |         | Issuer |
	// +---+----+            +---+----+         +---+----+
	//     |                     |                  |
	req := []byte("hello world")
	//     |                     +---- Request ---->|
	//     |                     |<--- Response ----+
	tok, err := MakeToken(sk, req)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	//     |<-- Request+Token ---|                  +
	//     |                     |                  |
	err = verifyToken(pk, tok)
	if err != nil {
		t.Fatalf("verification error: %s", err)
	}
}

func TestShow(t *testing.T) {
	// Generating Issuer key material
	pk, sk := Keygen()

	// +--------+            +--------+         +--------+
	// | Origin |            | Client |         | Issuer |
	// +---+----+            +---+----+         +---+----+
	//     |                     |                  |
	req := []byte("hello world")
	//     |                     +---- Request ---->|
	//     |                     |<--- Response ----+
	tok, err := MakeToken(sk, req)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	// Client verifieh the issue response
	err = verifyToken(pk, tok)
	if err != nil {
		t.Fatalf("verification error: %s", err)
	}
	// Client creates a showing against Origin example.com
	show, err := ShowTokenWithLimit(tok, []byte("example.com"), 3, 1)
	if err != nil {
		t.Fatalf("showing error: %s", err)
	}
	//     |<-- Request+Token ---|                  +
	//     |                     |                  |
	if err = VerifyShowing(show, pk, 3, []byte("example.com")); err != nil {
		t.Fatalf("verification error: %s", err)
	}
	return
}
