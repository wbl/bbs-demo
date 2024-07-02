package token

import (
	"testing"
)

func TestTokenCreationBasic(t *testing.T) {
	pk, sk := Keygen()
	tok, err := MakeToken(sk, []byte("hello world"))
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	err = verifyToken(pk, tok)
	if err != nil {
		t.Fatalf("verification error: %s", err)
	}
}
