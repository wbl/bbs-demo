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

func TestShow(t *testing.T) {
	pk, sk := Keygen()
	tok, err := MakeToken(sk, []byte("hello world"))
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	err = verifyToken(pk, tok)
	if err != nil {
		t.Fatalf("verification error: %s", err)
	}
	show, err := ShowTokenWithLimit(tok, []byte("example.com"), 3, 1)
	if err != nil {
		t.Fatalf("showing error: %s", err)
	}
	if err = VerifyShowing(show, pk, 3, []byte("example.com")); err != nil {
		t.Fatalf("verification error: %s", err)
	}
	return
}
