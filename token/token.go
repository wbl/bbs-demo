package token

import (
	"github.com/cloudflare/circl/ecc/bls12381"

	"github.com/wbl/bbs-demo/bound"
	"github.com/wbl/bbs-demo/linear"
)

type Showing struct {
	aprime bls12381.G1
	abar   bls12381.G1
	d      bls12381.G1

	message     []byte
	ticket      bls12381.G1
	kComm       bls12381.G1
	kRangeProof bound.Proof
}

// A is a signature (g0+s*h0+m*h1+x*h2). For now direct sign, but later will make it work indirectly.
type Token struct {
	a       bls12381.G1
	e       bls12381.Scalar
	s       bls12381.Scalar
	x       bls12381.Scalar
	message []byte
}

type SignRequest struct {
	c       bls12381.G1 // s*h0+m*h1+x*h2
	message []byte
	pi      linear.Proof
}

// No proof required because we can verify A, (s+sprime), e is signature of m, h2
type SignResponse struct {
	a      bls12381.G1
	sprime bls12381.Scalar
	e      bls12381.Scalar
}
