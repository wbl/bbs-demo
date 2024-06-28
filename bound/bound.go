// Package bound implements range proofs
package bound

import (
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381"
)

type Params struct {
	G bls12381.G1
	H bls12381.G1
}

type Proof struct{}
type Opening struct {
	K *bls12381.Scalar
	R *bls12381.Scalar
}

func Prove(comm *bls12381.G1, p *Params, o *Opening, bound uint32) (*Proof, error) {
	return nil, errors.New("not implemented")
}

func Verify(comm *bls12381.G1, p *Params, bound uint32, pi *Proof) bool {
	return false
}
