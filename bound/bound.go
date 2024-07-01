// Package bound implements range proofs for power of two sizes
package bound

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/wbl/bbs-demo/linear"
)

type Params struct {
	G *bls12381.G1
	H *bls12381.G1
}

type Proof struct {
	Ci []*bls12381.G1 //Commitments to each bit
	Pi *linear.Proof
}
type Opening struct {
	K *bls12381.Scalar
	R *bls12381.Scalar
}

func Prove(comm *bls12381.G1, p *Params, o *Opening, bitlength int) (*Proof, error) {
	if bitlength > 8 {
		return nil, fmt.Errorf("Not implemented yet")
	}
	n, err := o.K.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("error marshalling: %w", err)
	}
	// N is big endian, we want little endian bits
	val := n[len(n)-1]

	bitrs := make([]*bls12381.Scalar, bitlength)
	bitcoms := make([]*bls12381.G1, bitlength)
	digits := make([]*bls12381.Scalar, bitlength)

	for i := 0; i < bitlength; i++ {
		// Very nonconstant time
		bitrs[i] = &bls12381.Scalar{}
		bitcoms[i] = &bls12381.G1{}
		digits[i] = &bls12381.Scalar{}
		digits[i].SetUint64(0)
		bitrs[i].Random(rand.Reader)
		bitcoms[i].ScalarMult(bitrs[i], p.H)
		if val%2 == 1 {
			digits[i].SetOne()
			bitcoms[i].Add(bitcoms[i], p.G)
		}
		val = val / 2
	}

	// Idea of the proof: Show di commitments. given Ci Ci-g is a commitment to di-1. Can show di(Ci-g) is opening to zero.
	// Then show d0*g+2*d1*g+4*d2*g+o.R*h is opening of comm

	phi := &linear.Statement{}
	w := &linear.Witness{}
	phi.F = make([][]bls12381.G1, 2*bitlength+1)
	for i := 0; i < len(phi.F); i++ {
		phi.F[i] = make([]bls12381.G1, 3*bitlength+1)
		for j := 0; j < len(phi.F[i]); j++ {
			phi.F[i][j].SetIdentity()
		}
	}
	phi.X = make([]bls12381.G1, 2*bitlength+1)
	w.W = make([]bls12381.Scalar, 3*bitlength+1)

	// Open digits
	for i := 0; i < bitlength; i++ {
		phi.X[i] = *bitcoms[i]
		phi.F[i][i] = *p.G
		phi.F[i][bitlength+i] = *p.H
		w.W[i].Set(digits[i])
		w.W[bitlength+i].Set(bitrs[i])
	}

	negG := &bls12381.G1{}
	*negG = *p.G
	negG.Neg()
	for i := 0; i < bitlength; i++ {
		phi.F[bitlength+i][i].Add(bitcoms[i], negG)
		phi.F[bitlength+i][2*bitlength+i] = *p.H
		phi.F[bitlength+i][2*bitlength+i].Neg()
		phi.X[bitlength+i].SetIdentity()
		w.W[2*bitlength+i].Mul(digits[i], bitrs[i])
	}

	phi.F[2*bitlength][0] = *p.G

	two := &bls12381.Scalar{}
	two.SetUint64(2)
	for i := 1; i < bitlength; i++ {
		phi.F[2*bitlength][i].ScalarMult(two, &phi.F[2*bitlength][i-1])
	}
	phi.F[2*bitlength][3*bitlength] = *p.H
	phi.X[2*bitlength] = *comm
	w.W[3*bitlength] = *o.R

	Pi := &Proof{}
	Pi.Ci = bitcoms
	if !linear.Satisfied(phi, w) {
		return nil, fmt.Errorf("internal error")
	}
	Pi.Pi, err = linear.Prove(phi, w) // Todo: Check if right
	if err != nil {
		return nil, fmt.Errorf("error proving: %w", err)
	}
	return Pi, nil
}

func Verify(comm *bls12381.G1, p *Params, bitlength int, pi *Proof) bool {
	phi := linear.NewStatement(3*bitlength+1, 2*bitlength+1)
	// Commitment opening
	for i := 0; i < bitlength; i++ {
		phi.X[i] = *pi.Ci[i]
		phi.F[i][i] = *p.G
		phi.F[i][bitlength+i] = *p.H
	}

	negG := &bls12381.G1{}
	*negG = *p.G
	negG.Neg()
	for i := 0; i < bitlength; i++ {
		phi.F[bitlength+i][i].Add(pi.Ci[i], negG)
		phi.F[bitlength+i][2*bitlength+i] = *p.H
		phi.F[bitlength+i][2*bitlength+i].Neg()
		phi.X[bitlength+i].SetIdentity()
	}
	phi.F[2*bitlength][0] = *p.G

	two := &bls12381.Scalar{}
	two.SetUint64(2)
	for i := 1; i < bitlength; i++ {
		phi.F[2*bitlength][i].ScalarMult(two, &phi.F[2*bitlength][i-1])
	}
	phi.F[2*bitlength][3*bitlength] = *p.H
	phi.X[2*bitlength] = *comm
	return linear.Verify(phi, pi.Pi)
}
