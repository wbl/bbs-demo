// Package linear implements straightline extractable proofs of knowledge of discrete logs.
package linear

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/blake2b"
)

type Statement struct {
	F [][]bls12381.G1
	X []bls12381.G1
}

type Witness struct {
	W []bls12381.Scalar
}

type Proof struct {
	R []bls12381.G1
	S []bls12381.Scalar
}

func IsWellFormed(s *Statement) bool {
	rowlen := 0
	for rownum, row := range s.F {
		if rownum == 0 {
			rowlen = len(row)
		} else {
			if rowlen != len(row) {
				return false
			}
		}
	}
	if len(s.X) != len(s.F) {
		return false
	}
	return true
}

func InputDimension(s *Statement) int {
	return len(s.F[0])
}
func OutputDimension(s *Statement) int {
	return len(s.F)
}

func Prove(phi *Statement, w *Witness) (*Proof, error) {
	if !IsWellFormed(phi) {
		return nil, errors.New("badly formed statement")
	}
	r := make([]*bls12381.Scalar, InputDimension(phi))
	for i := 0; i < len(r); i++ {
		r[i] = &bls12381.Scalar{}
		r[i].Random(rand.Reader)
	}

	if len(w.W) != InputDimension(phi) {
		return nil, errors.New("Witness invalid length")
	}

	pi := &Proof{}
	pi.R = make([]bls12381.G1, OutputDimension(phi))
	for i := 0; i < len(pi.R); i++ {
		pi.R[i].SetIdentity()
	}
	t := &bls12381.G1{}
	for i, row := range phi.F {
		t.SetIdentity()
		for j := 0; j < len(row); j++ {
			t.ScalarMult(r[j], &row[j])
			pi.R[i].Add(&pi.R[i], t)
		}
	}

	c, err := hashStatementAndCommitment(phi, pi)
	if err != nil {
		return nil, fmt.Errorf("hashing: %w", err)
	}

	pi.S = make([]bls12381.Scalar, InputDimension(phi))
	cW := &bls12381.Scalar{}
	for i := 0; i < len(pi.S); i++ {
		cW.Mul(c, &w.W[i])
		pi.S[i].Add(r[i], cW)
	}
	return pi, nil
}

func Verify(phi *Statement, pi *Proof) bool {
	if !IsWellFormed(phi) {
		return false
	}
	if len(pi.R) != OutputDimension(phi) {
		return false
	}
	if len(pi.S) != InputDimension(phi) {
		return false
	}
	c, err := hashStatementAndCommitment(phi, pi)
	if err != nil {
		return false
	}
	rhs := make([]bls12381.G1, OutputDimension(phi))

	lhs := make([]bls12381.G1, OutputDimension(phi))

	t := &bls12381.G1{}
	for i, row := range phi.F {
		lhs[i].SetIdentity()
		for j := 0; j < len(row); j++ {
			t.ScalarMult(&pi.S[j], &row[j])
			lhs[i].Add(&lhs[i], t)
		}
	}

	for i := 0; i < len(rhs); i++ {
		rhs[i].ScalarMult(c, &phi.X[i])
		rhs[i].Add(&rhs[i], &pi.R[i])
	}

	for i := 0; i < len(rhs); i++ {
		if !rhs[i].IsEqual(&lhs[i]) {
			return false
		}
	}
	return true
}

func hashStatementAndCommitment(phi *Statement, pi *Proof) (*bls12381.Scalar, error) {
	hash, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	if err != nil {
		return nil, errors.New("failure to initialize hash")
	}
	_, err = fmt.Fprintf(hash, "Input: %d Output: %d", InputDimension(phi), OutputDimension(phi))
	if err != nil {
		return nil, errors.New("hashing issue")
	}
	for _, row := range phi.F {
		for _, elt := range row {
			hash.Write(elt.Bytes())
		}
	}
	for _, elt := range phi.X {
		hash.Write(elt.Bytes())
	}
	for _, elt := range pi.R {
		hash.Write(elt.Bytes())
	}

	c := &bls12381.Scalar{}
	c.Random(hash)
	return c, nil
}
