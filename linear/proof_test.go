package linear

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
)

func TestSimpleSchnorr(t *testing.T) {
	g := bls12381.G1Generator()
	x := &bls12381.Scalar{}
	x.Random(rand.Reader)
	a := &bls12381.G1{}
	a.ScalarMult(x, g)

	phi := &Statement{}
	phi.X = make([]bls12381.G1, 1)
	phi.X[0] = *a

	phi.F = make([][]bls12381.G1, 1)
	phi.F[0] = make([]bls12381.G1, 1)

	phi.F[0][0] = *g

	w := &Witness{}
	w.W = make([]bls12381.Scalar, 1)
	w.W[0].Set(x)

	pi, err := Prove(phi, w)
	if err != nil {
		t.Errorf("failure to prove: %s", err)
	}

	if !Verify(phi, pi) {
		t.Errorf("proof didn't verify")
	}
}

func TestDLOG(t *testing.T) {
	g0 := &bls12381.G1{}
	g1 := &bls12381.G1{}
	g0.Hash([]byte("g0"), []byte("test"))
	g1.Hash([]byte("g1"), []byte("test"))
	x := &bls12381.Scalar{}
	x.Random(rand.Reader)
	b0 := &bls12381.G1{}
	b1 := &bls12381.G1{}

	b0.ScalarMult(x, g0)
	b1.ScalarMult(x, g1)

	phi := &Statement{}
	phi.X = make([]bls12381.G1, 2)
	phi.X[0] = *b0
	phi.X[1] = *b1

	phi.F = make([][]bls12381.G1, 2)
	phi.F[0] = make([]bls12381.G1, 1)
	phi.F[1] = make([]bls12381.G1, 1)

	phi.F[0][0] = *g0
	phi.F[1][0] = *g1
	w := &Witness{}
	w.W = make([]bls12381.Scalar, 1)
	w.W[0].Set(x)

	pi, err := Prove(phi, w)
	if err != nil {
		t.Errorf("failure to prove: %s", err)
	}

	if !Verify(phi, pi) {
		t.Errorf("proof didn't verify")
	}

	phi.F[0][0] = *g1
	if Verify(phi, pi) {
		t.Errorf("proof verified and shouldn't")
	}
}

func Test2CommitEq(t *testing.T) {
	g0 := &bls12381.G1{}
	h0 := &bls12381.G1{}
	g1 := &bls12381.G1{}
	h1 := &bls12381.G1{}
	g0.Hash([]byte("g0"), nil)
	h0.Hash([]byte("h0"), nil)
	g1.Hash([]byte("g1"), nil)
	h1.Hash([]byte("h1"), nil)

	x := &bls12381.Scalar{}
	r0 := &bls12381.Scalar{}
	r1 := &bls12381.Scalar{}
	x.Random(rand.Reader)
	r0.Random(rand.Reader)
	r1.Random(rand.Reader)

	tmp := &bls12381.G1{}
	c0 := &bls12381.G1{}
	c1 := &bls12381.G1{}

	c0.ScalarMult(x, g0)
	tmp.ScalarMult(r0, h0)
	c0.Add(c0, tmp)

	c1.ScalarMult(x, g1)
	tmp.ScalarMult(r1, h1)
	c1.Add(c1, tmp)

	phi := &Statement{}
	phi.F = make([][]bls12381.G1, 2)
	for i := 0; i < 2; i++ {
		phi.F[i] = make([]bls12381.G1, 3)
		for j := 0; j < len(phi.F[i]); j++ {
			phi.F[i][j].SetIdentity()
		}
	}

	phi.X = make([]bls12381.G1, 2)
	phi.X[0] = *c0
	phi.X[1] = *c1

	w := &Witness{}
	w.W = make([]bls12381.Scalar, 3)
	w.W[0].Set(x)
	w.W[1].Set(r0)
	w.W[2].Set(r1)

	phi.F[0][0] = *g0
	phi.F[0][1] = *h0
	phi.F[1][0] = *g1
	phi.F[1][2] = *h1

	pi, err := Prove(phi, w)
	if err != nil {
		t.Errorf("failure to prove: %s", err)
	}

	if !Verify(phi, pi) {
		t.Errorf("proof didn't verify")
	}

}
