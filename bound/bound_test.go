package bound

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
)

func TestBoundSmall(t *testing.T) {
	params := &Params{}
	params.G = &bls12381.G1{}
	params.H = &bls12381.G1{}

	params.G.Hash([]byte("G1"), []byte("test"))
	params.H.Hash([]byte("H1"), []byte("test"))

	open := &Opening{}
	open.R = &bls12381.Scalar{}
	open.R.Random(rand.Reader)

	open.K = &bls12381.Scalar{}
	open.K.SetUint64(5)

	comm := &bls12381.G1{}
	comm.ScalarMult(open.K, params.G)
	tmp := &bls12381.G1{}
	tmp.ScalarMult(open.R, params.H)
	comm.Add(tmp, comm)

	proof, err := Prove(comm, params, open, 3)
	if err != nil {
		t.Fatalf("error in proving: %s", err)
	}
	if !Verify(comm, params, 3, proof) {
		t.Fatalf("error in verifying")
	}
}
