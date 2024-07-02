package token

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/blake2b"

	"github.com/wbl/bbs-demo/bound"
	"github.com/wbl/bbs-demo/linear"
)

type Showing struct {
	aprime *bls12381.G1
	abar   *bls12381.G1
	d      *bls12381.G1

	attribute   []byte
	ticket      *bls12381.G1
	kComm       *bls12381.G1
	kRangeProof bound.Proof
	pi          linear.Proof
}

// A is a signature (g0+s*g1+x*h0+m*h1)^1/(x+e). For now direct sign, but later will make it work indirectly.
type Token struct {
	a         *bls12381.G1
	e         *bls12381.Scalar
	s         *bls12381.Scalar
	key       *bls12381.Scalar
	attribute []byte
}

// SignRequest, PreToken, SignResponse are for blind signing
type SignRequest struct {
	c         *bls12381.G1 // s*g0+m*h0+x*h1
	attribute []byte
	pi        linear.Proof
}

type PreToken struct {
	s         *bls12381.Scalar
	x         *bls12381.Scalar
	attribute []byte
}

// No proof required because we can verify A, (s+sprime), e is signature of m, h2
type SignResponse struct {
	a      *bls12381.G1
	sprime *bls12381.Scalar
	e      *bls12381.Scalar
}

type PublicKey struct {
	w *bls12381.G2
}
type SigningKey struct {
	x *bls12381.Scalar
}
type params struct {
	g0 *bls12381.G1
	g1 *bls12381.G1
	h0 *bls12381.G1
	h1 *bls12381.G1
}

// For now just ignore blind signing?

func Keygen() (pk *PublicKey, sk *SigningKey) {
	pk = &PublicKey{}
	pk.w = &bls12381.G2{}
	sk = &SigningKey{}
	sk.x = &bls12381.Scalar{}
	sk.x.Random(rand.Reader)
	pk.w.ScalarMult(sk.x, bls12381.G2Generator())
	return
}

// Just for demo completeness now
func systemParams() *params {
	p := &params{}
	p.g0 = &bls12381.G1{}
	p.g1 = &bls12381.G1{}
	p.h0 = &bls12381.G1{}
	p.h1 = &bls12381.G1{}
	p.g0.Hash([]byte("g0"), []byte("demo"))
	p.g1.Hash([]byte("g1"), []byte("demo"))
	p.h0.Hash([]byte("h0"), []byte("demo"))
	p.h1.Hash([]byte("h1"), []byte("demo"))
	return p
}

func str2Scalar(in []byte) *bls12381.Scalar {
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	ret := &bls12381.Scalar{}
	xof.Write(in)
	ret.Random(xof)
	return ret
}

func MakeToken(sk *SigningKey, attribute []byte) (*Token, error) {
	t := &Token{}
	t.key = &bls12381.Scalar{}
	t.key.Random(rand.Reader)
	t.attribute = append(t.attribute, attribute...)

	params := systemParams()
	U := &bls12381.G1{}
	tmp := &bls12381.G1{}

	attrSclr := str2Scalar(attribute)
	U.ScalarMult(t.key, params.h0)
	tmp.ScalarMult(attrSclr, params.h1)
	U.Add(U, tmp)
	t.s = &bls12381.Scalar{}
	t.s.Random(rand.Reader)
	tmp.ScalarMult(t.s, params.g1)
	U.Add(U, tmp)
	U.Add(U, params.g0)

	t.e = &bls12381.Scalar{}
	t.e.Random(rand.Reader)

	exp := &bls12381.Scalar{}
	exp.Add(t.e, sk.x)
	exp.Inv(exp)

	t.a = &bls12381.G1{}
	t.a.ScalarMult(exp, U)

	return t, nil
}

func verifyToken(pk *PublicKey, t *Token) error {
	comm := &bls12381.G1{}
	tmp := &bls12381.G1{}
	params := systemParams()
	comm.ScalarMult(t.key, params.h0)
	attrSclr := str2Scalar(t.attribute)
	tmp.ScalarMult(attrSclr, params.h1)
	comm.Add(tmp, comm)
	tmp.ScalarMult(t.s, params.g1)
	comm.Add(tmp, comm)
	comm.Add(comm, params.g0)

	keyadj := &bls12381.G2{}
	keyadj.ScalarMult(t.e, bls12381.G2Generator())
	keyadj.Add(keyadj, pk.w)

	if bls12381.ProdPairFrac([]*bls12381.G1{t.a, comm}, []*bls12381.G2{keyadj, bls12381.G2Generator()}, []int{1, -1}).IsIdentity() {
		return nil
	}
	return errors.New("verification failed")
}

func ShowTokenWithLimit(t *Token, origin []byte) (*Showing, error) {

	return nil, errors.New("unimplemented")
}

func VerifyShowing(s *Showing, pk *PublicKey) error {
	return errors.New("unimplemented")
}

func GetTicket(s *Showing) []byte {
	return s.ticket.Bytes()
}

func GetAttribute(s *Showing) []byte {
	return s.attribute
}
