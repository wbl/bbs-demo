package token

import (
	"crypto/rand"
	"errors"
	"fmt"

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
	kRangeProof *bound.Proof
	pi          *linear.Proof
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
	c         *bls12381.G1 // s*g1+m*h0+x*h1
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

func computeCommFromToken(t *Token) *bls12381.G1 {
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

	return comm
}

func verifyToken(pk *PublicKey, t *Token) error {
	comm := computeCommFromToken(t)
	keyadj := &bls12381.G2{}
	keyadj.ScalarMult(t.e, bls12381.G2Generator())
	keyadj.Add(keyadj, pk.w)

	if bls12381.ProdPairFrac([]*bls12381.G1{t.a, comm}, []*bls12381.G2{keyadj, bls12381.G2Generator()}, []int{1, -1}).IsIdentity() {
		return nil
	}
	return errors.New("verification failed")
}

func ShowTokenWithLimit(t *Token, origin []byte, bitlimit int, k int) (*Showing, error) {
	// cdl translation:
	// our g0 = their g1
	// our g1 = their h0
	// our h0 =  their h1
	// our h1 = their h2
	if k < 0 {
		return nil, errors.New("incorrect parameters")
	}
	show := &Showing{}
	params := systemParams()
	show.attribute = append(show.attribute, t.attribute...)
	r1 := &bls12381.Scalar{}
	err := r1.Random(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("showtoken r1: %w", err)
	}
	show.aprime = &bls12381.G1{}
	show.aprime.ScalarMult(r1, t.a)
	comm := computeCommFromToken(t)

	tmp := &bls12381.G1{}
	tmp.ScalarMult(t.e, t.a)
	tmp.Neg()
	tmp.Add(tmp, comm)
	show.abar = &bls12381.G1{}
	show.abar.ScalarMult(r1, tmp)

	r2 := &bls12381.Scalar{}
	err = r2.Random(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("showtoken r2: %w", err)
	}
	show.d = &bls12381.G1{}
	show.d.ScalarMult(r1, comm)
	negR2 := &bls12381.Scalar{}
	negR2.Set(r2)
	negR2.Neg()
	tmp.ScalarMult(negR2, params.g1)
	show.d.Add(show.d, tmp)

	oriG := &bls12381.G1{}
	oriG.Hash(origin, []byte("origin generator"))

	kOpen := &bls12381.Scalar{}
	kOpen.Random(rand.Reader)
	kSc := &bls12381.Scalar{}
	kSc.SetUint64(uint64(k))
	show.kComm = &bls12381.G1{}
	show.kComm.ScalarMult(kSc, params.h0)
	tmp.ScalarMult(kOpen, params.h1)
	show.kComm.Add(show.kComm, tmp)

	oriGexp := &bls12381.Scalar{}
	oriGexp.Add(kSc, t.key)
	oriGexp.Inv(oriGexp)
	show.ticket = &bls12381.G1{}
	show.ticket.ScalarMult(oriGexp, oriG)

	show.kRangeProof, err = bound.Prove(show.kComm, &bound.Params{G: params.h0, H: params.h1}, &bound.Opening{K: kSc, R: kOpen}, bitlimit)
	if err != nil {
		return nil, fmt.Errorf("error in proving bound on k: %w", err)
	}
	// At this point we're here for the big event
	phi := linear.NewStatement(7, 4)
	w := &linear.Witness{}
	w.W = make([]bls12381.Scalar, 7)

	r3 := &bls12381.Scalar{}
	r3.Inv(r1)
	sprime := &bls12381.Scalar{}
	sprime.Mul(r2, r3)
	sprime.Neg()
	sprime.Add(t.s, sprime)

	w.W[0] = *t.e
	w.W[0].Neg()
	w.W[1] = *r2
	w.W[2] = *r3
	w.W[3] = *sprime
	w.W[3].Neg()
	w.W[4] = *t.key
	w.W[5] = *kSc
	w.W[6] = *kOpen

	phi.F[0][0] = *show.aprime
	phi.F[0][1] = *params.g1
	phi.X[0] = *show.d
	phi.X[0].Neg()
	phi.X[0].Add(&phi.X[0], show.abar)

	phi.F[1][2] = *show.d
	phi.F[1][3] = *params.g1
	phi.F[1][4] = *params.h0
	phi.F[1][4].Neg()

	demo := str2Scalar(show.attribute)
	phi.X[1].ScalarMult(demo, params.h1)
	phi.X[1].Add(&phi.X[1], params.g0)

	phi.F[2][5] = *params.h0
	phi.F[2][6] = *params.h1
	phi.X[2] = *show.kComm

	phi.F[3][4] = *show.ticket
	phi.F[3][5] = *show.ticket
	phi.X[3] = *oriG

	err = linear.Satisfied(phi, w)
	if err != nil {
		return nil, fmt.Errorf("witness failure: %w", err)
	}
	show.pi, err = linear.Prove(phi, w)
	if err != nil {
		return nil, fmt.Errorf("proving failure: %w", err)
	}
	return show, nil
}

func VerifyShowing(s *Showing, pk *PublicKey, bitlimit int) error {
	return errors.New("unimplemented")
}

func GetTicket(s *Showing) []byte {
	return s.ticket.Bytes()
}

func GetAttribute(s *Showing) []byte {
	return s.attribute
}
