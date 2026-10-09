package apostille

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

// The eight small-order points, as listed in core-0.2.md.
var smallOrderHex = []string{
	"0100000000000000000000000000000000000000000000000000000000000000", // identity
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
}

// mixedOrderHex is the base point plus the order-2 point.
const mixedOrderHex = "9599999999999999999999999999999999999999999999999999999999999999"

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPoint(t testing.TB, encoding []byte) *edwards25519.Point {
	t.Helper()
	p, err := new(edwards25519.Point).SetBytes(encoding)
	if err != nil {
		t.Fatalf("point %x does not decode: %v", encoding, err)
	}
	return p
}

// TestCurveLibraryAssumptions re-verifies, against the pinned
// filippo.io/edwards25519 release, the library behaviour Rule B depends on
// (docs/apostille/proposals/core-0.2-implementation-plan.md gotcha 3).
func TestCurveLibraryAssumptions(t *testing.T) {
	// L cannot be loaded as a scalar: it either fails or reduces to zero.
	if _, err := new(edwards25519.Scalar).SetCanonicalBytes(ed25519OrderLE[:]); err == nil {
		t.Fatal("SetCanonicalBytes accepted L")
	}
	wide := make([]byte, 64)
	copy(wide, ed25519OrderLE[:])
	zero, err := new(edwards25519.Scalar).SetUniformBytes(wide)
	if err != nil {
		t.Fatal(err)
	}
	if zero.Equal(new(edwards25519.Scalar)) != 1 {
		t.Fatal("SetUniformBytes did not reduce L to zero")
	}
	// ... so [L]P computed that way is the identity for every point, and would
	// pass the mixed-order example.
	mixed := mustPoint(t, mustHex(t, mixedOrderHex))
	if new(edwards25519.Point).ScalarMult(zero, mixed).Equal(edwards25519.NewIdentityPoint()) != 1 {
		t.Fatal("[0]P is not the identity")
	}

	// [L-1]P + P accepts the base point and rejects the mixed-order example
	// and every small-order point.
	torsionFree := func(p *edwards25519.Point) bool {
		q := new(edwards25519.Point).ScalarMult(orderMinusOne, p)
		return q.Add(q, p).Equal(edwards25519.NewIdentityPoint()) == 1
	}
	if !torsionFree(edwards25519.NewGeneratorPoint()) {
		t.Fatal("base point rejected")
	}
	if torsionFree(mixed) {
		t.Fatal("mixed-order point accepted")
	}
	for _, h := range smallOrderHex {
		p := mustPoint(t, mustHex(t, h))
		// The identity is trivially torsion-free; strictPoint rejects it separately.
		if h != smallOrderHex[0] && torsionFree(p) {
			t.Fatalf("small-order point %s accepted", h)
		}
	}

	// Point.SetBytes accepts non-canonical encodings, so strictPoint re-encodes.
	for _, h := range []string{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p, an alias of y = 0
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p+1, an alias of the identity
		"0100000000000000000000000000000000000000000000000000000000000080", // identity with the sign bit set
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 2 with the sign bit set
	} {
		enc := mustHex(t, h)
		p, err := new(edwards25519.Point).SetBytes(enc)
		t.Logf("SetBytes(%s): err=%v", h, err)
		if err == nil && bytes.Equal(p.Bytes(), enc) {
			t.Fatalf("%s: library re-encodes a non-canonical encoding to itself", h)
		}
		if _, err := strictPoint(enc); err == nil {
			t.Fatalf("%s: strictPoint accepted a non-canonical encoding", h)
		}
	}
}

func TestOrderConstants(t *testing.T) {
	// L = 2^252 + 27742317777372353535851937790883648493
	want := new(big.Int).Lsh(big.NewInt(1), 252)
	tail, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	want.Add(want, tail)
	var be [32]byte
	for i := range be {
		be[i] = ed25519OrderLE[31-i]
	}
	if new(big.Int).SetBytes(be[:]).Cmp(want) != 0 {
		t.Fatal("ed25519OrderLE is not L")
	}
	if want.String() != ed25519GroupOrder {
		t.Fatal("ed25519GroupOrder is not L")
	}
}

func TestStrictPublicKey(t *testing.T) {
	honest := testSigner(t, 1)
	if err := CheckStrictPublicKey(honest.key[32:]); err != nil {
		t.Fatalf("honest key rejected: %v", err)
	}
	if err := CheckStrictPublicKey(mustHex(t, "5866666666666666666666666666666666666666666666666666666666666666")); err != nil {
		t.Fatalf("base point rejected: %v", err)
	}
	for _, h := range smallOrderHex {
		if CheckStrictPublicKey(mustHex(t, h)) == nil {
			t.Errorf("small-order key %s accepted", h)
		}
	}
	if err := CheckStrictPublicKey(mustHex(t, mixedOrderHex)); err == nil || !strings.Contains(err.Error(), "prime-order subgroup") {
		t.Errorf("mixed-order key: %v", err)
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if CheckStrictPublicKey(bad) == nil {
			t.Errorf("%d-byte key accepted", len(bad))
		}
	}
	// y = 2 does not lie on the curve.
	notOnCurve := make([]byte, 32)
	notOnCurve[0] = 2
	if err := CheckStrictPublicKey(notOnCurve); err == nil {
		t.Error("an encoding that is not on the curve was accepted")
	}
}

func TestStrictSignature(t *testing.T) {
	s := testSigner(t, 4)
	pub := s.key[32:]
	msg := []byte("strict")
	sig := ed25519.Sign(s.key, msg)
	if !VerifyStrict(pub, msg, sig) {
		t.Fatal("honest signature rejected")
	}
	if VerifyStrict(pub, []byte("other"), sig) {
		t.Fatal("signature accepted for another message")
	}
	flipped := append([]byte{}, sig...)
	flipped[0] ^= 1
	if VerifyStrict(pub, msg, flipped) {
		t.Fatal("corrupted signature accepted")
	}
	if VerifyStrict(pub[:31], msg, sig) || VerifyStrict(pub, msg, sig[:63]) {
		t.Fatal("wrong sizes accepted")
	}

	// S = L and S + L are rejected by step 1 even though S + L satisfies the
	// group equation.
	order := ed25519OrderLE[:]
	atOrder := append(append([]byte{}, sig[:32]...), order...)
	if err := verifyStrictSignature(pub, msg, atOrder); err == nil || !strings.Contains(err.Error(), "below the group order") {
		t.Fatalf("S = L: %v", err)
	}
	sBig := new(big.Int).SetBytes(reverseBytes(sig[32:]))
	lBig, _ := new(big.Int).SetString(ed25519GroupOrder, 10)
	plusL := append(append([]byte{}, sig[:32]...), reverseBytes(sBig.Add(sBig, lBig).FillBytes(make([]byte, 32)))...)
	if err := verifyStrictSignature(pub, msg, plusL); err == nil || !strings.Contains(err.Error(), "below the group order") {
		t.Fatalf("S + L: %v", err)
	}
	// S = L - 1 is in range and fails only the equation.
	belowOrder := append([]byte{}, atOrder...)
	belowOrder[32]--
	if err := verifyStrictSignature(pub, msg, belowOrder); err == nil || !strings.Contains(err.Error(), "equation") {
		t.Fatalf("S = L-1: %v", err)
	}
}

// clampedScalar is the secret scalar a of an Ed25519 seed, reduced modulo L.
func clampedScalar(t testing.TB, seed []byte) *edwards25519.Scalar {
	t.Helper()
	h := sha512.Sum512(seed)
	a, err := new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// challenge is k = SHA-512(R || A || M) mod L.
func challenge(t testing.TB, r, a, m []byte) *edwards25519.Scalar {
	t.Helper()
	h := sha512.New()
	h.Write(r)
	h.Write(a)
	h.Write(m)
	k, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestIdentityRHonestKey pins gotcha 11: on an honest key the signature
// R = identity, S = k*a mod L is accepted by crypto/ed25519 and by a verifier
// that checks only the key, and rejected by exactly the identity clause on R.
func TestIdentityRHonestKey(t *testing.T) {
	s := testSigner(t, 4)
	pub := s.key[32:]
	msg := []byte("identity R")
	identity := mustHex(t, smallOrderHex[0])
	a := clampedScalar(t, s.key.Seed())
	k := challenge(t, identity, pub, msg)
	sig := append(append([]byte{}, identity...), new(edwards25519.Scalar).Multiply(k, a).Bytes()...)
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatal("crypto/ed25519 rejected the identity-R signature")
	}
	if err := CheckStrictPublicKey(pub); err != nil {
		t.Fatal(err)
	}
	if err := verifyStrictSignature(pub, msg, sig); err == nil || !strings.Contains(err.Error(), "R: point is the identity") {
		t.Fatalf("identity R: %v", err)
	}
}
