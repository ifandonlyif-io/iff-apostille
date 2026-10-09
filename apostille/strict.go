package apostille

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math/big"

	"filippo.io/edwards25519"
)

// Strict Ed25519 verification, Core 0.2 "Strict Ed25519 verification". The
// curve library is used for point decoding and arithmetic only; its own
// scalar type cannot hold L, so subgroup membership is tested as [L-1]P + P.

// ed25519OrderLE is L as 32 little-endian bytes, the order of the base point
// (RFC 8032 section 5.1): 2^252 + 27742317777372353535851937790883648493.
var ed25519OrderLE = func() [32]byte {
	order, ok := new(big.Int).SetString(ed25519GroupOrder, 10)
	if !ok {
		panic("invalid Ed25519 group order constant")
	}
	var le [32]byte
	order.FillBytes(le[:])
	for i, j := 0, len(le)-1; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}
	return le
}()

// orderMinusOne is the canonical scalar L-1. [L-1]P + P is [L]P without
// loading L itself, which a reducing scalar type turns into zero.
var orderMinusOne = func() *edwards25519.Scalar {
	le := ed25519OrderLE
	le[0]-- // the lowest byte of L is 0xed, so no borrow
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(le[:])
	if err != nil {
		panic("L-1 is not a canonical scalar")
	}
	return s
}()

// ed25519GroupOrder is L in decimal.
const ed25519GroupOrder = "7237005577332262213973186563042994240857116359379907606001950938285454250989"

// strictPoint decodes a 32-byte point encoding and applies steps 2 and 3: the
// point decodes, re-encodes to the same bytes, is not the identity and lies in
// the prime-order subgroup. The errors carry no input bytes.
func strictPoint(encoding []byte) (*edwards25519.Point, error) {
	if len(encoding) != 32 {
		return nil, errors.New("point encoding must be 32 bytes")
	}
	point, err := new(edwards25519.Point).SetBytes(encoding)
	if err != nil {
		return nil, errors.New("point does not decode")
	}
	// SetBytes accepts y >= p and a set sign bit on x = 0 by design.
	if !bytes.Equal(point.Bytes(), encoding) {
		return nil, errors.New("point encoding is not canonical")
	}
	identity := edwards25519.NewIdentityPoint()
	if point.Equal(identity) == 1 {
		return nil, errors.New("point is the identity")
	}
	check := new(edwards25519.Point).ScalarMult(orderMinusOne, point)
	if check.Add(check, point).Equal(identity) != 1 {
		return nil, errors.New("point is not in the prime-order subgroup")
	}
	return point, nil
}

// CheckStrictPublicKey applies steps 2 and 3 of strict Ed25519 verification to
// a raw 32-byte public key. A key generated and used as RFC 8032 describes
// always passes. A service can use it as its own access policy for login or
// registration keys.
func CheckStrictPublicKey(key []byte) error {
	if _, err := strictPoint(key); err != nil {
		return errors.New("invalid public key: " + err.Error())
	}
	return nil
}

// verifyStrictSignature performs steps 1 to 4 in order and reports the first
// failure. Once A and R are torsion-free, the cofactorless equation of
// crypto/ed25519 gives the same verdict as the cofactored one.
func verifyStrictSignature(key, message, signature []byte) error {
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid source signature: wrong key or signature size")
	}
	// Step 1: S < L, comparing little-endian bytes from the most significant.
	for i := 31; ; i-- {
		s, l := signature[32+i], ed25519OrderLE[i]
		if s != l {
			if s > l {
				return errors.New("invalid source signature: S is not below the group order")
			}
			break
		}
		if i == 0 {
			return errors.New("invalid source signature: S is not below the group order")
		}
	}
	if _, err := strictPoint(key); err != nil {
		return errors.New("invalid source signature: public key: " + err.Error())
	}
	if _, err := strictPoint(signature[:32]); err != nil {
		return errors.New("invalid source signature: R: " + err.Error())
	}
	if !ed25519.Verify(ed25519.PublicKey(key), message, signature) {
		return errors.New("invalid source signature: equation does not hold")
	}
	return nil
}

// VerifyStrict reports whether signature is a valid Core 0.2 strict Ed25519
// signature of message under the raw 32-byte key.
func VerifyStrict(key, message, signature []byte) bool {
	return verifyStrictSignature(key, message, signature) == nil
}
