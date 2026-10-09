package apostille

import (
	"crypto/mldsa"
	"errors"
	"strings"
)

// ML-DSA-65 signers and the Core 0.3 login challenge. The seed is the 32-byte
// FIPS 204 seed; Ed25519 seeds are the same length, so the algorithm is always
// chosen by the constructor, never inferred from the bytes.

// seedChars is the length of an unpadded base64url 32-byte seed.
const seedChars = 43

// LoginPrefix03 starts every Core 0.3 login challenge message.
const LoginPrefix03 = "iff-apostille/login/0.3\n"

// NewMLDSASigner builds an ML-DSA-65 signer from a seed of exactly 43
// canonical unpadded base64url characters (32 bytes).
func NewMLDSASigner(seed string) (*Signer, error) {
	raw, err := rawURL.DecodeString(seed)
	if err != nil || len(seed) != seedChars || len(raw) != mldsa.PrivateKeySize || rawURL.EncodeToString(raw) != seed {
		return nil, errors.New("ML-DSA-65 seed must be 43 canonical base64url characters")
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), raw)
	if err != nil {
		return nil, errors.New("invalid ML-DSA-65 seed")
	}
	return &Signer{ml: key}, nil
}

// GenerateMLDSAKey returns a fresh ML-DSA-65 seed and its public key, both
// canonical unpadded base64url.
func GenerateMLDSAKey() (seed string, publicKey string, err error) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return "", "", err
	}
	return rawURL.EncodeToString(key.Bytes()), rawURL.EncodeToString(key.PublicKey().Bytes()), nil
}

// SignChallenge03 signs a Core 0.3 login challenge (hedged ML-DSA-65, empty
// context). The message must start with LoginPrefix03; an Ed25519 signer is
// refused, and SignChallenge refuses an ML-DSA-65 signer.
func (s *Signer) SignChallenge03(message string) (string, error) {
	if !s.Enabled() {
		return "", errors.New("signing key required")
	}
	if s.Algorithm() != Algorithm03 {
		return "", errors.New("the 0.3 login challenge needs an ML-DSA-65 key")
	}
	if !strings.HasPrefix(message, LoginPrefix03) || len(message) > 4096 {
		return "", errors.New("invalid login challenge")
	}
	signature, err := s.signMessage([]byte(message))
	if err != nil {
		return "", err
	}
	return rawURL.EncodeToString(signature), nil
}

// VerifyChallenge03 reports whether signature is a canonical ML-DSA-65
// signature by publicKey over message, which must carry LoginPrefix03.
func VerifyChallenge03(publicKey, message, signature string) bool {
	if len(message) > 4096 || !strings.HasPrefix(message, LoginPrefix03) {
		return false
	}
	key, err := profile03.decodePublicKey(publicKey)
	if err != nil {
		return false
	}
	sig, err := profile03.decodeSignature(signature)
	return err == nil && profile03.verify(key, []byte(message), sig) == nil
}
