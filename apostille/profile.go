package apostille

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
)

// Protocol02 identifies Core 0.2: the 0.1 artifacts and algorithm with exact
// identifier grammar, strict Ed25519 keys and signatures, and no mixing of
// versions inside one bundle. See docs/apostille/spec/core-0.2.md.
const Protocol02 = "https://ifandonlyif.io/apostille/spec/0.2"

// profile holds everything that differs between protocol versions. Verification
// and signing select one by protocol string and never branch on the version
// themselves, so a later version is one more entry in profiles. The decoded key
// and signature sizes fix the exact encoded lengths; nothing else in the
// version-dependent paths assumes an algorithm's sizes.
type profile struct {
	protocol string
	// domain closes the signature domain "iff-apostille/<kind>/<domain>\n".
	domain string
	// algorithm is the exact signature.algorithm value an envelope must carry.
	algorithm     string
	publicKeySize int
	signatureSize int
	// validIssuer decides issuer and service_audience identifiers.
	validIssuer func(string) bool
	// checkKey runs on every decoded public key an artifact carries.
	checkKey func(key []byte) error
	// verify checks one signature over the signing input of an already
	// size-checked key and signature.
	verify func(key, message, signature []byte) error
}

var errInvalidSignature = errors.New("invalid source signature")

var profile01 = &profile{
	protocol:      Protocol,
	domain:        "0.1",
	algorithm:     Algorithm,
	publicKeySize: ed25519.PublicKeySize,
	signatureSize: ed25519.SignatureSize,
	validIssuer:   ValidIssuer,
	checkKey:      func([]byte) error { return nil },
	verify: func(key, message, signature []byte) error {
		if !ed25519.Verify(ed25519.PublicKey(key), message, signature) {
			return errInvalidSignature
		}
		return nil
	},
}

var profile02 = &profile{
	protocol:      Protocol02,
	domain:        "0.2",
	algorithm:     Algorithm,
	publicKeySize: ed25519.PublicKeySize,
	signatureSize: ed25519.SignatureSize,
	validIssuer:   ValidIssuer02,
	checkKey:      CheckStrictPublicKey,
	verify:        verifyStrictSignature,
}

// profiles lists every known version, oldest first.
var profiles = []*profile{profile01, profile02}

// KnownProtocols returns every protocol identifier this implementation
// verifies and signs, oldest first.
func KnownProtocols() []string {
	out := make([]string, len(profiles))
	for i, p := range profiles {
		out[i] = p.protocol
	}
	return out
}

func profileFor(protocol string) (*profile, error) {
	for _, p := range profiles {
		if p.protocol == protocol {
			return p, nil
		}
	}
	return nil, errors.New("unsupported protocol")
}

func (p *profile) encodedPublicKeyLen() int {
	return base64.RawURLEncoding.EncodedLen(p.publicKeySize)
}

func (p *profile) encodedSignatureLen() int {
	return base64.RawURLEncoding.EncodedLen(p.signatureSize)
}

// fieldLimit bounds an encoded key or signature field before it is decoded:
// twice the decoded size, which is 64 and 128 bytes for Ed25519. The exact
// lengths are enforced by the canonical decoders below.
func (p *profile) fieldLimit(decoded int) int { return 2 * decoded }

// signingInput is UTF8("iff-apostille/" + kind + "/" + domain + "\n") || SHA256(payload).
func (p *profile) signingInput(kind string, payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return append([]byte("iff-apostille/"+kind+"/"+p.domain+"\n"), hash[:]...)
}

// decodePublicKey returns the raw key of a canonical unpadded base64url field
// of exactly the profile's size. It does not apply checkKey.
func (p *profile) decodePublicKey(value string) ([]byte, error) {
	raw, err := rawURL.DecodeString(value)
	if err != nil || len(raw) != p.publicKeySize || len(value) != p.encodedPublicKeyLen() || rawURL.EncodeToString(raw) != value {
		return nil, errors.New("invalid canonical public key")
	}
	return raw, nil
}

func (p *profile) decodeSignature(value string) ([]byte, error) {
	raw, err := rawURL.DecodeString(value)
	if err != nil || len(raw) != p.signatureSize || len(value) != p.encodedSignatureLen() || rawURL.EncodeToString(raw) != value {
		return nil, errInvalidSignature
	}
	return raw, nil
}

// acceptsProtocol applies VerifyOptions.AcceptedProtocols: nil accepts every
// known version, any other list (even an empty one) accepts only its members.
func acceptsProtocol(accepted []string, protocol string) bool {
	return accepted == nil || slices.Contains(accepted, protocol)
}
