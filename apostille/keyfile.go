package apostille

import (
	"errors"
	"strings"
)

// MaxKeyFileBytes bounds a private key file; a Core 0.3 file is about 2.9 KB.
const MaxKeyFileBytes = 4 << 10

// KeyFile is the JSON private key file the reference tools share. Its protocol
// member names the key's algorithm: the Core 0.1 identifier means Ed25519 (the
// key signs 0.1 and 0.2) and the Core 0.3 identifier means ML-DSA-65 (the key
// signs 0.3 only). The Core 0.2 identifier is not a key file protocol. Both
// seeds are 32 bytes, so the file never lets a seed be read under the other
// algorithm: the derived public key must match the stored one.
type KeyFile struct {
	Protocol  string `json:"protocol"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Seed      string `json:"seed"`
	Role      string `json:"role,omitempty"`
}

// ParseKeyFile strictly parses a private key file of at most MaxKeyFileBytes
// and returns its signer. The seed must be 43 canonical unpadded base64url
// characters, the role at most 64 bytes without CR, LF or NUL, and the public
// key and key ID derived under the file's algorithm must equal the stored ones.
func ParseKeyFile(raw []byte) (*Signer, KeyFile, error) {
	var stored KeyFile
	if len(raw) > MaxKeyFileBytes {
		return nil, KeyFile{}, errors.New("private key file is too large")
	}
	if err := StrictJSON(raw, &stored); err != nil {
		return nil, KeyFile{}, err
	}
	if !validKeyRole(stored.Role) {
		return nil, KeyFile{}, errors.New("private key role label is invalid")
	}
	var signer *Signer
	var err error
	switch stored.Protocol {
	case Protocol:
		signer, err = newSignerFromSeed(stored.Seed)
	case Protocol03:
		signer, err = NewMLDSASigner(stored.Seed)
	default:
		return nil, KeyFile{}, errors.New("private key uses an unsupported protocol")
	}
	if err != nil {
		return nil, KeyFile{}, err
	}
	if signer.KeyID() != stored.KeyID || signer.PublicKey() != stored.PublicKey {
		return nil, KeyFile{}, errors.New("private key metadata does not match its seed")
	}
	return signer, stored, nil
}

// GenerateMLDSAKeyFile returns a Core 0.3 key file for a fresh ML-DSA-65 key.
func GenerateMLDSAKeyFile(role string) (KeyFile, error) {
	if !validKeyRole(role) {
		return KeyFile{}, errors.New("role must be a label of at most 64 bytes without CR, LF or NUL")
	}
	seed, _, err := GenerateMLDSAKey()
	if err != nil {
		return KeyFile{}, err
	}
	signer, err := NewMLDSASigner(seed)
	if err != nil {
		return KeyFile{}, err
	}
	return KeyFile{Protocol: Protocol03, KeyID: signer.KeyID(), PublicKey: signer.PublicKey(), Seed: seed, Role: role}, nil
}

func validKeyRole(role string) bool {
	return len(role) <= 64 && !strings.ContainsAny(role, "\r\n\x00")
}

// newSignerFromSeed is NewSigner restricted to a canonical 32-byte seed.
func newSignerFromSeed(seed string) (*Signer, error) {
	raw, err := rawURL.DecodeString(seed)
	if err != nil || len(seed) != seedChars || len(raw) != 32 || rawURL.EncodeToString(raw) != seed {
		return nil, errors.New("Ed25519 seed must be 43 canonical base64url characters")
	}
	return NewSigner(seed)
}
