package apostille

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func keyFileJSON(t *testing.T, k KeyFile) []byte {
	t.Helper()
	raw, err := json.Marshal(k)
	require.NoError(t, err)
	return raw
}

// fixtureKeyFile is the key file of the public fixture seed n for protocol's
// algorithm.
func fixtureKeyFile(t *testing.T, protocol string, n byte) KeyFile {
	t.Helper()
	s := testSignerFor(t, protocol, n)
	return KeyFile{Protocol: protocol, KeyID: s.KeyID(), PublicKey: s.PublicKey(), Seed: rawURL.EncodeToString(bytes.Repeat([]byte{n}, 32))}
}

func TestParseKeyFileAccepts(t *testing.T) {
	ed := fixtureKeyFile(t, Protocol, 1)
	ed.Role = "admin"
	s, k, err := ParseKeyFile(keyFileJSON(t, ed))
	require.NoError(t, err)
	require.Equal(t, ed, k)
	require.Equal(t, Algorithm, s.Algorithm())
	// An Ed25519 key signs 0.1 and 0.2, never 0.3.
	for _, protocol := range []string{Protocol, Protocol02} {
		require.True(t, signsStatement(t, s, protocol), protocol)
	}
	require.False(t, signsStatement(t, s, Protocol03))

	ml := fixtureKeyFile(t, Protocol03, 1)
	s, k, err = ParseKeyFile(keyFileJSON(t, ml))
	require.NoError(t, err)
	require.Equal(t, ml, k)
	require.Equal(t, Algorithm03, s.Algorithm())
	require.Equal(t, ml.KeyID, s.KeyID())
	// An ML-DSA-65 key signs 0.3 only.
	require.True(t, signsStatement(t, s, Protocol03))
	require.False(t, signsStatement(t, s, Protocol))
	require.False(t, signsStatement(t, s, Protocol02))

	// A role of exactly 64 bytes is fine.
	ed.Role = strings.Repeat("r", 64)
	_, _, err = ParseKeyFile(keyFileJSON(t, ed))
	require.NoError(t, err)
}

func signsStatement(t *testing.T, s *Signer, protocol string) bool {
	t.Helper()
	st := Statement{Header: headerFor(protocol, KindStatement, KeyIdentity(s.KeyID()), s, fixedNow), AgentID: agentID, ArtifactSHA256: Hash(nil), ArtifactSize: "0", ArtifactMediaType: "application/octet-stream", Nonce: nonceID}
	_, err := s.SignFor(protocol, KindStatement, st)
	return err == nil
}

func TestGenerateMLDSAKeyFile(t *testing.T) {
	k, err := GenerateMLDSAKeyFile("agent")
	require.NoError(t, err)
	require.Equal(t, Protocol03, k.Protocol)
	require.Equal(t, "agent", k.Role)
	require.Len(t, k.Seed, 43)
	require.Len(t, k.PublicKey, 2603)
	raw := keyFileJSON(t, k)
	require.Less(t, len(raw), MaxKeyFileBytes)
	require.Greater(t, len(raw), 2700, "a 0.3 file is about 2.9 KB")
	s, back, err := ParseKeyFile(raw)
	require.NoError(t, err)
	require.Equal(t, k, back)
	require.True(t, signsStatement(t, s, Protocol03))

	other, err := GenerateMLDSAKeyFile("")
	require.NoError(t, err)
	require.NotEqual(t, k.Seed, other.Seed)
	_, err = GenerateMLDSAKeyFile(strings.Repeat("r", 65))
	require.Error(t, err)
	_, err = GenerateMLDSAKeyFile("a\nb")
	require.Error(t, err)
}

// TestKeyFileRefusesTheOtherAlgorithmsSeed covers the shared 32-byte seed: a
// seed of one algorithm placed in a file of the other, with the first
// algorithm's own metadata, is refused because the derived key differs.
func TestKeyFileRefusesTheOtherAlgorithmsSeed(t *testing.T) {
	ed := fixtureKeyFile(t, Protocol, 1)
	ml := fixtureKeyFile(t, Protocol03, 1)
	require.Equal(t, ed.Seed, ml.Seed, "the same seed text")

	// A 0.1 Ed25519 seed in a 0.3 file, with its Ed25519 metadata.
	asML := ed
	asML.Protocol = Protocol03
	_, _, err := ParseKeyFile(keyFileJSON(t, asML))
	require.ErrorContains(t, err, "does not match")

	// An ML-DSA seed in a 0.1 file, with its ML-DSA metadata.
	asEd := ml
	asEd.Protocol = Protocol
	_, _, err = ParseKeyFile(keyFileJSON(t, asEd))
	require.ErrorContains(t, err, "does not match")

	// Mixed metadata: a 0.3 file whose key ID or public key is the Ed25519 one.
	for name, mutate := range map[string]func(*KeyFile){
		"ed25519 key id":     func(k *KeyFile) { k.KeyID = ed.KeyID },
		"ed25519 public key": func(k *KeyFile) { k.PublicKey = ed.PublicKey },
	} {
		k := ml
		mutate(&k)
		_, _, err := ParseKeyFile(keyFileJSON(t, k))
		require.ErrorContains(t, err, "does not match", name)
	}
}

func TestParseKeyFileRefuses(t *testing.T) {
	ed := fixtureKeyFile(t, Protocol, 1)
	ml := fixtureKeyFile(t, Protocol03, 1)
	std := strings.NewReplacer("-", "+", "_", "/")
	edStd := fixtureKeyFile(t, Protocol, 0xfb)
	require.NotEqual(t, edStd.Seed, std.Replace(edStd.Seed))

	cases := map[string]func() []byte{
		"0.2 identifier": func() []byte { k := ed; k.Protocol = Protocol02; return keyFileJSON(t, k) },
		"unknown protocol": func() []byte {
			k := ed
			k.Protocol = "https://ifandonlyif.io/apostille/spec/0.4"
			return keyFileJSON(t, k)
		},
		"empty protocol": func() []byte { k := ed; k.Protocol = ""; return keyFileJSON(t, k) },
		"ed25519 key id": func() []byte { k := ed; k.KeyID = ml.KeyID; return keyFileJSON(t, k) },
		"ed25519 public key": func() []byte {
			k := ed
			k.PublicKey = rawURL.EncodeToString(bytes.Repeat([]byte{1}, 32))
			return keyFileJSON(t, k)
		},
		"ml-dsa key id": func() []byte { k := ml; k.KeyID = "sha256:" + strings.Repeat("0", 64); return keyFileJSON(t, k) },
		"ml-dsa public key": func() []byte {
			k := ml
			k.PublicKey = fixtureKeyFile(t, Protocol03, 2).PublicKey
			return keyFileJSON(t, k)
		},
		"empty seed":    func() []byte { k := ml; k.Seed = ""; return keyFileJSON(t, k) },
		"short seed":    func() []byte { k := ed; k.Seed = k.Seed[:42]; return keyFileJSON(t, k) },
		"padded seed":   func() []byte { k := ed; k.Seed += "="; return keyFileJSON(t, k) },
		"standard seed": func() []byte { k := edStd; k.Seed = std.Replace(k.Seed); return keyFileJSON(t, k) },
		"expanded ed25519": func() []byte {
			k := ed
			k.Seed = rawURL.EncodeToString(append(bytes.Repeat([]byte{1}, 32), make([]byte, 32)...))
			return keyFileJSON(t, k)
		},
		"noncanonical seed": func() []byte { k := ml; k.Seed = k.Seed[:42] + "F"; return keyFileJSON(t, k) },
		"role too long":     func() []byte { k := ed; k.Role = strings.Repeat("r", 65); return keyFileJSON(t, k) },
		"role newline":      func() []byte { k := ml; k.Role = "a\nb"; return keyFileJSON(t, k) },
		"role carriage":     func() []byte { k := ml; k.Role = "a\rb"; return keyFileJSON(t, k) },
		"role nul":          func() []byte { k := ed; k.Role = "a\x00b"; return keyFileJSON(t, k) },
		"unknown member":    func() []byte { return []byte(strings.Replace(string(keyFileJSON(t, ed)), `{`, `{"x":"y",`, 1)) },
		"duplicate member":  func() []byte { return []byte(strings.Replace(string(keyFileJSON(t, ed)), `{`, `{"seed":"x",`, 1)) },
		"not an object":     func() []byte { return []byte(`[]`) },
		"empty":             func() []byte { return nil },
		"trailing data":     func() []byte { return append(keyFileJSON(t, ed), []byte(` {}`)...) },
		"numeric role":      func() []byte { return []byte(strings.Replace(string(keyFileJSON(t, ed)), `}`, `,"role":1}`, 1)) },
		"oversize": func() []byte {
			k := ml
			k.Role = ""
			return append(keyFileJSON(t, k), bytes.Repeat([]byte(" "), MaxKeyFileBytes)...)
		},
		"oversize with role":  func() []byte { return bytes.Repeat([]byte("{"), MaxKeyFileBytes+1) },
		"ed25519 nonstandard": func() []byte { k := ed; k.PublicKey = std.Replace(edStd.PublicKey); return keyFileJSON(t, k) },
	}
	for name, build := range cases {
		_, _, err := ParseKeyFile(build())
		require.Error(t, err, name)
	}

	// A file at exactly the cap is read; the cap is on the input, not the key.
	padded := append(keyFileJSON(t, ml), bytes.Repeat([]byte(" "), MaxKeyFileBytes-len(keyFileJSON(t, ml)))...)
	require.Len(t, padded, MaxKeyFileBytes)
	_, _, err := ParseKeyFile(padded)
	require.NoError(t, err)
	_, _, err = ParseKeyFile(append(padded, ' '))
	require.ErrorContains(t, err, "too large")
}

func TestKeyFileSignersInterop(t *testing.T) {
	// A key file's signer produces what the typed constructors produce.
	k := fixtureKeyFile(t, Protocol03, 2)
	fromFile, _, err := ParseKeyFile(keyFileJSON(t, k))
	require.NoError(t, err)
	direct, err := NewMLDSASigner(k.Seed)
	require.NoError(t, err)
	require.Equal(t, direct.KeyID(), fromFile.KeyID())
	require.Equal(t, direct.PublicKey(), fromFile.PublicKey())

	reg, err := CreateRegistrationFor(Protocol03, fromFile, direct, exampleIssuer, time.Hour, fixedNow)
	require.NoError(t, err)
	_, err = VerifyRegistration(reg, exampleIssuer, fixedNow)
	require.NoError(t, err)
}
