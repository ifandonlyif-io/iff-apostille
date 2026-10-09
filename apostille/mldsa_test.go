package apostille

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMLDSASignerSeedValidation(t *testing.T) {
	seed := rawURL.EncodeToString(bytes.Repeat([]byte{7}, 32))
	require.Len(t, seed, 43)
	s, err := NewMLDSASigner(seed)
	require.NoError(t, err)
	require.Equal(t, Algorithm03, s.Algorithm())
	require.True(t, s.Enabled())

	// 32 bytes leave two unused bits in the last character; flip the lowest.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, seed[42])
	for name, bad := range map[string]string{
		"empty":           "",
		"short":           seed[:42],
		"long":            seed + "A",
		"padded":          seed + "=",
		"noncanonical":    seed[:42] + string(alphabet[last|1]),
		"standard":        strings.NewReplacer("-", "+", "_", "/").Replace(rawURL.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))),
		"expanded-ed2551": rawURL.EncodeToString(bytes.Repeat([]byte{7}, 64)),
		"not-base64":      strings.Repeat("!", 43),
	} {
		_, err := NewMLDSASigner(bad)
		require.Error(t, err, name)
	}
	_, err = NewMLDSASigner(rawURL.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)))
	require.NoError(t, err, "a seed whose characters include - and _ is fine")
}

func TestMLDSAKeyDerivation(t *testing.T) {
	s := testSignerFor(t, Protocol03, 1)
	pub := s.publicKeyBytes()
	require.Len(t, pub, 1952)
	require.Len(t, s.PublicKey(), 2603)
	sum := sha256.Sum256(pub)
	require.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), s.KeyID())

	// The same seed as an Ed25519 key gives an unrelated key and ID.
	ed := testSigner(t, 1)
	require.Equal(t, Algorithm, ed.Algorithm())
	require.NotEqual(t, ed.KeyID(), s.KeyID())
	require.Len(t, ed.PublicKey(), 43)

	// A disabled signer reports nothing and signs nothing.
	for _, disabled := range []*Signer{nil, {}} {
		require.False(t, disabled.Enabled())
		require.Equal(t, "", disabled.Algorithm())
		require.Equal(t, "", disabled.KeyID())
		require.Equal(t, "", disabled.PublicKey())
		_, err := disabled.SignFor(Protocol03, KindStatement, Statement{})
		require.Error(t, err)
	}
	empty, err := NewSigner("")
	require.NoError(t, err)
	require.Equal(t, "", empty.Algorithm())

	seed, publicKey, err := GenerateMLDSAKey()
	require.NoError(t, err)
	gen, err := NewMLDSASigner(seed)
	require.NoError(t, err)
	require.Equal(t, publicKey, gen.PublicKey())
	seed2, _, err := GenerateMLDSAKey()
	require.NoError(t, err)
	require.NotEqual(t, seed, seed2)
}

func TestSignForRefusesAnotherAlgorithmBeforeAnyWork(t *testing.T) {
	ed := testSigner(t, 1)
	ml, err := NewMLDSASigner(rawURL.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	require.NoError(t, err)

	// A value that cannot be marshalled would fail first if any work happened.
	unmarshalable := map[string]any{"c": make(chan int)}
	_, err = ed.SignFor(Protocol03, KindStatement, unmarshalable)
	require.EqualError(t, err, "signer does not support the protocol's signature algorithm")
	for _, protocol := range []string{Protocol, Protocol02} {
		_, err = ml.SignFor(protocol, KindStatement, unmarshalable)
		require.EqualError(t, err, "signer does not support the protocol's signature algorithm")
	}
	// Right algorithm: the failure is the marshalling one.
	_, err = ml.SignFor(Protocol03, KindStatement, unmarshalable)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "algorithm")

	// The untyped entry points keep signing 0.1 and so refuse ML-DSA signers.
	_, err = ml.Sign(KindStatement, Statement{})
	require.EqualError(t, err, "signer does not support the protocol's signature algorithm")
	_, err = CreateRegistration(ml, ml, exampleIssuer, time.Hour, fixedNow)
	require.Error(t, err)
}

func TestMLDSAProductionSigningIsHedged(t *testing.T) {
	seed := rawURL.EncodeToString(bytes.Repeat([]byte{9}, 32))
	prod, err := NewMLDSASigner(seed)
	require.NoError(t, err)
	require.False(t, prod.deterministic)
	input := profile03.signingInput(KindStatement, []byte(`{"a":"b"}`))
	first, err := prod.signMessage(input)
	require.NoError(t, err)
	second, err := prod.signMessage(input)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "hedged signing uses fresh randomness")
	require.NoError(t, profile03.verify(prod.publicKeyBytes(), input, first))
	require.NoError(t, profile03.verify(prod.publicKeyBytes(), input, second))

	// The deterministic variant yields one signature, and verifiers accept it.
	det, err := NewMLDSASigner(seed)
	require.NoError(t, err)
	det.deterministic = true
	d1, err := det.signMessage(input)
	require.NoError(t, err)
	d2, err := det.signMessage(input)
	require.NoError(t, err)
	require.Equal(t, d1, d2)
	require.NoError(t, profile03.verify(det.publicKeyBytes(), input, d1))
	require.NotEqual(t, d1, first)
}

// TestDeterministicSigningIsTestOnly keeps the deterministic hook out of
// production code: only _test.go files may turn it on.
func TestDeterministicSigningIsTestOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		require.NoError(t, err)
		checked++
		text := string(src)
		require.NotContains(t, text, "deterministic = true", file)
		require.NotContains(t, text, "deterministic: true", file)
		if file != "crypto.go" {
			require.NotContains(t, text, "SignDeterministic", file)
		}
	}
	require.Positive(t, checked)
}

func TestProfile03RejectsOtherSignatureForms(t *testing.T) {
	s := testSignerFor(t, Protocol03, 1)
	key := s.ml
	pub := s.publicKeyBytes()
	message := profile03.signingInput(KindStatement, []byte(`{}`))

	pure, err := key.SignDeterministic(message, &mldsa.Options{})
	require.NoError(t, err)
	require.NoError(t, profile03.verify(pub, message, pure))
	require.Error(t, profile03.verify(pub, append([]byte{0}, message...), pure))

	withContext, err := key.SignDeterministic(message, &mldsa.Options{Context: "x"})
	require.NoError(t, err)
	require.Error(t, profile03.verify(pub, message, withContext))

	// Any 1952-byte string is a decodable key: verification just fails.
	require.NoError(t, profile03.checkKey(make([]byte, 1952)))
	require.Error(t, profile03.verify(make([]byte, 1952), message, pure))
	require.Error(t, profile03.checkKey(pub[:1951]))
	require.Error(t, profile03.verify(pub[:1951], message, pure))
}

func TestExternalMuMatchesPureSigning(t *testing.T) {
	s := testSignerFor(t, Protocol03, 3)
	message := profile03.signingInput(KindCertificate, []byte(`{"x":"y"}`))
	mu := externalMu(s.publicKeyBytes(), append([]byte{0, 0}, message...))
	viaMu, err := s.ml.SignDeterministic(mu, crypto.MLDSAMu)
	require.NoError(t, err)
	direct, err := s.ml.SignDeterministic(message, &mldsa.Options{})
	require.NoError(t, err)
	require.Equal(t, direct, viaMu, "mu of the pure M' reproduces the deterministic pure signature")
}

func TestSigningAndVerificationAt03(t *testing.T) {
	admin, err := NewMLDSASigner(rawURL.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	require.NoError(t, err)
	agent, err := NewMLDSASigner(rawURL.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	require.NoError(t, err)
	issuer, err := NewMLDSASigner(rawURL.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	require.NoError(t, err)
	now := fixedNow

	reg, err := CreateRegistrationFor(Protocol03, admin, agent, exampleIssuer, time.Hour, now)
	require.NoError(t, err)
	require.Equal(t, Protocol03, reg.Delegation.Protocol)
	require.Equal(t, Algorithm03, reg.Delegation.Signature.Algorithm)
	require.Len(t, reg.Delegation.Signature.PublicKey, 2603)
	require.Len(t, reg.Delegation.Signature.Value, 4412)
	_, err = VerifyRegistration(reg, exampleIssuer, now)
	require.NoError(t, err)

	st, err := CreateStatementFor(Protocol03, strings.NewReader("hello\n"), "text/plain", agent, &reg, "", now)
	require.NoError(t, err)
	grant, err := CreateGrantFor(Protocol03, st, reg, admin, exampleIssuer, "private", now)
	require.NoError(t, err)
	_, err = ValidateGrant(grant, st, reg.Delegation, admin.KeyID(), exampleIssuer, now)
	require.NoError(t, err)

	b, err := Issue(Bundle{Protocol: Protocol03, Statement: st, Delegation: &reg.Delegation, Acceptance: &reg.Acceptance}, issuer, exampleIssuer, now.Add(time.Minute))
	require.NoError(t, err)
	v, err := VerifyBundle(b, VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{issuer.KeyID()}, Now: now.Add(time.Hour), AcceptedProtocols: []string{Protocol03}})
	require.NoError(t, err)
	require.Equal(t, Protocol03, v.Protocol)
	require.Equal(t, "accepted_by_policy", v.IssuerTrust)
	require.True(t, VerifyArtifact(v, []byte("hello\n")))

	// A receiver restricted to 0.1 and 0.2 refuses it.
	_, err = VerifyBundle(b, VerifyOptions{AcceptedProtocols: []string{Protocol, Protocol02}})
	require.ErrorContains(t, err, "not accepted")

	// The cached verifier agrees, and a tampered signature is refused.
	cached := new(Verifier)
	_, err = cached.VerifyBundle(b, VerifyOptions{})
	require.NoError(t, err)
	bad := cloneBundle(b)
	bad.Statement.Signature.Value = flipFirstByte(t, bad.Statement.Signature.Value)
	_, err = cached.VerifyBundle(bad, VerifyOptions{})
	require.ErrorContains(t, err, "invalid source signature")
}

func flipFirstByte(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := rawURL.DecodeString(encoded)
	require.NoError(t, err)
	raw[0] ^= 1
	return rawURL.EncodeToString(raw)
}

func TestGrantNamingAnotherVersionsStatement(t *testing.T) {
	admin3, agent3 := testSignerFor(t, Protocol03, 1), testSignerFor(t, Protocol03, 2)
	admin2, agent2 := testSigner(t, 1), testSigner(t, 2)
	now := fixedNow

	reg3, err := CreateRegistrationFor(Protocol03, admin3, agent3, exampleIssuer, time.Hour, now)
	require.NoError(t, err)
	reg2, err := CreateRegistrationFor(Protocol02, admin2, agent2, exampleIssuer, time.Hour, now)
	require.NoError(t, err)
	st3, err := CreateStatementFor(Protocol03, strings.NewReader("hello\n"), "text/plain", agent3, &reg3, "", now)
	require.NoError(t, err)
	st2, err := CreateStatementFor(Protocol02, strings.NewReader("hello\n"), "text/plain", agent2, &reg2, "", now)
	require.NoError(t, err)

	// Creation refuses to bind a 0.3 grant to 0.2 material, either way round.
	_, err = CreateGrantFor(Protocol03, st2, reg3, admin3, exampleIssuer, "private", now)
	require.Error(t, err)
	_, err = CreateGrantFor(Protocol03, st3, reg2, admin3, exampleIssuer, "private", now)
	require.Error(t, err)
	_, err = CreateGrantFor(Protocol02, st3, reg3, admin2, exampleIssuer, "private", now)
	require.Error(t, err)
	_, err = CreateStatementFor(Protocol03, strings.NewReader("x"), "text/plain", agent3, &reg2, "", now)
	require.ErrorContains(t, err, "differs")

	// A genuine 0.3 grant over a genuine 0.3 statement and delegation is refused
	// when checked against a 0.2 statement or delegation.
	grant3, err := CreateGrantFor(Protocol03, st3, reg3, admin3, exampleIssuer, "private", now)
	require.NoError(t, err)
	grant2, err := CreateGrantFor(Protocol02, st2, reg2, admin2, exampleIssuer, "private", now)
	require.NoError(t, err)
	for _, tc := range []struct{ grant, statement, delegation Envelope }{
		{grant3, st2, reg3.Delegation},
		{grant3, st3, reg2.Delegation},
		{grant3, st2, reg2.Delegation},
		{grant2, st3, reg2.Delegation},
		{grant2, st2, reg3.Delegation},
	} {
		_, err = ValidateGrant(tc.grant, tc.statement, tc.delegation, admin3.KeyID(), exampleIssuer, now)
		require.ErrorContains(t, err, "different protocol versions")
	}
}

func TestLogin03(t *testing.T) {
	s := testSignerFor(t, Protocol03, 1)
	ed := testSigner(t, 1)
	message := LoginPrefix03 + "issuer:https://service.example\nkey_id:" + s.KeyID() + "\nchallenge:x"

	sig, err := s.SignChallenge03(message)
	require.NoError(t, err)
	require.Len(t, sig, 4412)
	require.True(t, VerifyChallenge03(s.PublicKey(), message, sig))

	// Hedged: signing again gives a different, equally valid signature.
	prod, err := NewMLDSASigner(rawURL.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	require.NoError(t, err)
	a, err := prod.SignChallenge03(message)
	require.NoError(t, err)
	b, err := prod.SignChallenge03(message)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	require.True(t, VerifyChallenge03(prod.PublicKey(), message, a))
	require.True(t, VerifyChallenge03(prod.PublicKey(), message, b))

	// Size bounds: 4096 bytes signs, 4097 does not.
	long := LoginPrefix03 + strings.Repeat("a", 4096-len(LoginPrefix03))
	sigLong, err := s.SignChallenge03(long)
	require.NoError(t, err)
	require.True(t, VerifyChallenge03(s.PublicKey(), long, sigLong))
	_, err = s.SignChallenge03(long + "a")
	require.Error(t, err)
	require.False(t, VerifyChallenge03(s.PublicKey(), long+"a", sigLong))

	// Prefix separation, in both directions and for both algorithms.
	_, err = s.SignChallenge03("iff-apostille/login/0.1\nx")
	require.Error(t, err, "ML-DSA signer refuses the 0.1 prefix")
	_, err = s.SignChallenge("iff-apostille/login/0.1\nx")
	require.Error(t, err, "the 0.1 login function refuses an ML-DSA signer")
	_, err = ed.SignChallenge03(message)
	require.Error(t, err, "Ed25519 signer refuses the 0.3 prefix")
	_, err = ed.SignChallenge(message)
	require.Error(t, err)
	_, err = s.SignChallenge03("iff-apostille/origin-statement/0.3\nx")
	require.Error(t, err)

	// 0.1 logins still work and do not verify as 0.3 logins, nor the reverse.
	message01 := "iff-apostille/login/0.1\nx"
	sig01, err := ed.SignChallenge(message01)
	require.NoError(t, err)
	require.True(t, VerifyChallenge(ed.PublicKey(), message01, sig01))
	require.False(t, VerifyChallenge03(ed.PublicKey(), message01, sig01))
	require.False(t, VerifyChallenge03(s.PublicKey(), message, sig01))
	require.False(t, VerifyChallenge(s.PublicKey(), message, sig))

	// Tampering and malformed encodings.
	require.False(t, VerifyChallenge03(s.PublicKey(), message+"x", sig))
	require.False(t, VerifyChallenge03(s.PublicKey(), "iff-apostille/login/0.1\n"+message[len(LoginPrefix03):], sig))
	require.False(t, VerifyChallenge03(s.PublicKey(), message, sig+"="))
	require.False(t, VerifyChallenge03(s.PublicKey(), message, sig[:4411]))
	require.False(t, VerifyChallenge03(s.PublicKey(), message, strings.NewReplacer("-", "+", "_", "/").Replace(sig)))
	require.False(t, VerifyChallenge03(s.PublicKey()[:2602], message, sig))
	require.False(t, VerifyChallenge03(testSignerFor(t, Protocol03, 2).PublicKey(), message, sig))

	// A login signature is not a signature over any artifact.
	input := profile03.signingInput(KindStatement, []byte(message))
	require.Error(t, profile03.verify(s.publicKeyBytes(), input, mustDecode(t, sig)))
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := rawURL.DecodeString(s)
	require.NoError(t, err)
	return raw
}

// TestWycheproofSubset checks the committed Wycheproof subset against its own
// messages with crypto/mldsa (the source test's verdict) and then through the
// 0.3 profile.
func TestWycheproofSubset(t *testing.T) {
	f := loadWycheproof(t)
	require.Equal(t, "ee7b4f7e611928cbe163dc6f5e54527bfd166f34", f.Commit)
	require.GreaterOrEqual(t, len(f.Tests), 13)
	seen := map[int]bool{}
	for _, tc := range f.Tests {
		require.False(t, seen[tc.TcID])
		seen[tc.TcID] = true
		pub, sig, msg := mustDecode(t, tc.PublicKeyB64), mustDecode(t, tc.SignatureB64), mustDecode(t, tc.MessageB64)
		require.Len(t, pub, 1952)
		require.Len(t, sig, 3309)
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub)
		require.NoError(t, err)
		require.Error(t, mldsa.Verify(pk, msg, sig, &mldsa.Options{}), "tcId %d", tc.TcID)
		require.Error(t, profile03.verify(pub, msg, sig), "tcId %d", tc.TcID)
		require.True(t, strings.Contains(strings.Join(tc.Flags, ","), "InvalidHintsEncoding") || strings.Contains(strings.Join(tc.Flags, ","), "InfinityNormViolation"), "tcId %d", tc.TcID)
	}
}

// TestHedgedFixture covers the committed hedged envelopes: they verify, they
// are not the deterministic ones, and signing them again would not reproduce
// them (which is why they are committed rather than regenerated).
func TestHedgedFixture(t *testing.T) {
	hedged := loadHedgedFixture(t)
	det, _, _, issuer := gen03.fixedBundle(t)
	opts := VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{issuer.KeyID()}, Now: fixedNow.Add(time.Hour)}

	v, err := VerifyBundle(hedged.Bundle, opts)
	require.NoError(t, err)
	require.Equal(t, "accepted_by_policy", v.IssuerTrust)
	vDet, err := VerifyBundle(det, opts)
	require.NoError(t, err)
	require.Equal(t, vDet.IssuerKeyID, v.IssuerKeyID, "same keys")

	for name, pair := range map[string][2]*Envelope{
		"statement":   {&hedged.Bundle.Statement, &det.Statement},
		"delegation":  {hedged.Bundle.Delegation, det.Delegation},
		"acceptance":  {hedged.Bundle.Acceptance, det.Acceptance},
		"certificate": {hedged.Bundle.Certificate, det.Certificate},
	} {
		require.Equal(t, pair[1].Signature.PublicKey, pair[0].Signature.PublicKey, name)
		require.NotEqual(t, pair[1].Signature.Value, pair[0].Signature.Value, name+": hedged differs from deterministic")
		_, err := VerifyEnvelope(*pair[0])
		require.NoError(t, err, name)
	}
	// The delegation's payload does not depend on any signature, so only the
	// signature separates the hedged envelope from the deterministic one.
	require.Equal(t, det.Delegation.Payload, hedged.Bundle.Delegation.Payload)

	// Signing the same payload again with the production path gives yet another
	// signature, so regenerating the fixture would change it.
	again := hedgedKnownAnswerBundle(t)
	require.NotEqual(t, again.Delegation.Signature.Value, hedged.Bundle.Delegation.Signature.Value)
	require.Equal(t, again.Delegation.Payload, hedged.Bundle.Delegation.Payload)
}
