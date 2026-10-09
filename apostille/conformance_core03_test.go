package apostille

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Core 0.3 writers. They are distinct test functions so that
//
//	UPDATE_APOSTILLE_FIXTURES=1 go test -run '^TestWriteCore03(Vector|Cases)$'
//
// rewrites only the 0.3 files; the Core 0.1 and 0.2 files are frozen. Run the
// vector first: the case generator checks its base bundle against it. Every
// signature in both files is deterministic except the hedged accept case, which
// is read from testdata/apostille/core-0.3-hedged.json (see hedgedFixturePath).
// ---------------------------------------------------------------------------

func TestWriteCore03Vector(t *testing.T) { writeInteropFixture(t, gen03) }

func TestWriteCore03Cases(t *testing.T) { writeConformanceCases(t, gen03, core03ExtraCases) }

// core03ExtraCases are the categories that exist only in the 0.3 file, on top
// of every 0.2 category that does not depend on Ed25519, regenerated under the
// 0.3 namespace by the shared writer.
func core03ExtraCases(t *testing.T) ([]bundleCase, []issuerConformanceCase) {
	g := gen03
	var cases []bundleCase
	cases = append(cases, g.identifierBundleCases(t)...)
	cases = append(cases, g.hedgedCases(t)...)
	cases = append(cases, g.mldsaSizeCases(t)...)
	cases = append(cases, g.mldsaEncodingCases(t)...)
	cases = append(cases, g.mldsaAlgorithmCases(t)...)
	cases = append(cases, g.contextAndPrehashCases(t)...)
	cases = append(cases, g.domainCases03(t)...)
	cases = append(cases, g.malformedSignatureCases(t)...)
	cases = append(cases, g.wycheproofCases(t)...)
	cases = append(cases, g.nonMLDSAKeyCases(t)...)
	cases = append(cases, g.crossVersionCases03(t)...)
	return cases, g.identifierConformanceCases(t)
}

// ---------------------------------------------------------------------------
// The hedged accept case. A hedged signature differs on every run, so it is
// generated once by TestWriteCore03HedgedFixture and committed; the case
// generator only copies it. UPDATE_APOSTILLE_FIXTURES never rewrites it.
// ---------------------------------------------------------------------------

func hedgedFixturePath() string {
	return filepath.Join("..", "testdata", "apostille", "core-0.3-hedged.json")
}

type hedgedFixtureFile struct {
	Protocol string `json:"protocol"`
	Notice   string `json:"notice"`
	Bundle   Bundle `json:"bundle"`
}

const hedgedFixtureNotice = "Synthetic public test seeds. The known-answer content of core-0.3.json with every envelope signed by the production (hedged) ML-DSA-65 path, generated once. Do not regenerate: hedged signatures differ on every run, and the 0.3 case file embeds these bytes."

// hedgedKnownAnswerBundle builds the known-answer bundle with hedged signers,
// exactly as g.fixedBundle builds it with deterministic ones.
func hedgedKnownAnswerBundle(t *testing.T) Bundle {
	t.Helper()
	b, _, _, issuer := fixtureSigned(t, Protocol03, func(n byte) *Signer {
		s := testSignerFor(t, Protocol03, n)
		s.deterministic = false
		return s
	})
	var c Certificate
	requireNoErr(t, "hedged certificate", DecodePayload(*b.Certificate, KindCertificate, &c))
	c.CertificateID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	ce := mustSignFor(t, Protocol03, issuer, KindCertificate, c)
	b.Certificate = &ce
	return b
}

// TestWriteCore03HedgedFixture writes the hedged fixture. It does nothing
// unless UPDATE_APOSTILLE_HEDGED=1, a variable the other writers do not read.
func TestWriteCore03HedgedFixture(t *testing.T) {
	if os.Getenv("UPDATE_APOSTILLE_HEDGED") != "1" {
		return
	}
	raw, err := json.MarshalIndent(hedgedFixtureFile{Protocol: Protocol03, Notice: hedgedFixtureNotice, Bundle: hedgedKnownAnswerBundle(t)}, "", "  ")
	requireNoErr(t, "hedged fixture", err)
	requireNoErr(t, "hedged fixture", os.WriteFile(hedgedFixturePath(), append(raw, '\n'), 0o644))
}

func loadHedgedFixture(t testing.TB) hedgedFixtureFile {
	t.Helper()
	raw, err := os.ReadFile(hedgedFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	var f hedgedFixtureFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Protocol != Protocol03 || f.Bundle.Protocol != Protocol03 {
		t.Fatalf("hedged fixture names %q", f.Protocol)
	}
	return f
}

func (g caseGen) hedgedCases(t *testing.T) []bundleCase {
	t.Helper()
	b := loadHedgedFixture(t).Bundle
	det, _, _, issuer := g.fixedBundle(t)
	if det.Statement.Signature.Value == b.Statement.Signature.Value || bytes.Equal(rawJSON(t, det), rawJSON(t, b)) {
		t.Fatal("hedged fixture is not distinguishable from the deterministic known-answer bundle")
	}
	name := "accept/hedged-signatures-known-answer-content"
	bc, v := g.acceptCase(t, name, "The known-answer content of core-0.3.json with every envelope signed by the production, hedged ML-DSA-65 signer (committed once, core-0.3-hedged.json): verifiers do not distinguish hedged from deterministic signatures.", rawJSON(t, b), pin(issuer))
	if v.IssuerTrust != "accepted_by_policy" || v.Freshness != "valid_at_evaluation_time" || v.AgentBinding != "admin_key_delegation" {
		t.Fatalf("%s: unexpected verification: %+v", name, v)
	}
	return []bundleCase{withArtifact(t, name, bc, v, []byte("hello\n"), true)}
}

// ---------------------------------------------------------------------------
// ML-DSA material built from the public fixture seed 4.
// ---------------------------------------------------------------------------

// honestML is the fixture signer's producer-only bundle with its parts: the
// base of every vector that keeps the key and message honest.
type honestML struct {
	bundle  Bundle
	signer  *Signer
	pub     []byte
	payload []byte
	message []byte
	sig     []byte
}

func (g caseGen) honestML(t *testing.T) honestML {
	t.Helper()
	b, s := g.producerOnly(t)
	payload, err := rawURL.DecodeString(b.Statement.Payload)
	requireNoErr(t, "honestML", err)
	sig, err := rawURL.DecodeString(b.Statement.Signature.Value)
	requireNoErr(t, "honestML", err)
	h := honestML{bundle: b, signer: s, pub: s.publicKeyBytes(), payload: payload, message: g.prof.signingInput(KindStatement, payload), sig: sig}
	if len(h.pub) != 1952 || len(h.sig) != 3309 {
		t.Fatalf("honestML: key %d bytes, signature %d bytes", len(h.pub), len(h.sig))
	}
	return h
}

func (h honestML) withSignature(sig []byte) Bundle {
	b := h.bundle
	b.Statement.Signature.Value = rawURL.EncodeToString(sig)
	return b
}

func (h honestML) withKey(pub []byte) Bundle {
	b := h.bundle
	b.Statement.Signature.PublicKey = rawURL.EncodeToString(pub)
	b.Statement.Signature.KeyID = Fingerprint(pub)
	return b
}

// mldsaKey is the fixture seed 4 under the given parameter set.
func mldsaKey(t *testing.T, params mldsa.Parameters) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.NewPrivateKey(params, bytes.Repeat([]byte{4}, 32))
	requireNoErr(t, params.String(), err)
	return key
}

func (g caseGen) mldsaSizeCases(t *testing.T) []bundleCase {
	t.Helper()
	h := g.honestML(t)
	var out []bundleCase

	for _, tc := range []struct {
		tag, what string
		pub       []byte
	}{
		{"short", "one byte short (1951)", h.pub[:len(h.pub)-1]},
		{"long", "one byte long (1953)", append(append([]byte{}, h.pub...), 0)},
	} {
		out = append(out, rejectCase(t, "reject/ml-dsa-public-key-"+tc.tag,
			"The statement's public key is "+tc.what+", with a genuine signature of the right size: a 0.3 key is exactly 1952 bytes (2603 characters).",
			rawJSON(t, h.withKey(tc.pub)), VerifyOptions{}, "key fingerprint mismatch"))
	}
	for _, tc := range []struct {
		tag, what string
		sig       []byte
	}{
		{"short", "one byte short (3308)", h.sig[:len(h.sig)-1]},
		{"long", "one byte long (3310)", append(append([]byte{}, h.sig...), 0)},
	} {
		out = append(out, rejectCase(t, "reject/ml-dsa-signature-"+tc.tag,
			"The statement's signature is "+tc.what+": a 0.3 signature is exactly 3309 bytes (4412 characters).",
			rawJSON(t, h.withSignature(tc.sig)), VerifyOptions{}, "invalid source signature"))
	}

	// Real keys and signatures of the other parameter sets, over the real
	// signing input. Only their sizes make them invalid here.
	for _, tc := range []struct {
		tag    string
		params mldsa.Parameters
	}{{"44", mldsa.MLDSA44()}, {"87", mldsa.MLDSA87()}} {
		key := mldsaKey(t, tc.params)
		pub := key.PublicKey().Bytes()
		sig, err := key.SignDeterministic(h.message, &mldsa.Options{})
		requireNoErr(t, "ML-DSA-"+tc.tag, err)
		if err := mldsa.Verify(key.PublicKey(), h.message, sig, &mldsa.Options{}); err != nil {
			t.Fatalf("ML-DSA-%s control signature does not verify under its own parameter set: %v", tc.tag, err)
		}
		wantKey, wantSig := tc.params.PublicKeySize(), tc.params.SignatureSize()
		out = append(out, rejectCase(t, "reject/ml-dsa-"+tc.tag+"-key-and-signature",
			fmt.Sprintf("A genuine ML-DSA-%s key (%d bytes) and signature (%d bytes) over the 0.3 signing input, in a 0.3 envelope that still says ML-DSA-65: the key size is wrong.", tc.tag, wantKey, wantSig),
			rawJSON(t, h.withKey(pub).withSig(sig)), VerifyOptions{}, "key fingerprint mismatch"))
		out = append(out, rejectCase(t, "reject/ml-dsa-"+tc.tag+"-signature-with-65-key",
			fmt.Sprintf("The ML-DSA-65 key with a genuine ML-DSA-%s signature (%d bytes) by another key: the signature size is wrong.", tc.tag, wantSig),
			rawJSON(t, h.withSignature(sig)), VerifyOptions{}, "invalid source signature"))
	}
	return out
}

// withSig sets the signature of a bundle's statement.
func (b Bundle) withSig(sig []byte) Bundle {
	b.Statement.Signature.Value = rawURL.EncodeToString(sig)
	return b
}

// nonCanonicalTail returns s with its last base64url character replaced by one
// whose unused low bits are nonzero, so that a lenient decoder yields the same
// bytes as the canonical string.
func nonCanonicalTail(t *testing.T, s string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, s[len(s)-1])
	if last < 0 {
		t.Fatal("nonCanonicalTail: not base64url")
	}
	alt := s[:len(s)-1] + string(alphabet[last|1])
	if alt == s {
		alt = s[:len(s)-1] + string(alphabet[last|2])
	}
	lenient, err := base64.RawURLEncoding.DecodeString(alt)
	requireNoErr(t, "nonCanonicalTail", err)
	canonical, err := rawURL.DecodeString(s)
	requireNoErr(t, "nonCanonicalTail", err)
	if !bytes.Equal(lenient, canonical) {
		t.Fatal("nonCanonicalTail: the alias decodes to different bytes")
	}
	if _, err := rawURL.DecodeString(alt); err == nil {
		t.Fatal("nonCanonicalTail: strict decoding accepted the alias")
	}
	return alt
}

func (g caseGen) mldsaEncodingCases(t *testing.T) []bundleCase {
	t.Helper()
	h := g.honestML(t)
	pubStr, sigStr := h.bundle.Statement.Signature.PublicKey, h.bundle.Statement.Signature.Value
	flip := strings.NewReplacer("-", "+", "_", "/")
	if flip.Replace(pubStr) == pubStr || flip.Replace(sigStr) == sigStr {
		t.Fatal("the fixture key or signature has no -/_ character to flip")
	}
	withKeyString := func(s string) []byte {
		b := h.bundle
		b.Statement.Signature.PublicKey = s
		return rawJSON(t, b)
	}
	withSigString := func(s string) []byte {
		b := h.bundle
		b.Statement.Signature.Value = s
		return rawJSON(t, b)
	}
	// 1952 bytes leave two unused bits in the last character; 3309 bytes leave none.
	return []bundleCase{
		rejectCase(t, "reject/ml-dsa-public-key-noncanonical-trailing-bits",
			"The 2603-character public key with nonzero unused bits in its last character: a lenient decoder reads the same 1952 bytes, so only the canonical re-encoding check rejects it.",
			withKeyString(nonCanonicalTail(t, pubStr)), VerifyOptions{}, "key fingerprint mismatch"),
		rejectCase(t, "reject/ml-dsa-public-key-padded",
			"The public key with the '=' padding that standard base64 adds to 1952 bytes (2604 characters).",
			withKeyString(pubStr+"="), VerifyOptions{}, "key fingerprint mismatch"),
		rejectCase(t, "reject/ml-dsa-public-key-standard-alphabet",
			"The public key with '-' and '_' replaced by '+' and '/': only unpadded base64url is valid.",
			withKeyString(flip.Replace(pubStr)), VerifyOptions{}, "key fingerprint mismatch"),
		rejectCase(t, "reject/ml-dsa-signature-padded",
			"The 4412-character signature with an '=' appended: 3309 bytes need no padding, so the signature is one character too long.",
			withSigString(sigStr+"="), VerifyOptions{}, "invalid source signature"),
		rejectCase(t, "reject/ml-dsa-signature-standard-alphabet",
			"The signature with '-' and '_' replaced by '+' and '/': only unpadded base64url is valid.",
			withSigString(flip.Replace(sigStr)), VerifyOptions{}, "invalid source signature"),
	}
}

func (g caseGen) mldsaAlgorithmCases(t *testing.T) []bundleCase {
	t.Helper()
	b, _ := g.producerOnly(t)
	var out []bundleCase
	for _, tc := range []struct{ tag, value string }{
		{"lowercase", "ml-dsa-65"},
		{"no-hyphens", "MLDSA65"},
		{"trailing-space", "ML-DSA-65 "},
		{"ed25519", "Ed25519"},
		{"ml-dsa-44", "ML-DSA-44"},
		{"ml-dsa-87", "ML-DSA-87"},
		{"empty", ""},
	} {
		value := tc.value
		out = append(out, rejectCase(t, "reject/algorithm-"+tc.tag,
			fmt.Sprintf("The signature algorithm %q instead of exactly ML-DSA-65: there is no negotiation, normalization or fallback.", value),
			mutateJSON(t, b, func(m map[string]any) {
				m["statement"].(map[string]any)["signature"].(map[string]any)["algorithm"] = value
			}), VerifyOptions{}, "unsupported envelope protocol or algorithm"))
	}
	return out
}

// ---------------------------------------------------------------------------
// Non-empty context and HashML-DSA.
//
// HashML-DSA (FIPS 204 Algorithm 4) signs M' = 0x01 || len(ctx) || ctx ||
// OID(PH) || PH(M) in place of the pure M' = 0x00 || len(ctx) || ctx || M. Go
// has no HashML-DSA signer, so the signature is built from the signer's
// external-mu entry point: mu = SHAKE256(tr || M', 64) with
// tr = SHAKE256(pk, 64), signed with opts.HashFunc() == crypto.MLDSAMu.
// The construction is checked in two ways: signing the pure M' this way yields
// a signature that the pure verifier accepts, which proves tr and mu are
// computed as FIPS 204 specifies; and the HashML-DSA signature differs only in
// M'. Go has no HashML-DSA verifier, so the generator cannot assert that a
// HashML-DSA verifier accepts it; it asserts that crypto/mldsa's pure
// verifier, which Core 0.3 uses, rejects it, as does Apostille.
// ---------------------------------------------------------------------------

// externalMu is FIPS 204's mu for public key pk and message representative mPrime.
func externalMu(pk, mPrime []byte) []byte {
	tr := sha3.SumSHAKE256(pk, 64)
	return sha3.SumSHAKE256(append(append([]byte{}, tr...), mPrime...), 64)
}

// hashMLDSAMessage is M' of HashML-DSA with the empty context, the DER object
// identifier of the hash function and the digest of m.
func hashMLDSAMessage(oid, digest []byte) []byte {
	out := []byte{0x01, 0x00}
	out = append(out, oid...)
	return append(out, digest...)
}

var (
	// DER of 2.16.840.1.101.3.4.2.1 (SHA-256) and 2.16.840.1.101.3.4.2.3 (SHA-512).
	oidSHA256 = []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	oidSHA512 = []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}
)

func (g caseGen) contextAndPrehashCases(t *testing.T) []bundleCase {
	t.Helper()
	h := g.honestML(t)
	key := h.signer.ml
	pk := key.PublicKey()
	var out []bundleCase

	// Non-empty contexts, signed and verified under that same context.
	for _, tc := range []struct{ tag, ctx, what string }{
		{"short", "apostille", `the 9-byte context "apostille"`},
		{"longest", strings.Repeat("A", 255), "the longest allowed context (255 bytes)"},
	} {
		sig, err := key.SignDeterministic(h.message, &mldsa.Options{Context: tc.ctx})
		requireNoErr(t, tc.tag, err)
		if err := mldsa.Verify(pk, h.message, sig, &mldsa.Options{Context: tc.ctx}); err != nil {
			t.Fatalf("context %s: control signature does not verify under its own context: %v", tc.tag, err)
		}
		out = append(out, rejectCase(t, "reject/signature-with-context-"+tc.tag,
			"A genuine ML-DSA-65 signature over the 0.3 signing input made with "+tc.what+": it verifies under that context, but 0.3 verifies with the empty context.",
			rawJSON(t, h.withSignature(sig)), VerifyOptions{}, "invalid source signature"))
	}

	// Control: signing the pure M' (0x00 || 0x00 || M) through external mu gives
	// a signature the pure verifier accepts.
	pureMu := externalMu(pk.Bytes(), append([]byte{0x00, 0x00}, h.message...))
	pure, err := key.SignDeterministic(pureMu, crypto.MLDSAMu)
	requireNoErr(t, "external mu control", err)
	if err := mldsa.Verify(pk, h.message, pure, &mldsa.Options{}); err != nil {
		t.Fatalf("external-mu control: mu of the pure M' does not verify as a pure signature: %v", err)
	}

	for _, tc := range []struct {
		tag, name string
		oid       []byte
		digest    []byte
	}{
		{"sha256", "SHA-256", oidSHA256, func() []byte { d := sha256.Sum256(h.message); return d[:] }()},
		{"sha512", "SHA-512", oidSHA512, func() []byte { d := sha512.Sum512(h.message); return d[:] }()},
	} {
		mu := externalMu(pk.Bytes(), hashMLDSAMessage(tc.oid, tc.digest))
		sig, err := key.SignDeterministic(mu, crypto.MLDSAMu)
		requireNoErr(t, tc.tag, err)
		if mldsa.Verify(pk, h.message, sig, &mldsa.Options{}) == nil {
			t.Fatalf("HashML-DSA-%s signature verifies under pure ML-DSA", tc.name)
		}
		if bytes.Equal(sig, pure) {
			t.Fatalf("HashML-DSA-%s signature equals the pure one", tc.name)
		}
		out = append(out, rejectCase(t, "reject/signature-hashml-dsa-"+tc.tag,
			"A HashML-DSA ("+tc.name+") signature of the 0.3 signing input by the right key, built through external mu (mu = SHAKE256(tr || 0x01 || 0x00 || OID || "+tc.name+"(M), 64)); the construction is checked against a pure-M' control. Core 0.3 allows pure ML-DSA only.",
			rawJSON(t, h.withSignature(sig)), VerifyOptions{}, "invalid source signature"))
	}
	return out
}

// ---------------------------------------------------------------------------
// Signatures over another version's domain.
// ---------------------------------------------------------------------------

func (g caseGen) domainCases03(t *testing.T) []bundleCase {
	t.Helper()
	h := g.honestML(t)
	b3, _, _, issuer := g.fixedBundle(t)
	var out []bundleCase

	for _, other := range []*profile{profile02, profile01} {
		input := other.signingInput(KindStatement, h.payload)
		sig, err := h.signer.signMessage(input)
		requireNoErr(t, "domain", err)
		if err := g.prof.verify(h.pub, input, sig); err != nil {
			t.Fatalf("a signature over the %s signing input does not verify as a plain ML-DSA-65 signature: %v", other.domain, err)
		}
		out = append(out, rejectCase(t, "reject/cross-version-0.3-statement-signed-under-"+other.domain+"-domain",
			"A 0.3 statement whose signature is a genuine ML-DSA-65 signature over the "+other.domain+" signing input: the domain string differs, so it does not verify under 0.3.",
			rawJSON(t, h.withSignature(sig)), VerifyOptions{}, "invalid source signature"))
	}

	cert := *b3.Certificate
	certPayload, err := rawURL.DecodeString(cert.Payload)
	requireNoErr(t, "domain", err)
	sig, err := issuer.signMessage(profile02.signingInput(KindCertificate, certPayload))
	requireNoErr(t, "domain", err)
	cert.Signature.Value = rawURL.EncodeToString(sig)
	bad := cloneBundle(b3)
	bad.Certificate = &cert
	out = append(out, rejectCase(t, "reject/cross-version-0.3-certificate-signed-under-0.2-domain",
		"A 0.3 certificate whose signature is a genuine ML-DSA-65 signature over the 0.2 signing input.",
		rawJSON(t, bad), pin(issuer), "invalid source signature"))

	// A statement whose signed payload names 0.2, validly signed under the 0.3 domain.
	st := g.producerOnlyStatement(h.signer)
	st.Protocol = Protocol02
	p, err := Canonical(st)
	requireNoErr(t, "domain", err)
	b := h.bundle
	b.Statement = g.signRaw(t, h.signer, KindStatement, p)
	out = append(out, rejectCase(t, "reject/payload-protocol-mismatch-0.2",
		"A 0.3 statement, validly signed, whose signed payload header names the 0.2 protocol.",
		rawJSON(t, b), VerifyOptions{}, "invalid signed protocol header"))
	return out
}

// ---------------------------------------------------------------------------
// Malformed signature encodings.
//
// FIPS 204 layout of an ML-DSA-65 signature (k=6, l=5, omega=55, gamma1=2^19,
// beta=tau*eta=196, lambda=192): c-tilde 48 bytes || z = 5*256 coefficients of
// 20 bits = 3200 bytes || h = omega+k = 61 bytes (55 hint indices, then six
// cumulative per-polynomial counts). Each case below keeps a genuine signature
// and breaks one rule of Algorithm 3's decoding, so the signature is otherwise
// the honest one. Go's verifier reports every failure as a single error, so the
// generator cannot see which check fired; the rule named is the one violated.
// ---------------------------------------------------------------------------

const (
	sigCTildeLen = 48
	sigZLen      = 3200
	sigHintLen   = 61
	sigOmega     = 55
	sigK         = 6
)

func (g caseGen) malformedSignatureCases(t *testing.T) []bundleCase {
	t.Helper()
	h := g.honestML(t)
	if sigCTildeLen+sigZLen+sigHintLen != len(h.sig) {
		t.Fatal("ML-DSA-65 signature layout does not add up to 3309")
	}
	zOff, hOff := sigCTildeLen, sigCTildeLen+sigZLen

	mutate := func(f func(sig []byte)) []byte {
		sig := append([]byte{}, h.sig...)
		f(sig)
		return sig
	}
	// hints replaces the hint block: indices in order, then the cumulative counts.
	hints := func(indices []byte, counts [sigK]byte) func([]byte) {
		return func(sig []byte) {
			block := sig[hOff:]
			for i := range block {
				block[i] = 0
			}
			copy(block, indices)
			copy(block[sigOmega:], counts[:])
		}
	}

	var out []bundleCase
	for _, tc := range []struct {
		tag, reason string
		f           func([]byte)
	}{
		{"hint-indices-decreasing", "Two hint indices in one polynomial in decreasing order (5, 3) instead of strictly increasing.", hints([]byte{5, 3}, [sigK]byte{2, 2, 2, 2, 2, 2})},
		{"hint-indices-repeated", "Two equal hint indices (5, 5) in one polynomial.", hints([]byte{5, 5}, [sigK]byte{2, 2, 2, 2, 2, 2})},
		{"hint-count-above-omega", "The final cumulative hint count is 56, above omega = 55.", hints(nil, [sigK]byte{0, 0, 0, 0, 0, sigOmega + 1})},
		{"hint-counts-decreasing", "Cumulative hint counts that decrease (2 then 1).", hints([]byte{1, 2}, [sigK]byte{2, 1, 2, 2, 2, 2})},
		{"hint-padding-nonzero", "A nonzero byte in the unused hint indices after the last counted index.", func(sig []byte) {
			hints([]byte{7}, [sigK]byte{1, 1, 1, 1, 1, 1})(sig)
			sig[hOff+5] = 9
		}},
	} {
		out = append(out, rejectCase(t, "reject/ml-dsa-malformed-"+tc.tag,
			"A genuine signature with its hint block replaced: "+tc.reason+" FIPS 204's hint-decoding check rejects it.",
			rawJSON(t, h.withSignature(mutate(tc.f))), VerifyOptions{}, "invalid source signature"))
	}

	// z coefficients are 20-bit values v = gamma1 - z_i, little-endian bit
	// order. Coefficient 0 sits in bytes 0, 1 and the low nibble of byte 2.
	for _, tc := range []struct {
		tag, reason string
		f           func([]byte)
	}{
		{"z-above-bound", "z coefficient 0 encoded as v = 0, i.e. z = gamma1 = 524288, above gamma1 - beta - 1 = 524091.", func(sig []byte) {
			sig[zOff], sig[zOff+1], sig[zOff+2] = 0, 0, sig[zOff+2]&0xf0
		}},
		{"z-below-bound", "z coefficient 0 encoded as v = 2^20 - 1, i.e. z = -524287, below -(gamma1 - beta - 1) = -524091.", func(sig []byte) {
			sig[zOff], sig[zOff+1], sig[zOff+2] = 0xff, 0xff, sig[zOff+2]|0x0f
		}},
	} {
		out = append(out, rejectCase(t, "reject/ml-dsa-malformed-"+tc.tag,
			"A genuine signature with one z coefficient pushed outside the signing bound: "+tc.reason+" FIPS 204's norm check on z rejects it.",
			rawJSON(t, h.withSignature(mutate(tc.f))), VerifyOptions{}, "invalid source signature"))
	}
	return out
}

// wycheproofFile is the committed subset described in its notice.
type wycheproofFile struct {
	Notice        string `json:"notice"`
	Module        string `json:"module"`
	ModuleVersion string `json:"module_version"`
	Commit        string `json:"commit"`
	File          string `json:"file"`
	Algorithm     string `json:"algorithm"`
	Tests         []struct {
		TcID         int      `json:"tc_id"`
		Flags        []string `json:"flags"`
		Comment      string   `json:"comment"`
		PublicKeyB64 string   `json:"public_key_b64"`
		SignatureB64 string   `json:"signature_b64"`
		MessageB64   string   `json:"message_b64"`
	} `json:"tests"`
}

func wycheproofPath() string {
	return filepath.Join("..", "testdata", "apostille", "core-0.3-wycheproof.json")
}

func loadWycheproof(t testing.TB) wycheproofFile {
	t.Helper()
	raw, err := os.ReadFile(wycheproofPath())
	if err != nil {
		t.Fatal(err)
	}
	var f wycheproofFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Algorithm != "ML-DSA-65" || len(f.Tests) == 0 {
		t.Fatalf("unexpected Wycheproof subset: %q, %d tests", f.Algorithm, len(f.Tests))
	}
	return f
}

// wycheproofCases carry the signatures of C2SP Wycheproof's ML-DSA-65 verify
// tests whose result is "invalid" because of the signature's encoding, with the
// source test's own public key. Their messages are not Apostille's, so these
// signatures are also wrong for the signing input; the constructed cases above
// are the ones that isolate a single rule. The subset's own test (see
// TestWycheproofSubset) checks each against the source message with crypto/mldsa.
func (g caseGen) wycheproofCases(t *testing.T) []bundleCase {
	t.Helper()
	f := loadWycheproof(t)
	var out []bundleCase
	for _, tc := range f.Tests {
		pub, err := rawURL.DecodeString(tc.PublicKeyB64)
		requireNoErr(t, "wycheproof key", err)
		sig, err := rawURL.DecodeString(tc.SignatureB64)
		requireNoErr(t, "wycheproof signature", err)
		payload := g.statementPayload(t, Fingerprint(pub), tc.TcID)
		out = append(out, rejectCase(t, fmt.Sprintf("reject/wycheproof-ml-dsa-65-tc%d", tc.TcID),
			fmt.Sprintf("Wycheproof %s tcId %d (%s; flags %s; commit %s), invalid by %s: the source test's public key and signature in a 0.3 statement. Only the committed subset core-0.3-wycheproof.json is used.", f.File, tc.TcID, tc.Comment, strings.Join(tc.Flags, ","), f.Commit, strings.Join(tc.Flags, ",")),
			rawJSON(t, g.keyBundle(payload, pub, sig)), VerifyOptions{}, "invalid source signature"))
	}
	return out
}

// ---------------------------------------------------------------------------
// Ed25519 keys where ML-DSA keys belong.
// ---------------------------------------------------------------------------

func (g caseGen) nonMLDSAKeyCases(t *testing.T) []bundleCase {
	t.Helper()
	var out []bundleCase

	// An Ed25519 key and a genuine Ed25519 signature over the 0.3 signing input.
	ed := testSigner(t, 4)
	payload := g.statementPayload(t, ed.KeyID(), 0)
	input := g.prof.signingInput(KindStatement, payload)
	edSig, err := ed.signMessage(input)
	requireNoErr(t, "ed25519", err)
	out = append(out, rejectCase(t, "reject/ed25519-public-key-as-signature-key",
		"The Ed25519 fixture key (32 bytes, 43 characters) with a genuine Ed25519 signature over the 0.3 signing input, in a 0.3 envelope: a 0.3 signature key is a 1952-byte ML-DSA-65 key.",
		rawJSON(t, g.keyBundle(payload, ed.publicKeyBytes(), edSig)), VerifyOptions{}, "key fingerprint mismatch"))

	// The same as an agent_public_key, in a delegation validly signed by the administrator.
	b, admin, _, issuer := g.fixedBundle(t)
	var d Delegation
	requireNoErr(t, "agent key", DecodePayload(*b.Delegation, KindDelegation, &d))
	for _, tc := range []struct {
		tag, why string
		key      []byte
	}{
		{"ed25519", "the Ed25519 fixture key (32 bytes)", ed.publicKeyBytes()},
		{"ml-dsa-65-one-byte-short", "the agent's ML-DSA-65 key with its last byte removed (1951 bytes)", func() []byte { k := g.signer(t, 2).publicKeyBytes(); return k[:len(k)-1] }()},
	} {
		dd := d
		dd.AgentPublicKey = rawURL.EncodeToString(tc.key)
		dd.AgentKeyID = Fingerprint(tc.key)
		p, err := Canonical(dd)
		requireNoErr(t, tc.tag, err)
		bad := g.signRaw(t, admin, KindDelegation, p)
		bundle := cloneBundle(b)
		bundle.Delegation = &bad
		out = append(out, rejectCase(t, "reject/agent-public-key-"+tc.tag,
			fmt.Sprintf("A delegation, validly signed by the administrator, whose agent_public_key is %s: the 0.3 key rule applies to agent_public_key as it does to signature.public_key.", tc.why),
			rawJSON(t, bundle), pin(issuer), "invalid agent delegation"))
	}
	return out
}

// ---------------------------------------------------------------------------
// Cross-version material.
// ---------------------------------------------------------------------------

func (g caseGen) crossVersionCases03(t *testing.T) []bundleCase {
	t.Helper()
	b3, _, _, issuer := g.fixedBundle(t)
	b2, _, _, _ := gen02.fixedBundle(t)
	b1, _, _, _ := gen01.fixedBundle(t)
	opts := pin(issuer)
	var out []bundleCase

	slot := func(b *Bundle, name string) *Envelope {
		switch name {
		case "statement":
			return &b.Statement
		case "delegation":
			return b.Delegation
		case "acceptance":
			return b.Acceptance
		}
		return b.Certificate
	}
	slots := []string{"statement", "delegation", "acceptance", "certificate"}

	// An envelope of another version inside a bundle, one per slot and direction.
	// Each envelope is valid under its own version; the bundle is rejected before
	// any signature check.
	for _, tc := range []struct {
		host, guest string
		hostB, from Bundle
	}{
		{"0.3", "0.2", b3, b2}, {"0.3", "0.1", b3, b1},
		{"0.2", "0.3", b2, b3}, {"0.1", "0.3", b1, b3},
	} {
		for _, name := range slots {
			bad := cloneBundle(tc.hostB)
			from := cloneBundle(tc.from)
			*slot(&bad, name) = *slot(&from, name)
			out = append(out, rejectCase(t, "reject/cross-version-"+tc.guest+"-"+name+"-in-"+tc.host+"-bundle",
				fmt.Sprintf("A genuine %s %s envelope in an otherwise %s bundle: a bundle carries one version.", tc.guest, name, tc.host),
				rawJSON(t, bad), opts, "bundle mixes protocol versions"))
		}
	}

	// The same material relabelled at bundle level only.
	for _, tc := range []struct {
		name, reason string
		b            Bundle
		label        string
	}{
		{"reject/cross-version-0.3-bundle-labelled-0.2", "A complete 0.3 bundle with only the bundle protocol changed to 0.2: its envelopes still name 0.3.", b3, Protocol02},
		{"reject/cross-version-0.3-bundle-labelled-0.1", "A complete 0.3 bundle with only the bundle protocol changed to 0.1: its envelopes still name 0.3.", b3, Protocol},
		{"reject/cross-version-0.2-bundle-labelled-0.3", "A complete 0.2 bundle with only the bundle protocol changed to 0.3: its envelopes still name 0.2.", b2, Protocol03},
		{"reject/cross-version-0.1-bundle-labelled-0.3", "A complete 0.1 bundle with only the bundle protocol changed to 0.3: its envelopes still name 0.1.", b1, Protocol03},
	} {
		relabelled := cloneBundle(tc.b)
		relabelled.Protocol = tc.label
		out = append(out, rejectCase(t, tc.name, tc.reason, rawJSON(t, relabelled), opts, "bundle mixes protocol versions"))
	}

	// A producer-only 0.2 statement (Ed25519 key and signature) relabelled 0.3 in
	// the bundle, envelope and payload with its digest recomputed: first with the
	// Ed25519 algorithm string it carries, then with the string changed too.
	base2, _ := gen02.producerOnly(t)
	payload2, err := rawURL.DecodeString(base2.Statement.Payload)
	requireNoErr(t, "relabel", err)
	relabelPayload := replaceOnce(t, payload2, `spec/0.2"`, `spec/0.3"`)
	relabel := func(algorithm string) Bundle {
		bad := base2
		bad.Protocol = Protocol03
		bad.Statement.Protocol = Protocol03
		bad.Statement.Payload = rawURL.EncodeToString(relabelPayload)
		bad.Statement.PayloadSHA256 = Hash(relabelPayload)
		bad.Statement.Signature.Algorithm = algorithm
		return bad
	}
	out = append(out, rejectCase(t, "reject/cross-version-0.2-statement-relabelled-0.3",
		"A genuine 0.2 statement, Ed25519 key and signature included, with its protocol changed to 0.3 in the bundle, envelope and payload (digest recomputed): the algorithm is Ed25519, not ML-DSA-65.",
		rawJSON(t, relabel(Algorithm)), VerifyOptions{}, "unsupported envelope protocol or algorithm"))
	out = append(out, rejectCase(t, "reject/cross-version-0.2-statement-relabelled-0.3-algorithm",
		"The same relabelled 0.2 statement with its algorithm string also changed to ML-DSA-65: the 32-byte Ed25519 key is not a 1952-byte ML-DSA-65 key.",
		rawJSON(t, relabel(Algorithm03)), VerifyOptions{}, "key fingerprint mismatch"))

	// Unknown versions fail closed.
	unknown := protocolNeverDefined
	out = append(out, rejectCase(t, "reject/unknown-bundle-protocol",
		"A bundle whose protocol names a version this profile does not define is rejected.",
		mutateJSON(t, b3, func(m map[string]any) { m["protocol"] = unknown }), opts, "unsupported bundle protocol"))
	out = append(out, rejectCase(t, "reject/empty-bundle-protocol",
		"An empty bundle protocol selects no rule set.",
		mutateJSON(t, b3, func(m map[string]any) { m["protocol"] = "" }), opts, "unsupported bundle protocol"))
	out = append(out, rejectCase(t, "reject/unknown-envelope-protocol",
		"An envelope naming an unknown version inside a 0.3 bundle.",
		mutateJSON(t, b3, func(m map[string]any) { m["statement"].(map[string]any)["protocol"] = unknown }), opts, "bundle mixes protocol versions"))
	return out
}

// ---------------------------------------------------------------------------
// Checks on the generator's own material.
// ---------------------------------------------------------------------------

func TestCore03CaseGeneratorUsesDeterministicSigners(t *testing.T) {
	s := testSignerFor(t, Protocol03, 4)
	again := testSignerFor(t, Protocol03, 4)
	input := profile03.signingInput(KindStatement, []byte(`{}`))
	a, err := s.signMessage(input)
	requireNoErr(t, "sign", err)
	b, err := again.signMessage(input)
	requireNoErr(t, "sign", err)
	if !bytes.Equal(a, b) {
		t.Fatal("the test signer is not deterministic")
	}
}
