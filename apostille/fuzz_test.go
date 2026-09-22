package apostille

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Seeds are added before f.Fuzz, where only a *testing.F exists, so they are
// built through the public API rather than the *testing.T helpers in
// apostille_test.go.

// fuzzSigner is testSigner for a *testing.F.
func fuzzSigner(f testing.TB, n byte) *Signer {
	f.Helper()
	s, err := NewSigner(rawURL.EncodeToString(bytes.Repeat([]byte{n}, 32)))
	if err != nil {
		f.Fatalf("fuzzSigner(%d): %v", n, err)
	}
	return s
}

// fuzzConformanceFile reads and decodes testdata/apostille/core-0.1-cases.json
// once, for seeding; it is never written to.
func fuzzConformanceFile(f *testing.F) conformanceFile {
	f.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "apostille", "core-0.1-cases.json"))
	if err != nil {
		f.Fatalf("reading conformance cases: %v", err)
	}
	var file conformanceFile
	if err := json.Unmarshal(raw, &file); err != nil {
		f.Fatalf("decoding conformance cases: %v", err)
	}
	return file
}

// fuzzFindNumber reports whether a value decoded by StrictJSON holds a number
// anywhere. 0.1 rejects every numeric token, so none may survive decoding.
func fuzzFindNumber(v any) bool {
	switch x := v.(type) {
	case float64, json.Number:
		return true
	case map[string]any:
		for _, val := range x {
			if fuzzFindNumber(val) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if fuzzFindNumber(val) {
				return true
			}
		}
	}
	return false
}

// fuzzFindReplacement reports whether a decoded value holds U+FFFD in any
// member name or string.
func fuzzFindReplacement(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.ContainsRune(x, '\uFFFD')
	case map[string]any:
		for key, val := range x {
			if strings.ContainsRune(key, '\uFFFD') || fuzzFindReplacement(val) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if fuzzFindReplacement(val) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// FuzzStrictJSON
// ---------------------------------------------------------------------------

func FuzzStrictJSON(f *testing.F) {
	file := fuzzConformanceFile(f)
	for _, c := range file.StrictJSONCases {
		if c.InputGen != nil || c.InputB64 == nil {
			continue
		}
		raw, err := rawURL.DecodeString(*c.InputB64)
		if err != nil {
			f.Fatalf("strict_json_cases[%s]: decoding input_b64: %v", c.Name, err)
		}
		f.Add(raw)
	}
	for _, c := range file.BundleCases {
		if c.InputGen != nil || c.InputB64 == nil {
			continue
		}
		raw, err := rawURL.DecodeString(*c.InputB64)
		if err != nil {
			f.Fatalf("bundle_cases[%s]: decoding input_b64: %v", c.Name, err)
		}
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var dst any
		if StrictJSON(raw, &dst) != nil {
			return
		}
		c1, err := Canonical(dst)
		if err != nil {
			t.Fatalf("Canonical(dst) failed after StrictJSON accepted raw: %v\nraw: %x", err, raw)
		}
		var again any
		if err := StrictJSON(c1, &again); err != nil {
			t.Fatalf("StrictJSON rejected its own Canonical output: %v\ncanonical: %s", err, c1)
		}
		c2, err := Canonical(again)
		if err != nil {
			t.Fatalf("Canonical(again) failed: %v\ncanonical: %s", err, c1)
		}
		if !bytes.Equal(c1, c2) {
			t.Fatalf("Canonical is not idempotent:\nc1: %s\nc2: %s", c1, c2)
		}
		if fuzzFindNumber(dst) {
			t.Fatalf("StrictJSON accepted a JSON number: raw: %s", raw)
		}
		// A decoded U+FFFD must be one the input spelled out, literally or as
		// \ufffd; anything else means a decoder papered over invalid text.
		if !bytes.Contains(raw, []byte("\uFFFD")) && !bytes.Contains(bytes.ToLower(raw), []byte("fffd")) && fuzzFindReplacement(dst) {
			t.Fatalf("StrictJSON manufactured U+FFFD: raw: %q", raw)
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzVerify
// ---------------------------------------------------------------------------

func FuzzVerify(f *testing.F) {
	file := fuzzConformanceFile(f)
	for _, c := range file.BundleCases {
		if c.InputGen != nil || c.InputB64 == nil {
			continue
		}
		raw, err := rawURL.DecodeString(*c.InputB64)
		if err != nil {
			f.Fatalf("bundle_cases[%s]: decoding input_b64: %v", c.Name, err)
		}
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		v1, err1 := Verify(raw, VerifyOptions{})
		if err1 == nil {
			if v1.ArtifactIntegrity != "valid" || v1.IssuerTrust != "unknown" || v1.Freshness != "unknown" {
				t.Fatalf("Verify with no policy accepted but result dimensions are wrong: %+v", v1)
			}
		}
		// An embedded key must never establish trust by itself: this pins an
		// unrelated issuer and an unrelated (but syntactically valid) trusted
		// key ID that cannot possibly match whatever the fuzzed input embeds.
		v2, err2 := Verify(raw, VerifyOptions{
			ExpectedIssuer: "https://unrelated.example/x",
			TrustedKeyIDs:  []string{"sha256:" + strings.Repeat("0", 64)},
			Now:            fixedNow,
		})
		if err2 == nil && v2.IssuerTrust == "accepted_by_policy" {
			t.Fatalf("Verify accepted an unrelated, untrusted policy as accepted_by_policy: %+v", v2)
		}
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("Verify disagreed on acceptance across policies for the same input: err1=%v err2=%v", err1, err2)
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzSignedPayload
// ---------------------------------------------------------------------------

// fuzzSignedPayloadKinds is FuzzSignedPayload's kind%5 lookup table, and also
// the index order fuzzSignedPayloadSeeds' return value follows.
var fuzzSignedPayloadKinds = [5]string{KindStatement, KindDelegation, KindAcceptance, KindGrant, KindCertificate}

// fuzzSignedPayloadSeeds returns one valid canonical payload per kind, in
// fuzzSignedPayloadKinds order, with the same field values as fixture() and
// TestPublicationGrant.
func fuzzSignedPayloadSeeds(f testing.TB) [5][]byte {
	f.Helper()
	admin, agent, issuer := fuzzSigner(f, 1), fuzzSigner(f, 2), fuzzSigner(f, 3)

	d := Delegation{Header: NewHeader(KindDelegation, KeyIdentity(admin.KeyID()), admin, fixedNow), AgentID: agentID, AgentKeyID: agent.KeyID(), AgentPublicKey: agent.PublicKey(), ServiceAudience: exampleIssuer, NotBefore: fixedNow.Format(TimestampLayout), ExpiresAt: fixedNow.Add(48 * time.Hour).Format(TimestampLayout), Scopes: []string{"sign_origin_statement"}}
	dPayload, err := Canonical(d)
	if err != nil {
		f.Fatalf("delegation payload: %v", err)
	}
	dEnv, err := admin.Sign(KindDelegation, d)
	if err != nil {
		f.Fatalf("signing delegation: %v", err)
	}
	dh, err := EnvelopeDigest(dEnv)
	if err != nil {
		f.Fatalf("delegation digest: %v", err)
	}

	a := Acceptance{Header: NewHeader(KindAcceptance, KeyIdentity(agent.KeyID()), agent, fixedNow), AgentID: agentID, DelegationSHA256: dh}
	aPayload, err := Canonical(a)
	if err != nil {
		f.Fatalf("acceptance payload: %v", err)
	}

	st := Statement{Header: NewHeader(KindStatement, KeyIdentity(agent.KeyID()), agent, fixedNow), AgentID: agentID, DelegationSHA256: dh, ArtifactSHA256: Hash([]byte("hello\n")), ArtifactSize: "6", ArtifactMediaType: "text/plain", Nonce: nonceID}
	stPayload, err := Canonical(st)
	if err != nil {
		f.Fatalf("statement payload: %v", err)
	}
	stEnv, err := agent.Sign(KindStatement, st)
	if err != nil {
		f.Fatalf("signing statement: %v", err)
	}
	sh, err := EnvelopeDigest(stEnv)
	if err != nil {
		f.Fatalf("statement digest: %v", err)
	}

	g := PublicationGrant{Header: NewHeader(KindGrant, KeyIdentity(admin.KeyID()), admin, fixedNow), StatementSHA256: sh, DelegationSHA256: dh, ServiceAudience: exampleIssuer, Visibility: "private", Purpose: "issue_origin_certificate", ExpiresAt: fixedNow.Add(5 * time.Minute).Format(TimestampLayout), Nonce: nonceID}
	gPayload, err := Canonical(g)
	if err != nil {
		f.Fatalf("grant payload: %v", err)
	}

	cert := Certificate{Header: NewHeader(KindCertificate, exampleIssuer, issuer, fixedNow.Add(time.Minute)), CertificateID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", StatementSHA256: sh, DelegationSHA256: dh, SourceKeyID: agent.KeyID(), ExpiresAt: fixedNow.Add(time.Minute + 24*time.Hour).Format(TimestampLayout), SignatureCheck: "valid", AgentBinding: "admin_key_delegation", OrganizationBinding: "unproven", ContentTruth: "not_established"}
	certPayload, err := Canonical(cert)
	if err != nil {
		f.Fatalf("certificate payload: %v", err)
	}

	// Order matches fuzzSignedPayloadKinds: statement, delegation, acceptance, grant, certificate.
	return [5][]byte{stPayload, dPayload, aPayload, gPayload, certPayload}
}

func FuzzSignedPayload(f *testing.F) {
	// Each kind is signed by the key its seed payload names (agent, admin,
	// agent, admin, issuer), so every seed starts on the accept path and
	// mutations explore that kind's field rules rather than a key mismatch.
	admin, agent, issuer := fuzzSigner(f, 1), fuzzSigner(f, 2), fuzzSigner(f, 3)
	signers := [5]*Signer{agent, admin, agent, admin, issuer}

	seeds := fuzzSignedPayloadSeeds(f)
	for i, payload := range seeds {
		if _, err := VerifyEnvelope(signRaw(f, signers[i], fuzzSignedPayloadKinds[i], payload)); err != nil {
			f.Fatalf("%s seed is not on the accept path: %v", fuzzSignedPayloadKinds[i], err)
		}
		matching := uint8(i)
		mismatching := uint8((i + 1) % len(fuzzSignedPayloadKinds))
		f.Add(matching, payload)
		f.Add(mismatching, payload)
	}

	f.Fuzz(func(t *testing.T, kind uint8, payload []byte) {
		if len(payload) == 0 || len(payload) > MaxInputBytes/2 {
			return
		}
		i := int(kind) % len(fuzzSignedPayloadKinds)
		k := fuzzSignedPayloadKinds[i]
		// A real signature over the arbitrary bytes puts the fuzzer past the
		// signature check and onto payload validation.
		env := signRaw(t, signers[i], k, payload)
		v, err := VerifyEnvelope(env)
		if err != nil {
			return
		}
		var value any
		if err := StrictJSON(payload, &value); err != nil {
			t.Fatalf("VerifyEnvelope accepted a payload StrictJSON rejects: %v\npayload: %s", err, payload)
		}
		c, err := Canonical(value)
		if err != nil {
			t.Fatalf("Canonical failed on a payload VerifyEnvelope accepted: %v\npayload: %s", err, payload)
		}
		if !bytes.Equal(c, payload) {
			t.Fatalf("VerifyEnvelope accepted a non-canonical payload:\naccepted: %s\ncanonical: %s", payload, c)
		}
		if v.Header.Kind != env.Kind {
			t.Fatalf("Header.Kind = %q, want %q (env.Kind)", v.Header.Kind, env.Kind)
		}
		if v.Header.IssuerKeyID != env.Signature.KeyID {
			t.Fatalf("Header.IssuerKeyID = %q, want %q (env.Signature.KeyID)", v.Header.IssuerKeyID, env.Signature.KeyID)
		}
	})
}
