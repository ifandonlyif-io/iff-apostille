package apostille

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Seeds are added before f.Fuzz, where only a *testing.F exists, so they are
// built through the public API rather than the *testing.T helpers in
// apostille_test.go.

// fuzzSigner is testSignerFor for a *testing.F.
func fuzzSigner(f testing.TB, protocol string, n byte) *Signer {
	f.Helper()
	return testSignerFor(f, protocol, n)
}

// fuzzConformanceFiles reads and decodes both versions' case files
// (testdata/apostille/core-0.1-cases.json, core-0.2-cases.json and
// core-0.3-cases.json) for
// seeding; they are never written to.
func fuzzConformanceFiles(f *testing.F) []conformanceFile {
	f.Helper()
	var files []conformanceFile
	for _, g := range []caseGen{gen01, gen02, gen03} {
		raw, err := os.ReadFile(g.casesPath())
		if err != nil {
			f.Fatalf("reading conformance cases: %v", err)
		}
		var file conformanceFile
		if err := json.Unmarshal(raw, &file); err != nil {
			f.Fatalf("decoding conformance cases: %v", err)
		}
		files = append(files, file)
	}
	return files
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
	for _, file := range fuzzConformanceFiles(f) {
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
	for _, file := range fuzzConformanceFiles(f) {
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
		// An accepted-protocols list only ever narrows acceptance, and the
		// result names the version the bundle declared.
		if err1 == nil {
			for _, protocol := range KnownProtocols() {
				v3, err3 := Verify(raw, VerifyOptions{AcceptedProtocols: []string{protocol}})
				if (err3 == nil) != (v1.Protocol == protocol) || (err3 == nil && v3.Protocol != protocol) {
					t.Fatalf("AcceptedProtocols [%s] gave err=%v for a %s bundle", protocol, err3, v1.Protocol)
				}
			}
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
func fuzzSignedPayloadSeeds(f testing.TB, g caseGen) [5][]byte {
	f.Helper()
	admin, agent, issuer := fuzzSigner(f, g.protocol, 1), fuzzSigner(f, g.protocol, 2), fuzzSigner(f, g.protocol, 3)

	d := Delegation{Header: g.header(KindDelegation, KeyIdentity(admin.KeyID()), admin, fixedNow), AgentID: agentID, AgentKeyID: agent.KeyID(), AgentPublicKey: agent.PublicKey(), ServiceAudience: exampleIssuer, NotBefore: fixedNow.Format(TimestampLayout), ExpiresAt: fixedNow.Add(48 * time.Hour).Format(TimestampLayout), Scopes: []string{"sign_origin_statement"}}
	dPayload, err := Canonical(d)
	if err != nil {
		f.Fatalf("delegation payload: %v", err)
	}
	dEnv, err := admin.SignFor(g.protocol, KindDelegation, d)
	if err != nil {
		f.Fatalf("signing delegation: %v", err)
	}
	dh, err := EnvelopeDigest(dEnv)
	if err != nil {
		f.Fatalf("delegation digest: %v", err)
	}

	a := Acceptance{Header: g.header(KindAcceptance, KeyIdentity(agent.KeyID()), agent, fixedNow), AgentID: agentID, DelegationSHA256: dh}
	aPayload, err := Canonical(a)
	if err != nil {
		f.Fatalf("acceptance payload: %v", err)
	}

	st := Statement{Header: g.header(KindStatement, KeyIdentity(agent.KeyID()), agent, fixedNow), AgentID: agentID, DelegationSHA256: dh, ArtifactSHA256: Hash([]byte("hello\n")), ArtifactSize: "6", ArtifactMediaType: "text/plain", Nonce: nonceID}
	stPayload, err := Canonical(st)
	if err != nil {
		f.Fatalf("statement payload: %v", err)
	}
	stEnv, err := agent.SignFor(g.protocol, KindStatement, st)
	if err != nil {
		f.Fatalf("signing statement: %v", err)
	}
	sh, err := EnvelopeDigest(stEnv)
	if err != nil {
		f.Fatalf("statement digest: %v", err)
	}

	grant := PublicationGrant{Header: g.header(KindGrant, KeyIdentity(admin.KeyID()), admin, fixedNow), StatementSHA256: sh, DelegationSHA256: dh, ServiceAudience: exampleIssuer, Visibility: "private", Purpose: "issue_origin_certificate", ExpiresAt: fixedNow.Add(5 * time.Minute).Format(TimestampLayout), Nonce: nonceID}
	gPayload, err := Canonical(grant)
	if err != nil {
		f.Fatalf("grant payload: %v", err)
	}

	cert := Certificate{Header: g.header(KindCertificate, exampleIssuer, issuer, fixedNow.Add(time.Minute)), CertificateID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", StatementSHA256: sh, DelegationSHA256: dh, SourceKeyID: agent.KeyID(), ExpiresAt: fixedNow.Add(time.Minute + 24*time.Hour).Format(TimestampLayout), SignatureCheck: "valid", AgentBinding: "admin_key_delegation", OrganizationBinding: "unproven", ContentTruth: "not_established"}
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
	// The version selector picks the protocol the payload is signed under.
	versions := [3]caseGen{gen01, gen02, gen03}
	var signers [3][5]*Signer
	for v, g := range versions {
		admin, agent, issuer := fuzzSigner(f, g.protocol, 1), fuzzSigner(f, g.protocol, 2), fuzzSigner(f, g.protocol, 3)
		signers[v] = [5]*Signer{agent, admin, agent, admin, issuer}
	}

	for v, g := range versions {
		seeds := fuzzSignedPayloadSeeds(f, g)
		for i, payload := range seeds {
			if _, err := VerifyEnvelope(g.signRaw(f, signers[v][i], fuzzSignedPayloadKinds[i], payload)); err != nil {
				f.Fatalf("%s %s seed is not on the accept path: %v", g.version(), fuzzSignedPayloadKinds[i], err)
			}
			matching := uint8(i)
			mismatching := uint8((i + 1) % len(fuzzSignedPayloadKinds))
			f.Add(uint8(v), matching, payload)
			f.Add(uint8(v), mismatching, payload)
		}
	}

	f.Fuzz(func(t *testing.T, version, kind uint8, payload []byte) {
		if len(payload) == 0 || len(payload) > MaxInputBytes/2 {
			return
		}
		vi := int(version) % len(versions)
		g := versions[vi]
		i := int(kind) % len(fuzzSignedPayloadKinds)
		k := fuzzSignedPayloadKinds[i]
		// A real signature over the arbitrary bytes puts the fuzzer past the
		// signature check and onto payload validation.
		env := g.signRaw(t, signers[vi][i], k, payload)
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
		if v.Header.Protocol != g.protocol {
			t.Fatalf("Header.Protocol = %q, want %q (the envelope's version)", v.Header.Protocol, g.protocol)
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzValidIssuer02
// ---------------------------------------------------------------------------

func FuzzValidIssuer02(f *testing.F) {
	for _, row := range identifierRows(f) {
		f.Add(row.value)
	}
	for _, file := range fuzzConformanceFiles(f) {
		for _, c := range file.IssuerCases {
			f.Add(c.Value)
		}
	}
	f.Fuzz(func(t *testing.T, value string) {
		if !ValidIssuer02(value) {
			return
		}
		if len(value) == 0 || len(value) > 256 {
			t.Fatalf("accepted length %d: %q", len(value), value)
		}
		for i := 0; i < len(value); i++ {
			c := value[i]
			if c <= 0x20 || c >= 0x7f || strings.IndexByte("%?#\\", c) >= 0 {
				t.Fatalf("accepted forbidden byte %#x in %q", c, value)
			}
		}
		if !strings.HasPrefix(value, "https://") && !strings.HasPrefix(value, "urn:") {
			t.Fatalf("accepted an unknown scheme: %q", value)
		}
		if strings.Contains(value, "@") && strings.HasPrefix(value, "https://") {
			host := value[len("https://"):]
			if end := strings.IndexByte(host, '/'); end >= 0 {
				host = host[:end]
			}
			if strings.Contains(host, "@") {
				t.Fatalf("accepted userinfo: %q", value)
			}
		}
		if strings.HasPrefix(value, "https://") {
			rest := value[len("https://"):]
			if end := strings.IndexByte(rest, '/'); end >= 0 {
				for _, segment := range strings.Split(rest[end+1:], "/") {
					if segment == "." || segment == ".." {
						t.Fatalf("accepted a dot segment: %q", value)
					}
				}
			}
		}
		// Acceptance is a property of the bytes alone and is stable.
		if !ValidIssuer02(string([]byte(value))) {
			t.Fatalf("verdict not stable for %q", value)
		}
	})
}
