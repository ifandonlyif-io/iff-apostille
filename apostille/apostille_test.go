package apostille

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)

const exampleIssuer = "https://issuer.example/apostille"
const agentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const nonceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

func testSigner(t *testing.T, n byte) *Signer {
	t.Helper()
	s, e := NewSigner(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func mustSign(t *testing.T, s *Signer, kind string, p any) Envelope {
	t.Helper()
	e, err := s.Sign(kind, p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func fixture(t *testing.T) (Bundle, *Signer, *Signer, *Signer) {
	t.Helper()
	admin, agent, issuer := testSigner(t, 1), testSigner(t, 2), testSigner(t, 3)
	d := Delegation{Header: NewHeader(KindDelegation, KeyIdentity(admin.KeyID()), admin, fixedNow), AgentID: agentID, AgentKeyID: agent.KeyID(), AgentPublicKey: agent.PublicKey(), ServiceAudience: exampleIssuer, NotBefore: fixedNow.Format(TimestampLayout), ExpiresAt: fixedNow.Add(48 * time.Hour).Format(TimestampLayout), Scopes: []string{"sign_origin_statement"}}
	de := mustSign(t, admin, KindDelegation, d)
	dh, _ := EnvelopeDigest(de)
	a := Acceptance{Header: NewHeader(KindAcceptance, KeyIdentity(agent.KeyID()), agent, fixedNow), AgentID: agentID, DelegationSHA256: dh}
	ae := mustSign(t, agent, KindAcceptance, a)
	st := Statement{Header: NewHeader(KindStatement, KeyIdentity(agent.KeyID()), agent, fixedNow), AgentID: agentID, DelegationSHA256: dh, ArtifactSHA256: Hash([]byte("hello\n")), ArtifactSize: "6", ArtifactMediaType: "text/plain", Nonce: nonceID}
	se := mustSign(t, agent, KindStatement, st)
	bundle, err := Issue(Bundle{Protocol: Protocol, Statement: se, Delegation: &de, Acceptance: &ae}, issuer, exampleIssuer, fixedNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return bundle, admin, agent, issuer
}
func TestIndependentIssuerAndTrust(t *testing.T) {
	b, _, _, issuer := fixture(t)
	raw, _ := Canonical(b)
	opts := VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{issuer.KeyID()}, Now: fixedNow.Add(time.Hour)}
	v, err := Verify(raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	if v.IssuerTrust != "accepted_by_policy" || v.ArtifactIntegrity != "valid" || v.ContentTruth != "not_established" || v.AuthorizationPolicy != "current_revocation_unknown" || !VerifyArtifact(v, []byte("hello\n")) {
		t.Fatalf("unexpected verification: %+v", v)
	}
	if VerifyArtifact(v, []byte("hello!")) {
		t.Fatal("substituted artifact matched")
	}
	for _, opts := range []VerifyOptions{{}, {TrustedKeyIDs: []string{issuer.KeyID()}}, {ExpectedIssuer: exampleIssuer}, {ExpectedIssuer: "https://ifandonlyif.io/apostille", TrustedKeyIDs: []string{issuer.KeyID()}}} {
		v, e := Verify(raw, opts)
		if e != nil || v.IssuerTrust == "accepted_by_policy" || v.Freshness != "unknown" {
			t.Fatalf("untrusted bundle accepted: %+v %v", v, e)
		}
	}
	opts.Now = fixedNow.Add(72 * time.Hour)
	v, err = Verify(raw, opts)
	if err != nil || v.ArtifactIntegrity != "valid" || v.Freshness != "expired" {
		t.Fatalf("history lost after expiry: %+v %v", v, err)
	}
}

func TestBundleFieldPresenceAndCase(t *testing.T) {
	b, _, _, _ := fixture(t)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	input["Protocol"] = input["protocol"]
	delete(input, "protocol")
	raw, _ = json.Marshal(input)
	if _, err := Verify(raw, VerifyOptions{}); err == nil {
		t.Fatal("case-insensitive outer field accepted")
	}
	input["protocol"] = input["Protocol"]
	delete(input, "Protocol")
	delete(input, "certificate")
	raw, _ = json.Marshal(input)
	if _, err := Verify(raw, VerifyOptions{}); err == nil {
		t.Fatal("missing explicit attachment accepted")
	}
}
func TestTamperingAndWrongBindings(t *testing.T) {
	b, admin, agent, issuer := fixture(t)
	t.Run("changed_payload", func(t *testing.T) {
		bad := b
		bad.Statement.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{}`))
		if _, err := VerifyBundle(bad, VerifyOptions{}); err == nil {
			t.Fatal("tamper accepted")
		}
	})
	t.Run("changed_signature_key", func(t *testing.T) {
		bad := b
		bad.Statement.Signature.PublicKey = admin.PublicKey()
		if _, err := VerifyBundle(bad, VerifyOptions{}); err == nil {
			t.Fatal("wrong key accepted")
		}
	})
	t.Run("other_statement", func(t *testing.T) {
		var st Statement
		_ = DecodePayload(b.Statement, KindStatement, &st)
		st.ArtifactSHA256 = Hash([]byte("substitute"))
		bad := b
		bad.Statement = mustSign(t, agent, KindStatement, st)
		if _, err := VerifyBundle(bad, VerifyOptions{}); err == nil {
			t.Fatal("certificate graft accepted")
		}
	})
	t.Run("no_pop", func(t *testing.T) {
		bad := b
		bad.Acceptance = nil
		if _, err := VerifyBundle(bad, VerifyOptions{}); err == nil {
			t.Fatal("missing PoP accepted")
		}
	})
	t.Run("different_service", func(t *testing.T) {
		b.Certificate = nil
		if _, err := Issue(b, issuer, "https://other.example/apostille", fixedNow.Add(time.Hour)); err == nil {
			t.Fatal("cross service delegation accepted")
		}
	})
	t.Run("domain", func(t *testing.T) {
		bad := b
		bad.Statement.Kind = KindCertificate
		if _, err := VerifyBundle(bad, VerifyOptions{}); err == nil {
			t.Fatal("cross kind accepted")
		}
	})
}
func TestPublicationGrant(t *testing.T) {
	b, admin, _, _ := fixture(t)
	sh, _ := EnvelopeDigest(b.Statement)
	dh, _ := EnvelopeDigest(*b.Delegation)
	g := PublicationGrant{Header: NewHeader(KindGrant, KeyIdentity(admin.KeyID()), admin, fixedNow), StatementSHA256: sh, DelegationSHA256: dh, ServiceAudience: exampleIssuer, Visibility: "private", Purpose: "issue_origin_certificate", ExpiresAt: fixedNow.Add(5 * time.Minute).Format(TimestampLayout), Nonce: nonceID}
	grant := mustSign(t, admin, KindGrant, g)
	if _, err := ValidateGrant(grant, b.Statement, *b.Delegation, admin.KeyID(), exampleIssuer, fixedNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		admin, audience string
		now             time.Time
	}{{admin.KeyID(), exampleIssuer, fixedNow.Add(time.Hour)}, {admin.KeyID(), "https://other.example", fixedNow}, {testSigner(t, 4).KeyID(), exampleIssuer, fixedNow}} {
		if _, err := ValidateGrant(grant, b.Statement, *b.Delegation, tc.admin, tc.audience, tc.now); err == nil {
			t.Fatal("invalid grant accepted")
		}
	}
}
func TestStrictJSONAndKeyMaterial(t *testing.T) {
	for _, raw := range []string{`{"x":1}`, `{"x":null,"x":true}`, `{"x":"\ud800"}`, `{"x":"\udc00"}`, `{"x":true} {}`, strings.Repeat("[", 26) + `true` + strings.Repeat("]", 26)} {
		var dst any
		if err := StrictJSON([]byte(raw), &dst); err == nil {
			t.Errorf("invalid JSON accepted: %s", raw)
		}
	}
	var dst any
	if err := StrictJSON([]byte("{\"x\":\"\xff\"}"), &dst); err == nil {
		t.Fatal("invalid UTF8 accepted")
	}
	if err := StrictJSON([]byte(`{"x":"\ud83d\ude80"}`), &dst); err != nil {
		t.Fatal(err)
	}
	s := testSigner(t, 1)
	key := append([]byte(nil), s.key...)
	key[63] ^= 1
	if _, err := NewSigner(base64.RawURLEncoding.EncodeToString(key)); err == nil {
		t.Fatal("inconsistent private key accepted")
	}
	b, _, _, _ := fixture(t)
	var st Statement
	_ = DecodePayload(b.Statement, KindStatement, &st)
	raw, _ := Canonical(st)
	raw = bytes.Replace(raw, []byte(`"delegation_sha256":"`+st.DelegationSHA256+`",`), nil, 1)
	if _, err := validatePayload(KindStatement, raw); err == nil {
		t.Fatal("missing required field accepted")
	}
}
func TestSelfIssuedCoreWithoutRegistration(t *testing.T) {
	s := testSigner(t, 4)
	st := Statement{Header: NewHeader(KindStatement, KeyIdentity(s.KeyID()), s, fixedNow), AgentID: agentID, ArtifactSHA256: Hash(nil), ArtifactSize: "0", ArtifactMediaType: "application/octet-stream", Nonce: nonceID}
	se := mustSign(t, s, KindStatement, st)
	b := Bundle{Protocol: Protocol, Statement: se}
	v, e := VerifyBundle(b, VerifyOptions{})
	if e != nil || v.CertificateScope != "producer_only" {
		t.Fatalf("%+v %v", v, e)
	}
	b, e = Issue(b, s, "urn:example:private-issuer", fixedNow)
	if e != nil {
		t.Fatal(e)
	}
	v, e = VerifyBundle(b, VerifyOptions{ExpectedIssuer: "urn:example:private-issuer", TrustedKeyIDs: []string{s.KeyID()}, Now: fixedNow})
	if e != nil || v.IssuerTrust != "accepted_by_policy" || v.AgentBinding != "not_provided" {
		t.Fatalf("%+v %v", v, e)
	}
}
func TestLoginPurposeSeparation(t *testing.T) {
	s := testSigner(t, 1)
	message := "iff-apostille/login/0.1\nhttps://service.example\nnonce"
	sig, e := s.SignChallenge(message)
	if e != nil || !VerifyChallenge(s.PublicKey(), message, sig) {
		t.Fatal(e)
	}
	if VerifyChallenge(s.PublicKey(), message+"changed", sig) || VerifyChallenge(s.PublicKey(), "iff-service-receipt/v1\nnonce", sig) {
		t.Fatal("cross-purpose signature accepted")
	}
}
func TestWriteInteroperabilityFixture(t *testing.T) {
	b, admin, agent, issuer := fixture(t)
	var c Certificate
	_ = DecodePayload(*b.Certificate, KindCertificate, &c)
	c.CertificateID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	ce := mustSign(t, issuer, KindCertificate, c)
	b.Certificate = &ce
	fixture := struct {
		Protocol       string `json:"protocol"`
		EvaluationTime string `json:"evaluation_time"`
		Issuer         string `json:"issuer"`
		IssuerKeyID    string `json:"issuer_key_id"`
		AdminPublicKey string `json:"admin_public_key"`
		AgentPublicKey string `json:"agent_public_key"`
		Artifact       string `json:"artifact"`
		Bundle         Bundle `json:"bundle"`
	}{Protocol, fixedNow.Add(time.Hour).Format(TimestampLayout), exampleIssuer, issuer.KeyID(), admin.PublicKey(), agent.PublicKey(), "hello\n", b}
	raw, e := json.MarshalIndent(fixture, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "testdata", "apostille", "core-0.1.json")
	if os.Getenv("UPDATE_APOSTILLE_FIXTURES") == "1" {
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	existing, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(existing, raw) {
		t.Fatal("fixture mismatch; run UPDATE_APOSTILLE_FIXTURES=1 go test ./apostille to regenerate")
	}
}
