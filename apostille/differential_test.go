package apostille

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Shared plumbing: corpus accumulation, node runner, known-divergence
// comparison. Both TestGoJSDifferential (envelope level) and
// TestGoJSStrictJSONDifferential (parser level) use these.
// ---------------------------------------------------------------------------

// diffRunNode runs one node --input-type=module -e <script> process (the
// interop_test.go shell-out pattern) and returns its stdout. stderr is
// captured separately so it never corrupts a JSON stdout payload.
func diffRunNode(t *testing.T, node, script string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(node, append([]string{"--input-type=module", "-e", script}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node failed: %v\nstderr: %s", err, stderr.String())
	}
	return out
}

// diffCheckUniqueStrings is a hard safety net: the corpus builders below
// disambiguate labels as they go, so a duplicate here means a real bug in
// this file, not an expected condition.
func diffCheckUniqueStrings(t *testing.T, labels []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, label := range labels {
		if seen[label] {
			t.Fatalf("duplicate corpus label: %s", label)
		}
		seen[label] = true
	}
}

// diffFindDivergences compares Go/JS accept verdicts against a
// known-divergences table (value = Go's verdict on a divergence: true means
// Go accepts and JS rejects, false means Go rejects and JS accepts) and
// returns a description of every unexpected divergence and every stale
// table entry, sorted for a deterministic report. It never stops at the
// first problem.
func diffFindDivergences(labels []string, goAccept, jsAccept []bool, known map[string]bool) []string {
	seenKnown := map[string]bool{}
	var problems []string
	for i, label := range labels {
		if goAccept[i] == jsAccept[i] {
			continue
		}
		want, ok := known[label]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: go=%v js=%v (NOT in known divergence table)", label, goAccept[i], jsAccept[i]))
			continue
		}
		seenKnown[label] = true
		if want != goAccept[i] {
			problems = append(problems, fmt.Sprintf("%s: go=%v js=%v (table says go=%v)", label, goAccept[i], jsAccept[i], want))
		}
	}
	for label := range known {
		if !seenKnown[label] {
			problems = append(problems, "stale known divergence (did not reproduce, or not in corpus): "+label)
		}
	}
	sort.Strings(problems)
	return problems
}

// diffSummary returns agreement and per-side accept counts over a verdict list.
func diffSummary(goAccept, jsAccept []bool) (agree, goAcceptN, jsAcceptN int) {
	for i := range goAccept {
		if goAccept[i] == jsAccept[i] {
			agree++
		}
		if goAccept[i] {
			goAcceptN++
		}
		if jsAccept[i] {
			jsAcceptN++
		}
	}
	return
}

// diffValueLabel renders v as compact JSON for a corpus label, truncated so
// labels stay readable; differentialCorpus.add disambiguates any collisions
// this truncation causes.
func diffValueLabel(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<unmarshalable:%v>", err)
	}
	s := string(raw)
	const max = 40
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

func diffToMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func diffCloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func diffStrings(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

// diffEnumValues returns the 4 standard enum-field probe values: a wrong
// value, the correct value in a different case, empty, and the correct
// value with a trailing space.
func diffEnumValues(validValue, wrongValue string) []string {
	return []string{wrongValue, strings.ToUpper(validValue), "", validValue + " "}
}

// diffB64URLAlphabet is the unpadded base64url alphabet in index order.
const diffB64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// diffFlipTrailingBits changes the last character of a canonical (unpadded)
// base64url string to a different character whose unused low bits are
// non-zero: it decodes to the SAME bytes under a lenient decoder, but this
// protocol requires base64.RawURLEncoding.Strict() everywhere, which
// requires those bits be zero. ok is false when the value's decoded byte
// length is a multiple of 3 (no unused bits in the last character at all,
// so flipping would silently change the decoded bytes instead of producing
// a non-canonical encoding of the same bytes) — verified empirically: for
// such lengths the flipped string still decodes successfully.
func diffFlipTrailingBits(canonical string) (flipped string, ok bool) {
	if canonical == "" {
		return "", false
	}
	last := canonical[len(canonical)-1]
	idx := strings.IndexByte(diffB64URLAlphabet, last)
	if idx < 0 {
		return "", false
	}
	out := canonical[:len(canonical)-1] + string(diffB64URLAlphabet[idx^0b01])
	if _, err := rawURL.DecodeString(out); err == nil {
		return "", false
	}
	return out, true
}

// ---------------------------------------------------------------------------
// Envelope-level differential corpus: dictionaries.
// ---------------------------------------------------------------------------

// diffIssuerValues are substituted into every issuer-like member: ordinary
// identifiers, each rule in core-0.1.md "Common values", and forms that URL
// parsers are known to treat differently (scheme case, IP literals, path
// punctuation, dot segments).
var diffIssuerValues = []string{
	"https://issuer.example/apostille",
	"https://issuer.example",
	"https://issuer.example/",
	"urn:example:private-issuer",
	"urn:x",
	"urn:",
	"urn:/x",
	"URN:example:x",
	"HTTPS://issuer.example/a",
	"Https://issuer.example/a",
	"https://Issuer.example/a",
	"https://issuer.example:443/a",
	"https://issuer.example:0444/a",
	"https://issuer.example:8443/a",
	"https://issuer.example:/a",
	"https://issuer.example:65536/a",
	"https://issuer.example:0/a",
	"https://issuer.example:80/a",
	"https://issuer.example/a%20b",
	"https://issuer.example/a\\b",
	"https://issuer.example/a?",
	"urn:test#",
	"http://issuer.example",
	"https://user@issuer.example/a",
	"https://user:pw@issuer.example/a",
	"https://@issuer.example/a",
	"https://[::1]/a",
	"https://[::1]:8443/a",
	"https://[0:0:0:0:0:0:0:1]/a",
	"https://[::ffff:1.2.3.4]/a",
	"https://127.0.0.1/a",
	"https://127.1/a",
	"https://0x7f.0.0.1/a",
	"https://2130706433/a",
	"https://0177.0.0.1/a",
	"https://issuer.example./a",
	"https://issuer..example/a",
	"https://issuer_example/a",
	"https://-issuer.example/a",
	"https://issuer.example/a/../b",
	"https://issuer.example/./a",
	"https://issuer.example//a",
	"https://issuer.example/a/",
	"https://issuer.example/a!b",
	"https://issuer.example/a*b",
	"https://issuer.example/a'b",
	"https://issuer.example/a(b)",
	"https://issuer.example/a|b",
	"https://issuer.example/a^b",
	"https://issuer.example/a[b]",
	"https://issuer.example/a{b}",
	"https://issuer.example/a\"b",
	"https://issuer.example/a<b>",
	"https://issuer.example/a`b",
	"https://issuer.example/a~b",
	"https://issuer.example/a$b",
	"https://issuer.example/a&b",
	"https://issuer.example/a+b",
	"https://issuer.example/a,b",
	"https://issuer.example/a;b",
	"https://issuer.example/a=b",
	"https://issuer.example/a:b",
	"https://issuer.example/a@b",
	"https:///a",
	"https://",
	"https:/issuer.example/a",
	"https:issuer.example",
	"//issuer.example/a",
	"issuer.example/a",
	"",
	" https://issuer.example/a",
	"https://issuer.example/a ",
	"https://issuer.example/é",
	"https://é.example/a",
	"https://xn--9ca.example/a",
	"https://issuer.example/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"https://issuer.example/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"urn:apostille:key:sha256:0000000000000000000000000000000000000000000000000000000000000000",
	"urn:example:a/b",
	"urn:example:a%41",
	"urn:EXAMPLE:x",
	"urn:example:x y",
	"ftp://issuer.example/a",
	"wss://issuer.example/a",
	"https://issuer.example:443",
	"https://issuer.example:08443/a",
	"https://issuer.example:+8443/a",
	"https://ISSUER.EXAMPLE:8443/a",
	"https://issuer.example/A",
	"https://1.2.3.4.5/a",
	"https://256.1.1.1/a",
}

// diffTimestampValues probes issued_at/not_before/expires_at-shaped members:
// valid neighbours of fixedNow plus the malformed variants the spec lists.
var diffTimestampValues = []string{
	"2026-09-13T00:00:00Z",
	"2026-09-13T00:00:01Z",
	"2026-09-12T23:59:59Z",
	"2026-09-13T00:00:00.000Z",
	"2026-09-13T00:00:00+00:00",
	"2026-02-30T00:00:00Z",
	"2026-09-13t00:00:00z",
	"2026-09-13T24:00:00Z",
	"2026-09-13T00:60:00Z",
	"2026-09-13T00:00:60Z",
	"2026-09-13 00:00:00Z",
	"2026-09-13T00:00:00",
	"0000-09-13T00:00:00Z",
	"9999-09-13T00:00:00Z",
	"20260-09-13T00:00:00Z",
	"2026-9-13T00:00:00Z",
	"",
}

// diffUUIDValues probes agent_id/nonce/certificate_id-shaped members, built
// from agentID (apostille_test.go) so lengths are correct by construction.
var diffUUIDValues = func() []string {
	base := agentID
	return []string{
		strings.ToUpper(base),
		strings.Replace(base, "-4aaa-", "-1aaa-", 1),
		strings.Replace(base, "-4aaa-", "-7aaa-", 1),
		strings.Replace(base, "-8aaa-", "-caaa-", 1),
		strings.ReplaceAll(base, "-", ""),
		"{" + base + "}",
		strings.Repeat("0", 8) + "-" + strings.Repeat("0", 4) + "-" + strings.Repeat("0", 4) + "-" + strings.Repeat("0", 4) + "-" + strings.Repeat("0", 12),
		base[:len(base)-1],
		base + "a",
		"",
	}
}()

// diffDigestKeyIDValues probes both plain 64-hex digest members
// (delegation_sha256, statement_sha256, artifact_sha256) and "sha256:"+hex
// key-id members (issuer_key_id, source_key_id, agent_key_id) with the same
// list: some combinations are obviously wrong for a given field shape, but
// that is a legitimate (if uninteresting) corpus item, not a harness bug.
var diffDigestKeyIDValues = func() []string {
	hex64 := strings.Repeat("a", 64)
	return []string{
		strings.ToUpper(hex64),
		hex64[:63],
		hex64 + "a",
		strings.Repeat("g", 64),
		hex64,
		"sha256:sha256:" + hex64,
		"SHA256:" + hex64,
		"",
	}
}()

var diffSizeValues = []string{
	"0",
	"00",
	"01",
	"-1",
	"+1",
	"1.0",
	"1e3",
	" 1",
	strings.Repeat("9", 19),
	strings.Repeat("9", 20),
	"",
}

var diffMediaTypeValues = []string{
	"textplain",
	"text/plain\nx",
	"text/plain\x00x",
	strings.Repeat("a", 64) + "/" + strings.Repeat("a", 63), // 128 bytes: the boundary itself
	strings.Repeat("a", 64) + "/" + strings.Repeat("a", 64), // 129 bytes
	strings.Repeat("é", 60) + "/x",                          // multi-byte UTF-8, under both byte and char limits (control)
	strings.Repeat("é", 70) + "/x",                          // 142 bytes but 72 chars: crosses the 128-BYTE limit while under 128 chars
	"",
	"/",
}

var diffScopesValues = []any{
	[]any{},
	[]any{"sign_origin_statement", "sign_origin_statement"},
	[]any{"wrong_scope"},
	"sign_origin_statement",
	[]any{[]any{"sign_origin_statement"}},
}

// diffAgentPublicKeyValues probes delegation's agent_public_key: wrong
// length, padded, non-canonical trailing bits, and standard-alphabet
// variants of the real agent key (a genuine key is needed so unrelated
// checks, like the delegated-key fingerprint match, do not mask the one
// under test).
func diffAgentPublicKeyValues(canonical string) []any {
	raw, err := rawURL.DecodeString(canonical)
	if err != nil || len(raw) == 0 {
		return nil
	}
	values := []any{rawURL.EncodeToString(raw[:len(raw)-1]), canonical + "="}
	if flipped, ok := diffFlipTrailingBits(canonical); ok {
		values = append(values, flipped)
	}
	if standard := strings.NewReplacer("-", "+", "_", "/").Replace(canonical); standard != canonical {
		values = append(values, standard)
	}
	return values
}

// ---------------------------------------------------------------------------
// Envelope-level differential corpus: per-kind member specs and fixtures.
// ---------------------------------------------------------------------------

type diffMemberSpec struct {
	name   string
	values []any
}

func diffHeaderMembers(kind string, issuerValues []any) []diffMemberSpec {
	return []diffMemberSpec{
		{"protocol", diffStrings(diffEnumValues(Protocol, "https://ifandonlyif.io/apostille/spec/0.2"))},
		{"kind", diffStrings(diffEnumValues(kind, kind+"2"))},
		{"issuer", issuerValues},
		{"issuer_key_id", diffStrings(diffDigestKeyIDValues)},
		{"issued_at", diffStrings(diffTimestampValues)},
	}
}

func diffStatementMembers() []diffMemberSpec {
	return append(diffHeaderMembers(KindStatement, nil),
		diffMemberSpec{"agent_id", diffStrings(diffUUIDValues)},
		diffMemberSpec{"delegation_sha256", diffStrings(diffDigestKeyIDValues)},
		diffMemberSpec{"artifact_sha256", diffStrings(diffDigestKeyIDValues)},
		diffMemberSpec{"artifact_size", diffStrings(diffSizeValues)},
		diffMemberSpec{"artifact_media_type", diffStrings(diffMediaTypeValues)},
		diffMemberSpec{"nonce", diffStrings(diffUUIDValues)},
	)
}

func diffDelegationMembers(agentPublicKey string) []diffMemberSpec {
	return append(diffHeaderMembers(KindDelegation, nil),
		diffMemberSpec{"agent_id", diffStrings(diffUUIDValues)},
		diffMemberSpec{"agent_key_id", diffStrings(diffDigestKeyIDValues)},
		diffMemberSpec{"agent_public_key", diffAgentPublicKeyValues(agentPublicKey)},
		diffMemberSpec{"service_audience", diffStrings(diffIssuerValues)},
		diffMemberSpec{"not_before", diffStrings(diffTimestampValues)},
		diffMemberSpec{"expires_at", diffStrings(diffTimestampValues)},
		diffMemberSpec{"scopes", diffScopesValues},
	)
}

func diffAcceptanceMembers() []diffMemberSpec {
	return append(diffHeaderMembers(KindAcceptance, nil),
		diffMemberSpec{"agent_id", diffStrings(diffUUIDValues)},
		diffMemberSpec{"delegation_sha256", diffStrings(diffDigestKeyIDValues)},
	)
}

func diffGrantMembers() []diffMemberSpec {
	return append(diffHeaderMembers(KindGrant, nil),
		diffMemberSpec{"statement_sha256", diffStrings(diffDigestKeyIDValues)},
		diffMemberSpec{"delegation_sha256", diffStrings(diffDigestKeyIDValues)},
		diffMemberSpec{"service_audience", diffStrings(diffIssuerValues)},
		diffMemberSpec{"visibility", diffStrings(diffEnumValues("private", "secret"))},
		diffMemberSpec{"purpose", diffStrings(diffEnumValues("issue_origin_certificate", "issue_other_certificate"))},
		diffMemberSpec{"expires_at", diffStrings(diffTimestampValues)},
		diffMemberSpec{"nonce", diffStrings(diffUUIDValues)},
	)
}

func diffCertificateMembers() []diffMemberSpec {
	return append(diffHeaderMembers(KindCertificate, diffStrings(diffIssuerValues)),
		diffMemberSpec{"certificate_id", diffStrings(diffUUIDValues)},
		diffMemberSpec{"statement_sha256", diffStrings(diffDigestKeyIDValues)},
		diffMemberSpec{"delegation_sha256", diffStrings(diffDigestKeyIDValues)},
		diffMemberSpec{"source_key_id", diffStrings(diffDigestKeyIDValues)},
		diffMemberSpec{"expires_at", diffStrings(diffTimestampValues)},
		diffMemberSpec{"signature_check", diffStrings(diffEnumValues("valid", "invalid"))},
		diffMemberSpec{"agent_binding", diffStrings(diffEnumValues("not_provided", "unknown"))},
		diffMemberSpec{"organization_binding", diffStrings(diffEnumValues("unproven", "verified"))},
		diffMemberSpec{"content_truth", diffStrings(diffEnumValues("not_established", "established"))},
	)
}

// diffKindFixture holds one kind's base payload (map[string]any, ready for
// member substitution) and the signer that must re-sign it after every
// mutation, so only payload rules — never the signature — decide acceptance.
type diffKindFixture struct {
	kind    string
	base    map[string]any
	signer  *Signer
	members []diffMemberSpec
}

// diffKindFixtures builds one valid payload per Kind from the same fixtures
// conformance_cases_test.go uses (fixedBundle's delegated statement/
// delegation/acceptance, a grant built like TestPublicationGrant, and a
// producer-only self-issued certificate built like
// bundleCertificateIssuerSyntaxCases), so the corpus starts from bytes this
// codebase already trusts.
func diffKindFixtures(t *testing.T) []diffKindFixture {
	t.Helper()
	b, admin, agent, _ := fixedBundle(t)

	var st Statement
	if err := DecodePayload(b.Statement, KindStatement, &st); err != nil {
		t.Fatal(err)
	}
	var deleg Delegation
	if err := DecodePayload(*b.Delegation, KindDelegation, &deleg); err != nil {
		t.Fatal(err)
	}
	var acc Acceptance
	if err := DecodePayload(*b.Acceptance, KindAcceptance, &acc); err != nil {
		t.Fatal(err)
	}

	sh, err := EnvelopeDigest(b.Statement)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := EnvelopeDigest(*b.Delegation)
	if err != nil {
		t.Fatal(err)
	}
	grant := PublicationGrant{Header: NewHeader(KindGrant, KeyIdentity(admin.KeyID()), admin, fixedNow), StatementSHA256: sh, DelegationSHA256: dh, ServiceAudience: exampleIssuer, Visibility: "private", Purpose: "issue_origin_certificate", ExpiresAt: fixedNow.Add(5 * time.Minute).Format(TimestampLayout), Nonce: nonceID}

	pOnly, signer4 := producerOnly(t)
	cert := certFor(t, pOnly, signer4, "urn:example:private-issuer", fixedNow, fixedNow.Add(24*time.Hour), "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")

	return []diffKindFixture{
		{KindStatement, diffToMap(t, st), agent, diffStatementMembers()},
		{KindDelegation, diffToMap(t, deleg), admin, diffDelegationMembers(agent.PublicKey())},
		{KindAcceptance, diffToMap(t, acc), agent, diffAcceptanceMembers()},
		{KindGrant, diffToMap(t, grant), admin, diffGrantMembers()},
		{KindCertificate, diffToMap(t, cert), signer4, diffCertificateMembers()},
	}
}

// differentialItem is one entry in the Go<->JS envelope-verification corpus.
type differentialItem struct {
	Label    string   `json:"label"`
	Kind     string   `json:"kind"`
	Envelope Envelope `json:"envelope"`
}

// differentialCorpus accumulates items and disambiguates any label that
// would otherwise collide (e.g. two dictionary values that truncate to the
// same label text) by appending #2, #3, ...
type differentialCorpus struct {
	items      []differentialItem
	labelCount map[string]int
}

func (c *differentialCorpus) add(label, kind string, env Envelope) {
	if c.labelCount == nil {
		c.labelCount = map[string]int{}
	}
	c.labelCount[label]++
	if n := c.labelCount[label]; n > 1 {
		label = fmt.Sprintf("%s#%d", label, n)
	}
	c.items = append(c.items, differentialItem{Label: label, Kind: kind, Envelope: env})
}

func (c *differentialCorpus) addSigned(t *testing.T, label, kind string, signer *Signer, payload map[string]any) {
	t.Helper()
	raw, err := Canonical(payload)
	if err != nil {
		t.Fatalf("%s: Canonical: %v", label, err)
	}
	c.add(label, kind, signRaw(t, signer, kind, raw))
}

// ---------------------------------------------------------------------------
// Envelope-level differential corpus: builders.
// ---------------------------------------------------------------------------

// diffPayloadSubstitutionItems builds, for each kind and each payload
// member: one item per dictionary value (plus, for every string member,
// true/null/[]/{} wrong-JSON-type probes), one item with the member removed,
// and one item with an unknown "zzz" member added. Every item is re-signed
// over its exact mutated bytes, so the signature is always valid and only
// payload validation decides acceptance.
func diffPayloadSubstitutionItems(t *testing.T) []differentialItem {
	t.Helper()
	var corpus differentialCorpus
	for _, kf := range diffKindFixtures(t) {
		corpus.addSigned(t, kf.kind+"/baseline", kf.kind, kf.signer, diffCloneMap(kf.base))

		for _, member := range kf.members {
			if _, ok := kf.base[member.name]; !ok {
				t.Fatalf("diffPayloadSubstitutionItems: %s has no member %q", kf.kind, member.name)
			}
			values := member.values
			if member.name != "scopes" {
				values = append(append([]any{}, values...), true, nil, []any{}, map[string]any{})
			}
			for _, value := range values {
				m := diffCloneMap(kf.base)
				m[member.name] = value
				label := fmt.Sprintf("%s/%s=%s", kf.kind, member.name, diffValueLabel(value))
				corpus.addSigned(t, label, kf.kind, kf.signer, m)
			}

			removed := diffCloneMap(kf.base)
			delete(removed, member.name)
			corpus.addSigned(t, fmt.Sprintf("%s/%s=<removed>", kf.kind, member.name), kf.kind, kf.signer, removed)
		}

		withExtra := diffCloneMap(kf.base)
		withExtra["zzz"] = "x"
		corpus.addSigned(t, kf.kind+"/zzz=<added>", kf.kind, kf.signer, withExtra)
	}
	return corpus.items
}

// diffEnvelopeMutationItems builds envelope-transport-level mutations (as
// opposed to payload-content mutations) on an otherwise-valid envelope per
// kind: non-canonical base64url, padding, the standard base64 alphabet,
// key_id case, kind identity, payload_sha256 case, and algorithm spelling.
func diffEnvelopeMutationItems(t *testing.T) []differentialItem {
	t.Helper()
	var corpus differentialCorpus
	for _, kf := range diffKindFixtures(t) {
		payload, err := Canonical(kf.base)
		if err != nil {
			t.Fatalf("%s: Canonical: %v", kf.kind, err)
		}
		base := signRaw(t, kf.signer, kf.kind, payload)

		if flipped, ok := diffFlipTrailingBits(base.Payload); ok {
			env := base
			env.Payload = flipped
			corpus.add(kf.kind+"/envelope.payload=noncanonical-trailing-bits", kf.kind, env)
		}
		if flipped, ok := diffFlipTrailingBits(base.Signature.Value); ok {
			env := base
			env.Signature.Value = flipped
			corpus.add(kf.kind+"/envelope.signature.value=noncanonical-trailing-bits", kf.kind, env)
		}
		if flipped, ok := diffFlipTrailingBits(base.Signature.PublicKey); ok {
			env := base
			env.Signature.PublicKey = flipped
			corpus.add(kf.kind+"/envelope.signature.public_key=noncanonical-trailing-bits", kf.kind, env)
		}

		{
			env := base
			env.Payload += "="
			corpus.add(kf.kind+"/envelope.payload=padded", kf.kind, env)
		}
		{
			env := base
			env.Signature.Value += "="
			corpus.add(kf.kind+"/envelope.signature.value=padded", kf.kind, env)
		}
		{
			env := base
			env.Signature.PublicKey += "="
			corpus.add(kf.kind+"/envelope.signature.public_key=padded", kf.kind, env)
		}

		flip := strings.NewReplacer("-", "+", "_", "/")
		if v := flip.Replace(base.Payload); v != base.Payload {
			env := base
			env.Payload = v
			corpus.add(kf.kind+"/envelope.payload=standard-alphabet", kf.kind, env)
		}
		if v := flip.Replace(base.Signature.Value); v != base.Signature.Value {
			env := base
			env.Signature.Value = v
			corpus.add(kf.kind+"/envelope.signature.value=standard-alphabet", kf.kind, env)
		}
		if v := flip.Replace(base.Signature.PublicKey); v != base.Signature.PublicKey {
			env := base
			env.Signature.PublicKey = v
			corpus.add(kf.kind+"/envelope.signature.public_key=standard-alphabet", kf.kind, env)
		}

		{
			env := base
			env.Signature.KeyID = "sha256:" + strings.ToUpper(strings.TrimPrefix(base.Signature.KeyID, "sha256:"))
			corpus.add(kf.kind+"/envelope.signature.key_id=uppercase-hex", kf.kind, env)
		}

		for _, tc := range []struct{ suffix, value string }{
			{"unknown", kf.kind + "2"},
			{"empty", ""},
			{"65-chars", strings.Repeat("x", 65)},
		} {
			env := base
			env.Kind = tc.value
			corpus.add(fmt.Sprintf("%s/envelope.kind=%s", kf.kind, tc.suffix), env.Kind, env)
		}

		{
			env := base
			env.PayloadSHA256 = strings.ToUpper(base.PayloadSHA256)
			corpus.add(kf.kind+"/envelope.payload_sha256=uppercase", kf.kind, env)
		}

		for _, tc := range []struct{ suffix, value string }{
			{"lowercase", "ed25519"},
			{"EdDSA", "EdDSA"},
		} {
			env := base
			env.Signature.Algorithm = tc.value
			corpus.add(fmt.Sprintf("%s/envelope.signature.algorithm=%s", kf.kind, tc.suffix), kf.kind, env)
		}
	}
	return corpus.items
}

// ---------------------------------------------------------------------------
// Envelope-level differential corpus: Ed25519 edge cases.
// ---------------------------------------------------------------------------

// The four odd public keys below are 32-byte Ed25519 point encodings that a
// real Signer never produces. Their derivation (RFC 8032 compressed point
// format: little-endian y with the sign of x in the top bit of the last
// byte; p = 2^255-19):
//   - identity: y=1, x=0 -> canonical LE encoding 01 00...00
//   - non-canonical identity: y encoded as p+1 (unreduced) instead of 1 ->
//     LE encoding EE FF...FF 7F (same field element, non-canonical form)
//   - identity with a spurious x-sign bit: the canonical identity encoding
//     with the top bit of the last byte forced to 1 -> 01 00...00 80
//   - order-2 point: y=p-1 (i.e. -1 mod p), x=0 -> LE encoding EC FF...FF 7F
var (
	diffIdentityKey             = append([]byte{0x01}, make([]byte, 31)...)
	diffNonCanonicalIdentityKey = append(append([]byte{0xEE}, bytes.Repeat([]byte{0xFF}, 30)...), 0x7F)
	diffXSignIdentityKey        = append(append([]byte{0x01}, make([]byte, 30)...), 0x80)
	diffOrder2Key               = append(append([]byte{0xEC}, bytes.Repeat([]byte{0xFF}, 30)...), 0x7F)
)

// diffEd25519EdgeCaseLabels lists, in construction order, the labels
// diffEd25519EdgeCaseItems produces, for the dedicated per-case verdict log.
var diffEd25519EdgeCaseLabels = []string{
	"ed25519/identity-key-identity-sig",
	"ed25519/noncanonical-identity-key-identity-sig",
	"ed25519/identity-x-sign-bit-key-identity-sig",
	"ed25519/order2-key-identity-sig",
	"ed25519/order2-key-order2-sig",
	"ed25519/genuine-key-s-plus-l",
	"ed25519/genuine-key-r-identity-s-zero",
	"ed25519/genuine-key-r-identity-valid-s",
}

// diffOddKeyStatement builds a validly-STRUCTURED (but not validly-signed in
// the normal sense) origin-statement envelope whose issuer/issuer_key_id
// match pubKey's own fingerprint, so the fingerprint and signed-key-ID
// checks pass and only the Ed25519 verification math decides acceptance.
func diffOddKeyStatement(t *testing.T, pubKey, signature []byte) Envelope {
	t.Helper()
	keyID := Fingerprint(pubKey)
	st := Statement{
		Header:            Header{Protocol: Protocol, Kind: KindStatement, Issuer: KeyIdentity(keyID), IssuerKeyID: keyID, IssuedAt: fixedNow.Format(TimestampLayout)},
		AgentID:           agentID,
		ArtifactSHA256:    Hash(nil),
		ArtifactSize:      "0",
		ArtifactMediaType: "application/octet-stream",
		Nonce:             nonceID,
	}
	payload, err := Canonical(st)
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{
		Protocol:      Protocol,
		Kind:          KindStatement,
		Payload:       rawURL.EncodeToString(payload),
		PayloadSHA256: Hash(payload),
		Signature:     Signature{Algorithm: Algorithm, KeyID: keyID, PublicKey: rawURL.EncodeToString(pubKey), Value: rawURL.EncodeToString(signature)},
	}
}

// diffEd25519EdgeCaseItems builds the six Ed25519 edge cases from the spec:
// four "R=identity, S=0" forgery attempts against odd public keys (a classic
// low-order-point verification bypass: the equation [8]S[B] = [8]R + [8]kA
// degenerates to identity = identity for these keys, for ANY message), plus
// two mutations of a GENUINE key's genuine signature (S+L scalar
// malleability, reusing bundleSignatureMalleabilityCases's technique via the
// shared ed25519GroupOrder/reverseBytes; and R replaced with identity, S=0,
// which should NOT verify against a real full-order key except with
// negligible probability).
func diffEd25519EdgeCaseItems(t *testing.T) []differentialItem {
	t.Helper()
	var corpus differentialCorpus

	identitySig := append(append([]byte{}, diffIdentityKey...), make([]byte, 32)...)

	corpus.add(diffEd25519EdgeCaseLabels[0], KindStatement, diffOddKeyStatement(t, diffIdentityKey, identitySig))
	corpus.add(diffEd25519EdgeCaseLabels[1], KindStatement, diffOddKeyStatement(t, diffNonCanonicalIdentityKey, identitySig))
	corpus.add(diffEd25519EdgeCaseLabels[2], KindStatement, diffOddKeyStatement(t, diffXSignIdentityKey, identitySig))
	corpus.add(diffEd25519EdgeCaseLabels[3], KindStatement, diffOddKeyStatement(t, diffOrder2Key, identitySig))
	// For an order-2 key, S=0 verifies with R=identity when the challenge
	// scalar is even and with R=key when it is odd, so both forms are kept.
	order2Sig := append(append([]byte{}, diffOrder2Key...), make([]byte, 32)...)
	corpus.add(diffEd25519EdgeCaseLabels[4], KindStatement, diffOddKeyStatement(t, diffOrder2Key, order2Sig))

	genuineBundle, genuineSigner := producerOnly(t)
	genuineSig, err := rawURL.DecodeString(genuineBundle.Statement.Signature.Value)
	if err != nil {
		t.Fatal(err)
	}
	order, ok := new(big.Int).SetString(ed25519GroupOrder, 10)
	if !ok {
		t.Fatal("invalid Ed25519 group order constant")
	}
	scalar := new(big.Int).Add(new(big.Int).SetBytes(reverseBytes(genuineSig[32:])), order)
	malleated := append(append([]byte{}, genuineSig[:32]...), reverseBytes(scalar.FillBytes(make([]byte, 32)))...)
	if bytes.Equal(malleated, genuineSig) {
		t.Fatal("ed25519/genuine-key-s-plus-l: malleation did not change the signature")
	}
	splusL := genuineBundle.Statement
	splusL.Signature.Value = rawURL.EncodeToString(malleated)
	corpus.add(diffEd25519EdgeCaseLabels[5], KindStatement, splusL)

	rIdentityGenuine := genuineBundle.Statement
	rIdentityGenuine.Signature.Value = rawURL.EncodeToString(identitySig)
	corpus.add(diffEd25519EdgeCaseLabels[6], KindStatement, rIdentityGenuine)

	// A signer that holds a can pair R = identity with S = k*a mod L, where
	// k = SHA-512(R || A || M) mod L: [S]B = O + [k]A, so an RFC 8032
	// cofactorless verifier accepts it. No honest signer emits this (S reveals
	// a), but a verifier that checks A and forgets R would accept it.
	seed := genuineSigner.key[:ed25519.SeedSize]
	digest := sha512.Sum512(seed)
	clamped := append([]byte{}, digest[:32]...)
	clamped[0] &= 248
	clamped[31] &= 63
	clamped[31] |= 64
	a := new(big.Int).SetBytes(reverseBytes(clamped))
	payload, err := rawURL.DecodeString(genuineBundle.Statement.Payload)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := rawURL.DecodeString(genuineBundle.Statement.Signature.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	message := signingInput(KindStatement, payload)
	kDigest := sha512.Sum512(append(append(append([]byte{}, diffIdentityKey...), pub...), message...))
	k := new(big.Int).Mod(new(big.Int).SetBytes(reverseBytes(kDigest[:])), order)
	scalarS := new(big.Int).Mod(new(big.Int).Mul(k, a), order)
	validIdentitySig := append(append([]byte{}, diffIdentityKey...), reverseBytes(scalarS.FillBytes(make([]byte, 32)))...)
	if !ed25519.Verify(ed25519.PublicKey(pub), message, validIdentitySig) {
		t.Fatal("ed25519/genuine-key-r-identity-valid-s: construction does not verify under crypto/ed25519")
	}
	rIdentityValid := genuineBundle.Statement
	rIdentityValid.Signature.Value = rawURL.EncodeToString(validIdentitySig)
	corpus.add(diffEd25519EdgeCaseLabels[7], KindStatement, rIdentityValid)

	return corpus.items
}

// ---------------------------------------------------------------------------
// TestGoJSDifferential
// ---------------------------------------------------------------------------

// knownDivergences lists every envelope on which the two reference verifiers
// currently disagree, keyed by corpus label; the value is Go's verdict (true:
// Go accepts and JS rejects). The table is exact: an unlisted divergence fails
// the test, and so does an entry that stops diverging. All of them come from
// identifier syntax, which core-0.1.md describes in prose and each side
// implements with its own URL parser. Resolving one is a specification
// decision; neither verifier is assumed to be the correct one.
var knownDivergences = map[string]bool{
	// Uppercase URN scheme: net/url lowercases the scheme before ValidIssuer
	// compares it; validIssuer tests the literal prefix "urn:".
	`agent-delegation/service_audience="URN:example:x"`:  true,
	`origin-certificate/issuer="URN:example:x"`:          true,
	`publication-grant/service_audience="URN:example:x"`: true,

	// Non-canonical IP-literal hosts: net/url keeps Host as opaque text; the
	// WHATWG parser canonicalizes or refuses these literals, and validIssuer
	// requires the parsed host to equal the original text.
	`agent-delegation/service_audience="https://0177.0.0.1/a"`:         true,
	`agent-delegation/service_audience="https://0x7f.0.0.1/a"`:         true,
	`agent-delegation/service_audience="https://1.2.3.4.5/a"`:          true,
	`agent-delegation/service_audience="https://127.1/a"`:              true,
	`agent-delegation/service_audience="https://2130706433/a"`:         true,
	`agent-delegation/service_audience="https://256.1.1.1/a"`:          true,
	`agent-delegation/service_audience="https://[0:0:0:0:0:0:0:1]/a"`:  true,
	`agent-delegation/service_audience="https://[::ffff:1.2.3.4]/a"`:   true,
	`origin-certificate/issuer="https://0177.0.0.1/a"`:                 true,
	`origin-certificate/issuer="https://0x7f.0.0.1/a"`:                 true,
	`origin-certificate/issuer="https://1.2.3.4.5/a"`:                  true,
	`origin-certificate/issuer="https://127.1/a"`:                      true,
	`origin-certificate/issuer="https://2130706433/a"`:                 true,
	`origin-certificate/issuer="https://256.1.1.1/a"`:                  true,
	`origin-certificate/issuer="https://[0:0:0:0:0:0:0:1]/a"`:          true,
	`origin-certificate/issuer="https://[::ffff:1.2.3.4]/a"`:           true,
	`publication-grant/service_audience="https://0177.0.0.1/a"`:        true,
	`publication-grant/service_audience="https://0x7f.0.0.1/a"`:        true,
	`publication-grant/service_audience="https://1.2.3.4.5/a"`:         true,
	`publication-grant/service_audience="https://127.1/a"`:             true,
	`publication-grant/service_audience="https://2130706433/a"`:        true,
	`publication-grant/service_audience="https://256.1.1.1/a"`:         true,
	`publication-grant/service_audience="https://[0:0:0:0:0:0:0:1]/a"`: true,
	`publication-grant/service_audience="https://[::ffff:1.2.3.4]/a"`:  true,

	// Path punctuation ! * ' ( ) | ^ [ ]: ValidIssuer requires an empty
	// RawPath, which net/url sets whenever its own escaping would rewrite the
	// path; validIssuer only refuses percent escapes.
	`agent-delegation/service_audience="https://issuer.example/a!b"`:   false,
	`agent-delegation/service_audience="https://issuer.example/a'b"`:   false,
	`agent-delegation/service_audience="https://issuer.example/a(b)"`:  false,
	`agent-delegation/service_audience="https://issuer.example/a*b"`:   false,
	`agent-delegation/service_audience="https://issuer.example/a[b]"`:  false,
	`agent-delegation/service_audience="https://issuer.example/a^b"`:   false,
	`agent-delegation/service_audience="https://issuer.example/a|b"`:   false,
	`origin-certificate/issuer="https://issuer.example/a!b"`:           false,
	`origin-certificate/issuer="https://issuer.example/a'b"`:           false,
	`origin-certificate/issuer="https://issuer.example/a(b)"`:          false,
	`origin-certificate/issuer="https://issuer.example/a*b"`:           false,
	`origin-certificate/issuer="https://issuer.example/a[b]"`:          false,
	`origin-certificate/issuer="https://issuer.example/a^b"`:           false,
	`origin-certificate/issuer="https://issuer.example/a|b"`:           false,
	`publication-grant/service_audience="https://issuer.example/a!b"`:  false,
	`publication-grant/service_audience="https://issuer.example/a'b"`:  false,
	`publication-grant/service_audience="https://issuer.example/a(b)"`: false,
	`publication-grant/service_audience="https://issuer.example/a*b"`:  false,
	`publication-grant/service_audience="https://issuer.example/a[b]"`: false,
	`publication-grant/service_audience="https://issuer.example/a^b"`:  false,
	`publication-grant/service_audience="https://issuer.example/a|b"`:  false,
}

func TestGoJSDifferential(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for Go/JS differential testing")
	}

	var items []differentialItem
	items = append(items, diffPayloadSubstitutionItems(t)...)
	items = append(items, diffEnvelopeMutationItems(t)...)
	edStart := len(items)
	items = append(items, diffEd25519EdgeCaseItems(t)...)

	labels := make([]string, len(items))
	for i, it := range items {
		labels[i] = it.Label
	}
	diffCheckUniqueStrings(t, labels)

	goAccept := make([]bool, len(items))
	for i, item := range items {
		_, err := VerifyEnvelope(item.Envelope)
		goAccept[i] = err == nil
	}

	file := filepath.Join(t.TempDir(), "envelopes.json")
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}

	script := `import { readFile } from 'node:fs/promises';
import { verifyEnvelope } from '../web/apostille-core.mjs';
const items = JSON.parse(await readFile(process.argv[1], 'utf8'));
const results = [];
for (const item of items) {
  try { await verifyEnvelope(item.envelope, item.kind); results.push(true); }
  catch { results.push(false); }
}
process.stdout.write(JSON.stringify(results));`

	out := diffRunNode(t, node, script, file)
	var jsAccept []bool
	if err := json.Unmarshal(out, &jsAccept); err != nil {
		t.Fatalf("parsing node output: %v\noutput: %s", err, out)
	}
	if len(jsAccept) != len(items) {
		t.Fatalf("node returned %d results for %d items", len(jsAccept), len(items))
	}

	agree, goN, jsN := diffSummary(goAccept, jsAccept)
	t.Logf("envelope corpus=%d agree=%d known_divergences=%d go_accept=%d/%d js_accept=%d/%d",
		len(items), agree, len(knownDivergences), goN, len(items), jsN, len(items))

	for i := edStart; i < len(items); i++ {
		t.Logf("ed25519 edge case %s: go=%v js=%v", items[i].Label, goAccept[i], jsAccept[i])
	}

	if problems := diffFindDivergences(labels, goAccept, jsAccept, knownDivergences); len(problems) > 0 {
		t.Errorf("%d unexpected divergence(s) or stale table entries:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}

// ---------------------------------------------------------------------------
// Strict-JSON-level differential corpus.
// ---------------------------------------------------------------------------

type diffStrictItem struct {
	Label string
	Raw   []byte
}

// diffFixtureStrictItems replays every non-generated strict_json_cases input
// from testdata/apostille/core-0.1-cases.json.
func diffFixtureStrictItems(t *testing.T) []diffStrictItem {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "apostille", "core-0.1-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file conformanceFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var items []diffStrictItem
	for _, c := range file.StrictJSONCases {
		if c.InputGen != nil || c.InputB64 == nil {
			continue
		}
		decoded, err := rawURL.DecodeString(*c.InputB64)
		if err != nil {
			t.Fatalf("fixture strict_json_cases[%s]: %v", c.Name, err)
		}
		items = append(items, diffStrictItem{"fixture/" + c.Name, decoded})
	}
	return items
}

// diffSurrogateMatrixItems places each probe UTF-16 surrogate sequence both
// inside a string VALUE and inside a member NAME.
func diffSurrogateMatrixItems() []diffStrictItem {
	seqs := []struct {
		suffix string
		seq    []byte
	}{
		{"lone-high-d800", jsonUnicodeEscape("d800")},
		{"lone-high-dbff", jsonUnicodeEscape("dbff")},
		{"lone-low-dc00", jsonUnicodeEscape("dc00")},
		{"lone-low-dfff", jsonUnicodeEscape("dfff")},
		{"high-low-valid-pair", append(jsonUnicodeEscape("d83d"), jsonUnicodeEscape("de00")...)},
		{"low-high-reversed", append(jsonUnicodeEscape("dc00"), jsonUnicodeEscape("d800")...)},
		{"high-high", append(jsonUnicodeEscape("d800"), jsonUnicodeEscape("d800")...)},
		{"low-low", append(jsonUnicodeEscape("dc00"), jsonUnicodeEscape("dc00")...)},
		{"high-then-bmp-escape", append(jsonUnicodeEscape("d800"), jsonUnicodeEscape("0041")...)},
		{"high-then-literal-A", append(jsonUnicodeEscape("d800"), 'A')},
		{"low-then-literal-A", append(jsonUnicodeEscape("dc00"), 'A')},
		{"valid-pair-then-lone-high", append(append(jsonUnicodeEscape("d83d"), jsonUnicodeEscape("de00")...), jsonUnicodeEscape("d800")...)},
	}
	var items []diffStrictItem
	for _, s := range seqs {
		items = append(items,
			diffStrictItem{"surrogate/value/" + s.suffix, append(append([]byte(`{"x":"`), s.seq...), []byte(`"}`)...)},
			diffStrictItem{"surrogate/name/" + s.suffix, append(append([]byte(`{"`), s.seq...), []byte(`":true}`)...)},
		)
	}
	return items
}

func diffEscapeCases() []diffStrictItem {
	q := func(inner []byte) []byte { return append(append([]byte(`{"x":"`), inner...), []byte(`"}`)...) }
	return []diffStrictItem{
		{"escape/u0000", q(jsonUnicodeEscape("0000"))},
		{"escape/u001f", q(jsonUnicodeEscape("001f"))},
		{"escape/u007f", q(jsonUnicodeEscape("007f"))},
		{"escape/u0020-escaped-space", q(jsonUnicodeEscape("0020"))},
		{"escape/literal-space", q([]byte(" "))},
		{"escape/uppercase-hex-e9", q(jsonUnicodeEscape("00E9"))},
		{"escape/lowercase-hex-e9", q(jsonUnicodeEscape("00e9"))},
		{"escape/x41-invalid", q([]byte{backslash, 'x', '4', '1'})},
		{"escape/bell-invalid", q([]byte{backslash, 'a'})},
		{"escape/single-quote-invalid", q([]byte{backslash, '\''})},
		{"escape/lone-trailing-backslash", append([]byte(`{"x":"abc`), backslash)},
		{"escape/u12-short", q([]byte{backslash, 'u', '1', '2'})},
		{"escape/u12G4-bad-hex", q([]byte{backslash, 'u', '1', '2', 'G', '4'})},
	}
}

func diffLiteralUTF8Cases() []diffStrictItem {
	q := func(inner []byte) []byte { return append(append([]byte(`{"x":"`), inner...), []byte(`"}`)...) }
	return []diffStrictItem{
		{"literal/u2028-line-separator", q([]byte{0xE2, 0x80, 0xA8})},
		{"literal/u2029-paragraph-separator", q([]byte{0xE2, 0x80, 0xA9})},
		{"literal/ufeff-bom-inside-string", q(append(append([]byte("a"), 0xEF, 0xBB, 0xBF), 'b'))},
		{"literal/ufffd-replacement-char", q([]byte{0xEF, 0xBF, 0xBD})},
		{"literal/4byte-astral", q([]byte{0xF0, 0x9F, 0x9A, 0x80})},
		{"literal/overlong-utf8-c080", q([]byte{0xC0, 0x80})},
		{"literal/cesu8-surrogate-eda080", q([]byte{0xED, 0xA0, 0x80})},
		{"literal/truncated-multibyte", q([]byte{0xE2})},
	}
}

func diffWhitespaceCases() []diffStrictItem {
	wrap := func(ws []byte) []byte { return append(append(append([]byte{}, ws...), []byte(`{}`)...), ws...) }
	var items []diffStrictItem
	for _, v := range []struct {
		suffix string
		b      byte
	}{{"space", ' '}, {"tab", '\t'}, {"lf", '\n'}, {"cr", '\r'}} {
		items = append(items, diffStrictItem{"whitespace/valid-" + v.suffix, wrap([]byte{v.b})})
	}
	for _, v := range []struct {
		suffix string
		b      []byte
	}{{"form-feed", []byte{0x0C}}, {"vertical-tab", []byte{0x0B}}, {"nbsp", []byte{0xC2, 0xA0}}} {
		items = append(items, diffStrictItem{"whitespace/invalid-" + v.suffix, wrap(v.b)})
	}
	items = append(items,
		diffStrictItem{"whitespace/bom-at-start", append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{}`)...)},
		diffStrictItem{"whitespace/bom-mid-document", append(append([]byte(`{"a":`), []byte{0xEF, 0xBB, 0xBF}...), []byte(`true}`)...)},
	)
	return items
}

func diffNumberCases() []diffStrictItem {
	var items []diffStrictItem
	for _, tok := range []string{"0", "-0", "1.0", "1e3", "1E+3", "NaN", "Infinity", "0x10"} {
		items = append(items,
			diffStrictItem{"number/" + tok + "-object-value", []byte(`{"x":` + tok + `}`)},
			diffStrictItem{"number/" + tok + "-nested-array", []byte(`[[` + tok + `]]`)},
		)
	}
	return items
}

func diffLiteralTokenCases() []diffStrictItem {
	var items []diffStrictItem
	for _, tok := range []string{"true", "false", "null", "True", "NULL", "nul", "truee"} {
		items = append(items, diffStrictItem{"literal-token/" + tok, []byte(tok)})
	}
	return append(items,
		diffStrictItem{"literal-token/top-level-string", []byte(`"x"`)},
		diffStrictItem{"literal-token/top-level-true", []byte(`true`)},
		diffStrictItem{"literal-token/top-level-null", []byte(`null`)},
	)
}

func diffStructureCases() []diffStrictItem {
	items := []diffStrictItem{
		{"structure/empty-input", []byte{}},
		{"structure/only-whitespace", []byte("   \t\n")},
		{"structure/empty-object", []byte(`{}`)},
		{"structure/empty-array", []byte(`[]`)},
		{"structure/missing-value", []byte(`{"a":}`)},
		{"structure/missing-colon", []byte(`{"a"}`)},
		{"structure/object-just-comma", []byte(`{,}`)},
		{"structure/array-just-comma", []byte(`[,]`)},
		{"structure/array-trailing-comma", []byte(`[true,]`)},
		{"structure/object-trailing-comma", []byte(`{"a":true,}`)},
		{"structure/unquoted-key", []byte(`{a:true}`)},
		{"structure/single-quoted-key", []byte(`{'a':true}`)},
		{"structure/unterminated-string", []byte(`{"a":"b`)},
		{"structure/unterminated-array", []byte(`[true`)},
		{"structure/unterminated-object", []byte(`{"a":true`)},
		{"structure/bare-close-bracket", []byte(`]`)},
		{"structure/bare-close-brace", []byte(`}`)},
		{"structure/mismatched-open-array-close-object", []byte(`[}`)},
		{"structure/duplicate-name-literal", []byte(`{"a":true,"a":false}`)},
	}
	escapedDup := append(append([]byte(`{"a":true,"`), jsonUnicodeEscape("0061")...), []byte(`":false}`)...)
	items = append(items, diffStrictItem{"structure/duplicate-name-escaped-equivalent", escapedDup})
	items = append(items, diffStrictItem{"structure/case-different-keys-accepted-distinct", []byte(`{"a":true,"A":false}`)})

	nfc := []byte{0xC3, 0xA9}       // é, NFC (precomposed)
	nfd := []byte{0x65, 0xCC, 0x81} // e + combining acute, NFD
	nfdKeys := append(append(append([]byte(`{"`), nfc...), []byte(`":true,"`)...), append(append([]byte{}, nfd...), []byte(`":false}`)...)...)
	items = append(items, diffStrictItem{"structure/nfc-nfd-keys-accepted-distinct", nfdKeys})

	depth := func(n int) []byte { return []byte(strings.Repeat("[", n) + "true" + strings.Repeat("]", n)) }
	depthObj := func(n int) []byte { return []byte(strings.Repeat(`{"a":`, n) + "true" + strings.Repeat("}", n)) }
	depthMixed := func(n int) []byte {
		var open, closeTail string
		for i := 0; i < n; i++ {
			if i%2 == 0 {
				open += "["
				closeTail = "]" + closeTail
			} else {
				open += `{"a":`
				closeTail = "}" + closeTail
			}
		}
		return []byte(open + "true" + closeTail)
	}
	for _, n := range []int{23, 24, 25, 26} {
		items = append(items,
			diffStrictItem{fmt.Sprintf("structure/array-depth-%d", n), depth(n)},
			diffStrictItem{fmt.Sprintf("structure/object-depth-%d", n), depthObj(n)},
			diffStrictItem{fmt.Sprintf("structure/mixed-depth-%d", n), depthMixed(n)},
		)
	}
	return items
}

func diffSizeCorpusCases() []diffStrictItem {
	const overhead = len(`{"x":""}`) // 8 bytes: the exact JSON text with an empty string value
	makeSized := func(total int) []byte {
		return []byte(`{"x":"` + strings.Repeat("a", total-overhead) + `"}`)
	}
	items := []diffStrictItem{
		{"size/exactly-max-input-bytes", makeSized(MaxInputBytes)},
		{"size/max-input-bytes-plus-one", makeSized(MaxInputBytes + 1)},
	}
	// 70000 4-byte-UTF-8 rockets: 280000 UTF-8 bytes (over MaxInputBytes) but
	// 140000 UTF-16 code units (under it), probing for a UTF-16-length bug.
	const rocket = "🚀"
	items = append(items, diffStrictItem{"size/utf16-under-utf8-over-limit", []byte(`{"x":"` + strings.Repeat(rocket, 70000) + `"}`)})
	return items
}

// ---------------------------------------------------------------------------
// TestGoJSStrictJSONDifferential
// ---------------------------------------------------------------------------

// knownStrictJSONDivergences is the parser-layer counterpart of
// knownDivergences. A canonical-bytes mismatch where both sides accept would
// be keyed "<label>#canonical"; none is known.
var knownStrictJSONDivergences = map[string]bool{
	// Top-level scalars: an accepted difference between the parsing helpers,
	// not a protocol defect. parseStrict accepts any JSON value; jcs.Transform,
	// which validateJSON always calls, only parses an object or array, so
	// StrictJSON refuses a bare true, false, null or string. core-0.1.md
	// requires the root of a bundle, envelope and payload to be an object, and
	// both verification entry points enforce that (see the reject/input-root-*
	// and reject/payload-root-* conformance cases).
	`literal-token/false`:            false,
	`literal-token/null`:             false,
	`literal-token/top-level-null`:   false,
	`literal-token/top-level-string`: false,
	`literal-token/top-level-true`:   false,
	`literal-token/true`:             false,
}

func TestGoJSStrictJSONDifferential(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for Go/JS differential testing")
	}

	var items []diffStrictItem
	items = append(items, diffFixtureStrictItems(t)...)
	items = append(items, diffSurrogateMatrixItems()...)
	items = append(items, diffEscapeCases()...)
	items = append(items, diffLiteralUTF8Cases()...)
	items = append(items, diffWhitespaceCases()...)
	items = append(items, diffNumberCases()...)
	items = append(items, diffLiteralTokenCases()...)
	items = append(items, diffStructureCases()...)
	items = append(items, diffSizeCorpusCases()...)

	labels := make([]string, len(items))
	for i, it := range items {
		labels[i] = it.Label
	}
	diffCheckUniqueStrings(t, labels)

	goAccept := make([]bool, len(items))
	goCanonical := make([][]byte, len(items))
	for i, it := range items {
		var dst any
		if err := StrictJSON(it.Raw, &dst); err == nil {
			goAccept[i] = true
			c, err := Canonical(dst)
			if err != nil {
				t.Fatalf("%s: StrictJSON accepted but Canonical failed: %v", it.Label, err)
			}
			goCanonical[i] = c
		}
	}

	type wireItem struct {
		Label  string `json:"label"`
		RawB64 string `json:"raw_b64"`
	}
	wire := make([]wireItem, len(items))
	for i, it := range items {
		wire[i] = wireItem{Label: it.Label, RawB64: rawURL.EncodeToString(it.Raw)}
	}
	file := filepath.Join(t.TempDir(), "strict-json.json")
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}

	script := `import { readFile } from 'node:fs/promises';
import { parseStrict, canonical, decodeBytes } from '../web/apostille-core.mjs';
const items = JSON.parse(await readFile(process.argv[1], 'utf8'));
const results = [];
for (const item of items) {
  const bytes = Buffer.from(item.raw_b64, 'base64url');
  try {
    const text = decodeBytes(bytes);
    const value = parseStrict(text);
    let canonicalB64 = null;
    try { canonicalB64 = Buffer.from(new TextEncoder().encode(canonical(value))).toString('base64url'); } catch {}
    results.push({ accept: true, canonical_b64: canonicalB64 });
  } catch {
    results.push({ accept: false, canonical_b64: null });
  }
}
process.stdout.write(JSON.stringify(results));`

	out := diffRunNode(t, node, script, file)
	var jsResults []struct {
		Accept       bool    `json:"accept"`
		CanonicalB64 *string `json:"canonical_b64"`
	}
	if err := json.Unmarshal(out, &jsResults); err != nil {
		t.Fatalf("parsing node output: %v\noutput: %s", err, out)
	}
	if len(jsResults) != len(items) {
		t.Fatalf("node returned %d results for %d items", len(jsResults), len(items))
	}

	jsAccept := make([]bool, len(items))
	for i := range items {
		jsAccept[i] = jsResults[i].Accept
	}

	var canonLabels []string
	var canonGoAccept, canonJSAccept []bool
	for i := range items {
		if !goAccept[i] || !jsAccept[i] {
			continue
		}
		match := jsResults[i].CanonicalB64 != nil
		if match {
			jsCanon, err := rawURL.DecodeString(*jsResults[i].CanonicalB64)
			match = err == nil && bytes.Equal(jsCanon, goCanonical[i])
		}
		canonLabels = append(canonLabels, labels[i]+"#canonical")
		canonGoAccept = append(canonGoAccept, true)
		canonJSAccept = append(canonJSAccept, match)
	}

	allLabels := append(append([]string{}, labels...), canonLabels...)
	allGoAccept := append(append([]bool{}, goAccept...), canonGoAccept...)
	allJSAccept := append(append([]bool{}, jsAccept...), canonJSAccept...)

	agree, goN, jsN := diffSummary(goAccept, jsAccept)
	t.Logf("strict-json corpus=%d agree=%d known_divergences=%d go_accept=%d/%d js_accept=%d/%d both_accept_canonical_checked=%d",
		len(items), agree, len(knownStrictJSONDivergences), goN, len(items), jsN, len(items), len(canonLabels))

	if problems := diffFindDivergences(allLabels, allGoAccept, allJSAccept, knownStrictJSONDivergences); len(problems) > 0 {
		t.Errorf("%d unexpected divergence(s) or stale table entries:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}
