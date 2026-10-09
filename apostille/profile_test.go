package apostille

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKnownProtocolsAndProfileSizes(t *testing.T) {
	require.Equal(t, []string{Protocol, Protocol02, Protocol03}, KnownProtocols())
	require.Equal(t, "https://ifandonlyif.io/apostille/spec/0.2", Protocol02)
	require.Equal(t, "https://ifandonlyif.io/apostille/spec/0.3", Protocol03)
	for _, p := range profiles {
		wantKey, wantSig := 43, 86
		if p == profile03 {
			wantKey, wantSig = 2603, 4412
		}
		require.Equal(t, wantKey, p.encodedPublicKeyLen())
		require.Equal(t, wantSig, p.encodedSignatureLen())
		got, err := profileFor(p.protocol)
		require.NoError(t, err)
		require.Same(t, p, got)
	}
	for _, unknown := range []string{"", "https://ifandonlyif.io/apostille/spec/0.4", strings.ToUpper(Protocol02), strings.ToUpper(Protocol03)} {
		_, err := profileFor(unknown)
		require.Error(t, err, unknown)
	}
	require.Equal(t, "iff-apostille/origin-statement/0.1\n", string(profile01.signingInput(KindStatement, nil)[:35]))
	require.Equal(t, "iff-apostille/origin-statement/0.2\n", string(profile02.signingInput(KindStatement, nil)[:35]))
	require.Equal(t, "iff-apostille/origin-statement/0.3\n", string(profile03.signingInput(KindStatement, nil)[:35]))
	require.NotEqual(t, profile01.signingInput(KindStatement, []byte("x")), profile02.signingInput(KindStatement, []byte("x")))
	require.NotEqual(t, profile02.signingInput(KindStatement, []byte("x")), profile03.signingInput(KindStatement, []byte("x")))
}

// TestEnvelopeSizeGateFollowsProfile keeps the Core 0.1 limits (64 and 128
// bytes) now that they derive from the profile's decoded sizes; every other
// profile's limits are twice its decoded sizes.
func TestEnvelopeSizeGateFollowsProfile(t *testing.T) {
	for _, protocol := range KnownProtocols() {
		prof, err := profileFor(protocol)
		require.NoError(t, err)
		keyLimit, sigLimit := 2*prof.publicKeySize, 2*prof.signatureSize
		if protocol != Protocol03 {
			require.Equal(t, 64, keyLimit)
			require.Equal(t, 128, sigLimit)
		}
		b, _, _, _ := fixtureFor(t, protocol)
		env := b.Statement

		long := env
		long.Signature.PublicKey = strings.Repeat("A", keyLimit+1)
		_, err = VerifyEnvelope(long)
		require.ErrorContains(t, err, "exceed size limit")
		long.Signature.PublicKey = strings.Repeat("A", keyLimit)
		_, err = VerifyEnvelope(long)
		require.ErrorContains(t, err, "key fingerprint mismatch", "up to the limit reaches the decoder")

		long = env
		long.Signature.Value = strings.Repeat("A", sigLimit+1)
		_, err = VerifyEnvelope(long)
		require.ErrorContains(t, err, "exceed size limit")
		long.Signature.Value = strings.Repeat("A", sigLimit)
		_, err = VerifyEnvelope(long)
		require.ErrorContains(t, err, "invalid source signature")
	}
}

func TestExplicitVersionSigning(t *testing.T) {
	admin, agent := testSigner(t, 1), testSigner(t, 2)
	now := fixedNow

	// The existing functions keep signing 0.1.
	reg1, err := CreateRegistration(admin, agent, exampleIssuer, time.Hour, now)
	require.NoError(t, err)
	require.Equal(t, Protocol, reg1.Delegation.Protocol)
	require.Equal(t, Protocol, reg1.Acceptance.Protocol)

	reg2, err := CreateRegistrationFor(Protocol02, admin, agent, exampleIssuer, time.Hour, now)
	require.NoError(t, err)
	require.Equal(t, Protocol02, reg2.Delegation.Protocol)
	require.Equal(t, Protocol02, reg2.Acceptance.Protocol)
	d, err := VerifyRegistration(reg2, exampleIssuer, now)
	require.NoError(t, err)
	require.Equal(t, Protocol02, d.Protocol)

	_, err = CreateRegistrationFor("https://ifandonlyif.io/apostille/spec/0.4", admin, agent, exampleIssuer, time.Hour, now)
	require.Error(t, err)
	_, err = admin.SignFor("", KindDelegation, Delegation{})
	require.Error(t, err)

	// A statement cannot bind to a delegation of another version, in either direction.
	st2, err := CreateStatementFor(Protocol02, strings.NewReader("hello\n"), "text/plain", agent, &reg2, "", now)
	require.NoError(t, err)
	require.Equal(t, Protocol02, st2.Protocol)
	_, err = CreateStatement(strings.NewReader("hello\n"), "text/plain", agent, &reg2, "", now)
	require.ErrorContains(t, err, "differs")
	_, err = CreateStatementFor(Protocol02, strings.NewReader("hello\n"), "text/plain", agent, &reg1, "", now)
	require.ErrorContains(t, err, "differs")
	_, err = CreateStatementFor("unknown", strings.NewReader(""), "text/plain", agent, nil, agentID, now)
	require.Error(t, err)

	// Same for publication grants.
	st1, err := CreateStatement(strings.NewReader("hello\n"), "text/plain", agent, &reg1, "", now)
	require.NoError(t, err)
	grant2, err := CreateGrantFor(Protocol02, st2, reg2, admin, exampleIssuer, "private", now)
	require.NoError(t, err)
	require.Equal(t, Protocol02, grant2.Protocol)
	_, err = CreateGrantFor(Protocol02, st1, reg2, admin, exampleIssuer, "private", now)
	require.Error(t, err)
	_, err = CreateGrantFor(Protocol02, st2, reg1, admin, exampleIssuer, "private", now)
	require.Error(t, err)
	_, err = CreateGrant(st2, reg2, admin, exampleIssuer, "private", now)
	require.Error(t, err, "the 0.1 form refuses 0.2 material")
	grant1, err := CreateGrant(st1, reg1, admin, exampleIssuer, "private", now)
	require.NoError(t, err)

	// ValidateGrant: grant, statement and delegation agree.
	_, err = ValidateGrant(grant2, st2, reg2.Delegation, admin.KeyID(), exampleIssuer, now)
	require.NoError(t, err)
	_, err = ValidateGrant(grant1, st1, reg1.Delegation, admin.KeyID(), exampleIssuer, now)
	require.NoError(t, err)
	for _, tc := range []struct{ grant, statement, delegation Envelope }{
		{grant2, st1, reg2.Delegation},
		{grant2, st2, reg1.Delegation},
		{grant1, st2, reg1.Delegation},
		{grant1, st1, reg2.Delegation},
	} {
		_, err = ValidateGrant(tc.grant, tc.statement, tc.delegation, admin.KeyID(), exampleIssuer, now)
		require.ErrorContains(t, err, "different protocol versions")
	}
}

func TestIssuanceFollowsSourceVersion(t *testing.T) {
	for _, protocol := range KnownProtocols() {
		b, _, _, issuer := fixtureFor(t, protocol)
		require.Equal(t, protocol, b.Certificate.Protocol)
		v, err := VerifyBundle(b, VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{issuer.KeyID()}, Now: fixedNow.Add(time.Hour)})
		require.NoError(t, err)
		require.Equal(t, protocol, v.Protocol, "the result reports the bundle's version")
		require.Equal(t, "accepted_by_policy", v.IssuerTrust)
	}

	// A source of mixed versions is not certified, whichever version it names.
	b2, _, _, issuer := fixtureFor(t, Protocol02)
	b1, _, _, _ := fixtureFor(t, Protocol)
	for _, mixed := range []Bundle{
		{Protocol: Protocol02, Statement: b2.Statement, Delegation: b1.Delegation, Acceptance: b1.Acceptance},
		{Protocol: Protocol02, Statement: b2.Statement, Delegation: b2.Delegation, Acceptance: b1.Acceptance},
		{Protocol: Protocol, Statement: b2.Statement, Delegation: b1.Delegation, Acceptance: b1.Acceptance},
		{Protocol: Protocol03, Statement: b2.Statement, Delegation: b2.Delegation, Acceptance: b2.Acceptance},
	} {
		_, err := Issue(mixed, issuer, exampleIssuer, fixedNow.Add(time.Minute))
		require.Error(t, err)
		_, err = VerifyBundle(mixed, VerifyOptions{})
		require.Error(t, err)
	}
}

func TestAcceptedProtocols(t *testing.T) {
	b1, _, _, _ := fixtureFor(t, Protocol)
	b2, _, _, _ := fixtureFor(t, Protocol02)
	b3, _, _, _ := fixtureFor(t, Protocol03)
	for _, tc := range []struct {
		name     string
		accepted []string
		bundle   Bundle
		ok       bool
	}{
		{"unset accepts 0.1", nil, b1, true},
		{"unset accepts 0.2", nil, b2, true},
		{"only 0.2 accepts 0.2", []string{Protocol02}, b2, true},
		{"only 0.2 refuses 0.1", []string{Protocol02}, b1, false},
		{"only 0.1 refuses 0.2", []string{Protocol}, b2, false},
		{"both accept 0.2", []string{Protocol, Protocol02}, b2, true},
		{"an empty list accepts nothing", []string{}, b1, false},
		{"unset accepts 0.3", nil, b3, true},
		{"only 0.3 accepts 0.3", []string{Protocol03}, b3, true},
		{"only 0.3 refuses 0.2", []string{Protocol03}, b2, false},
		{"only 0.2 refuses 0.3", []string{Protocol02}, b3, false},
		{"0.1 and 0.2 refuse 0.3", []string{Protocol, Protocol02}, b3, false},
		{"an unknown entry matches nothing", []string{"https://ifandonlyif.io/apostille/spec/0.4"}, b2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := VerifyBundle(tc.bundle, VerifyOptions{AcceptedProtocols: tc.accepted})
			if tc.ok {
				require.NoError(t, err)
				require.Equal(t, tc.bundle.Protocol, v.Protocol)
				return
			}
			require.ErrorContains(t, err, "not accepted")
		})
	}

	// The restriction applies before any signature work: a bundle with
	// unusable signatures still fails with the policy error.
	broken := b2
	broken.Statement.Signature.Value = "x"
	_, err := VerifyBundle(broken, VerifyOptions{AcceptedProtocols: []string{Protocol}})
	require.ErrorContains(t, err, "not accepted")
	_, err = VerifyBundle(broken, VerifyOptions{})
	require.ErrorContains(t, err, "invalid source signature")
}

// TestCore01KeepsAcceptingDegenerateKeys documents why a receiver that needs
// strict verification must refuse 0.1: the same degenerate key and signature
// verify under 0.1 and are rejected under 0.2.
func TestCore01KeepsAcceptingDegenerateKeys(t *testing.T) {
	identity := mustHex(t, smallOrderHex[0])
	for _, g := range []caseGen{gen01, gen02} {
		payload, sig := g.searchSmallOrderSignature(t, identity)
		raw := rawJSON(t, g.keyBundle(payload, identity, sig))
		_, err := Verify(raw, VerifyOptions{})
		if g.protocol == Protocol {
			require.NoError(t, err)
			_, err = Verify(raw, VerifyOptions{AcceptedProtocols: []string{Protocol02}})
			require.ErrorContains(t, err, "not accepted")
		} else {
			require.ErrorContains(t, err, "invalid public key")
		}
	}
}

func TestValidIssuer02Table(t *testing.T) {
	for _, row := range identifierRows(t) {
		require.Equal(t, row.accept, ValidIssuer02(row.value), "%q", row.value)
	}
	// Identifiers of the 0.1 vectors satisfy the 0.2 grammar.
	for _, v := range []string{exampleIssuer, "https://ifandonlyif.io/apostille", "urn:apostille:key:sha256:" + strings.Repeat("0", 64), "urn:example:private-issuer"} {
		require.True(t, ValidIssuer02(v), v)
	}
}

// TestThirdProfileSlotsIn registers a throwaway version (new protocol string
// and signature domain) to show that signing, envelope and bundle verification
// follow the profile table with no further change.
func TestThirdProfileSlotsIn(t *testing.T) {
	const protocol = "https://ifandonlyif.io/apostille/spec/9.9"
	extra := *profile02
	extra.protocol, extra.domain = protocol, "9.9"
	profiles = append(profiles, &extra)
	t.Cleanup(func() { profiles = profiles[:3] })

	require.Equal(t, []string{Protocol, Protocol02, Protocol03, protocol}, KnownProtocols())
	b, _, _, issuer := fixtureFor(t, protocol)
	v, err := VerifyBundle(b, VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{issuer.KeyID()}, Now: fixedNow.Add(time.Hour)})
	require.NoError(t, err)
	require.Equal(t, protocol, v.Protocol)

	// Its signatures do not verify under the other domains.
	relabelled := b.Statement
	relabelled.Protocol = Protocol02
	_, err = VerifyEnvelope(relabelled)
	require.Error(t, err)
	_, err = VerifyBundle(b, VerifyOptions{AcceptedProtocols: []string{Protocol, Protocol02}})
	require.ErrorContains(t, err, "not accepted")
}

func TestParsePublicKeyFor(t *testing.T) {
	seed, edKey, err := GenerateKey()
	require.NoError(t, err)
	_, err = NewSigner(seed)
	require.NoError(t, err)
	_, mlKey, err := GenerateMLDSAKey()
	require.NoError(t, err)

	for _, protocol := range []string{Protocol, Protocol02} {
		raw, err := ParsePublicKeyFor(protocol, edKey)
		require.NoError(t, err, protocol)
		require.Len(t, raw, 32)
		_, err = ParsePublicKeyFor(protocol, mlKey)
		require.Error(t, err, protocol)
		_, err = ParsePublicKeyFor(protocol, edKey+"A")
		require.Error(t, err, protocol)
		_, err = ParsePublicKeyFor(protocol, edKey[:42])
		require.Error(t, err, protocol)
	}
	raw, err := ParsePublicKeyFor(Protocol03, mlKey)
	require.NoError(t, err)
	require.Len(t, raw, 1952)
	_, err = ParsePublicKeyFor(Protocol03, edKey)
	require.Error(t, err)
	_, err = ParsePublicKeyFor(Protocol03, mlKey[:len(mlKey)-1])
	require.Error(t, err)
	_, err = ParsePublicKeyFor(Protocol03, mlKey+"A")
	require.Error(t, err)
	// Flipping a padding bit of the last character decodes to the same bytes
	// but is not canonical.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, edKey[42])
	require.GreaterOrEqual(t, last, 0)
	_, err = ParsePublicKeyFor(Protocol, edKey[:42]+string(alphabet[last^1]))
	require.Error(t, err)
	_, err = ParsePublicKeyFor("https://ifandonlyif.io/apostille/spec/0.4", edKey)
	require.Error(t, err)
	_, err = ParsePublicKeyFor(Protocol, "")
	require.Error(t, err)
}
