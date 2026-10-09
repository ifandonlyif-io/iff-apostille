package apostille

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

// ---------------------------------------------------------------------------
// Core 0.2 writers. They are distinct test functions so that
//
//	UPDATE_APOSTILLE_FIXTURES=1 go test -run '^TestWriteCore02(Vector|Cases)$'
//
// rewrites only the 0.2 files; the Core 0.1 files are frozen. Run the vector
// first: the case generator checks its base bundle against it.
// ---------------------------------------------------------------------------

func TestWriteCore02Vector(t *testing.T) { writeInteropFixture(t, gen02) }

func TestWriteCore02Cases(t *testing.T) { writeConformanceCases(t, gen02, core02ExtraCases) }

// core02ExtraCases are the categories that exist only in the 0.2 file, on top
// of every 0.1 category regenerated under the 0.2 namespace.
func core02ExtraCases(t *testing.T) ([]bundleCase, []issuerConformanceCase) {
	g := gen02
	var cases []bundleCase
	cases = append(cases, g.identifierBundleCases(t)...)
	cases = append(cases, g.ed25519KeyCases(t)...)
	cases = append(cases, g.ed25519SignatureCases(t)...)
	cases = append(cases, g.agentKeyCases(t)...)
	cases = append(cases, g.crossVersionCases(t)...)
	return cases, g.identifierConformanceCases(t)
}

// ---------------------------------------------------------------------------
// Identifiers inside signed artifacts
// ---------------------------------------------------------------------------

// identifierChain is a delegated bundle whose delegation names audience and
// whose certificate names certIssuer. The delegation and certificate are signed
// with signRaw, so a value the profile rejects is still validly signed.
func (g caseGen) identifierChain(t *testing.T, audience, certIssuer string) (Bundle, *Signer) {
	t.Helper()
	admin, agent, issuer := testSigner(t, 1), testSigner(t, 2), testSigner(t, 3)
	d := Delegation{Header: g.header(KindDelegation, KeyIdentity(admin.KeyID()), admin, fixedNow), AgentID: agentID, AgentKeyID: agent.KeyID(), AgentPublicKey: agent.PublicKey(), ServiceAudience: audience, NotBefore: fixedNow.Format(TimestampLayout), ExpiresAt: fixedNow.Add(48 * time.Hour).Format(TimestampLayout), Scopes: []string{"sign_origin_statement"}}
	dp, err := Canonical(d)
	requireNoErr(t, "identifierChain", err)
	dEnv := g.signRaw(t, admin, KindDelegation, dp)
	dh, err := EnvelopeDigest(dEnv)
	requireNoErr(t, "identifierChain", err)
	aEnv := g.mustSign(t, agent, KindAcceptance, Acceptance{Header: g.header(KindAcceptance, KeyIdentity(agent.KeyID()), agent, fixedNow), AgentID: agentID, DelegationSHA256: dh})
	sEnv := g.mustSign(t, agent, KindStatement, Statement{Header: g.header(KindStatement, KeyIdentity(agent.KeyID()), agent, fixedNow), AgentID: agentID, DelegationSHA256: dh, ArtifactSHA256: Hash([]byte("hello\n")), ArtifactSize: "6", ArtifactMediaType: "text/plain", Nonce: nonceID})
	b := Bundle{Protocol: g.protocol, Statement: sEnv, Delegation: &dEnv, Acceptance: &aEnv}
	cert := g.certFor(t, b, issuer, certIssuer, fixedNow.Add(time.Minute), fixedNow.Add(time.Minute+24*time.Hour), "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	cp, err := Canonical(cert)
	requireNoErr(t, "identifierChain", err)
	cEnv := g.signRaw(t, issuer, KindCertificate, cp)
	b.Certificate = &cEnv
	return b, issuer
}

func (g caseGen) identifierBundleCases(t *testing.T) []bundleCase {
	t.Helper()
	var out []bundleCase

	for _, tc := range []struct{ tag, value string }{
		{"bare-host", "https://issuer.example"},
		{"ipv4", "https://127.0.0.1/a"},
		{"ipv6-loopback", "https://[::1]/a"},
		{"ipv6-leftmost-run-compressed", "https://[2001:db8::1:0:0:1]/a"},
		{"port", "https://issuer.example:8443/a"},
		{"pchar-sub-delim", "https://issuer.example/a!b"},
		{"pchar-parentheses", "https://issuer.example/a(b)"},
		{"empty-final-segment", "https://issuer.example/x/"},
		{"empty-inner-segment", "https://issuer.example//x"},
		{"urn-slash-in-nss", "urn:example:a/b"},
	} {
		b, issuer := g.identifierChain(t, tc.value, tc.value)
		name := "accept/identifier-" + tc.tag
		bc, v := g.acceptCase(t, name, fmt.Sprintf("The identifier %q satisfies the 0.2 grammar as a delegation service_audience and as the certificate issuer, and pins to accepted_by_policy.", tc.value),
			rawJSON(t, b), VerifyOptions{ExpectedIssuer: tc.value, TrustedKeyIDs: []string{issuer.KeyID()}, Now: fixedNow.Add(time.Hour)})
		if v.IssuerTrust != "accepted_by_policy" || v.Issuer != tc.value || v.AgentBinding != "admin_key_delegation" {
			t.Fatalf("%s: unexpected verification: %+v", name, v)
		}
		out = append(out, bc)
	}

	rejected := []struct{ tag, value string }{
		{"uppercase-scheme", "HTTPS://issuer.example/a"},
		{"uppercase-host", "https://Issuer.example/a"},
		{"port-443", "https://issuer.example:443/a"},
		{"port-0", "https://issuer.example:0/a"},
		{"port-leading-zero", "https://issuer.example:08443/a"},
		{"trailing-dot-host", "https://issuer.example./a"},
		{"underscore-host", "https://issuer_example/a"},
		{"leading-hyphen-label", "https://-issuer.example/a"},
		{"final-label-digit", "https://issuer.9x/a"},
		{"ipv4-short-form", "https://127.1/a"},
		{"ipv4-leading-zero", "https://01.2.3.4/a"},
		{"ipv4-octet-out-of-range", "https://256.1.1.1/a"},
		{"ipv6-zero-run-uncompressed", "https://[2001:db8:0:0:1:1:1:1]/a"},
		{"ipv6-single-zero-compressed", "https://[2001:db8::1:1:1:1:1]/a"},
		{"ipv6-rightmost-equal-run-compressed", "https://[2001:db8:1::0:0:1]/a"},
		{"ipv6-uppercase", "https://[2001:DB8::1]/a"},
		{"ipv6-leading-zero-group", "https://[2001:0db8::1]/a"},
		{"ipv6-dotted-tail", "https://[::ffff:1.2.3.4]/a"},
		{"ipv6-zone", "https://[fe80::1%eth0]/a"},
		{"path-pipe", "https://issuer.example/a|b"},
		{"path-brackets", "https://issuer.example/a[b]"},
		{"path-dot-dot-segment", "https://issuer.example/a/../b"},
		{"path-dot-segment", "https://issuer.example/./a"},
		{"path-percent-escape", "https://issuer.example/a%20b"},
		{"userinfo", "https://user@issuer.example/a"},
		{"urn-uppercase-scheme", "URN:example:x"},
		{"urn-uppercase-nid", "urn:EXAMPLE:x"},
		{"urn-no-nss", "urn:x"},
		{"urn-space", "urn:example:x y"},
	}
	for _, tc := range rejected {
		b, issuer := g.identifierChain(t, tc.value, exampleIssuer)
		out = append(out, rejectCase(t, "reject/identifier-audience-"+tc.tag,
			fmt.Sprintf("The delegation service_audience %q is outside the 0.2 grammar; everything else is valid and validly signed.", tc.value),
			rawJSON(t, b), pin(issuer), "invalid agent delegation"))
	}

	base, s := g.producerOnly(t)
	for _, tc := range rejected {
		b := base
		cert := g.certFor(t, b, s, tc.value, fixedNow, fixedNow.Add(24*time.Hour), "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
		p, err := Canonical(cert)
		requireNoErr(t, tc.tag, err)
		ce := g.signRaw(t, s, KindCertificate, p)
		b.Certificate = &ce
		out = append(out, rejectCase(t, "reject/identifier-certificate-issuer-"+tc.tag,
			fmt.Sprintf("The certificate issuer %q is outside the 0.2 grammar; everything else is valid and validly signed.", tc.value),
			rawJSON(t, b), VerifyOptions{}, "invalid signed protocol header"))
	}
	return out
}

// ---------------------------------------------------------------------------
// Ed25519 vectors. Built from the public fixture seeds only, with the curve
// library, so each signature is real wherever one can be constructed such that
// only the named rule fails. crypto/ed25519 is the "cofactorless verifier" the
// specification refers to: where a signature it accepts exists, the generator
// asserts that it does.
// ---------------------------------------------------------------------------

var smallOrderNames = []string{"identity", "order-2", "order-4", "order-4-sign-bit", "order-8-a", "order-8-b", "order-8-c", "order-8-d"}

// statementPayload is a canonical statement signed by the key keyID; n varies
// the nonce so a search can try many messages.
func (g caseGen) statementPayload(t *testing.T, keyID string, n int) []byte {
	t.Helper()
	st := Statement{
		Header:  Header{Protocol: g.protocol, Kind: KindStatement, Issuer: KeyIdentity(keyID), IssuerKeyID: keyID, IssuedAt: fixedNow.UTC().Format(TimestampLayout)},
		AgentID: agentID, ArtifactSHA256: Hash(nil), ArtifactSize: "0", ArtifactMediaType: "application/octet-stream",
		Nonce: fmt.Sprintf("%08x-bbbb-4bbb-8bbb-bbbbbbbbbbbb", n),
	}
	p, err := Canonical(st)
	requireNoErr(t, "statementPayload", err)
	return p
}

// keyBundle is a producer-only bundle whose statement names pub as its key and
// carries sig; the payload and its digest are valid for that key.
func (g caseGen) keyBundle(payload, pub, sig []byte) Bundle {
	return Bundle{Protocol: g.protocol, Statement: Envelope{
		Protocol: g.protocol, Kind: KindStatement, Payload: rawURL.EncodeToString(payload), PayloadSHA256: Hash(payload),
		Signature: Signature{Algorithm: g.prof.algorithm, KeyID: Fingerprint(pub), PublicKey: rawURL.EncodeToString(pub), Value: rawURL.EncodeToString(sig)},
	}}
}

// honestParts are the fixture signer's key, secret scalar, payload, message and
// genuine signature, the base of every vector that keeps the key honest.
type honestParts struct {
	bundle  Bundle
	pub     []byte
	a       *edwards25519.Scalar
	payload []byte
	message []byte
	sig     []byte
}

func (g caseGen) honest(t *testing.T) honestParts {
	t.Helper()
	b, s := g.producerOnly(t)
	payload, err := rawURL.DecodeString(b.Statement.Payload)
	requireNoErr(t, "honest", err)
	sig, err := rawURL.DecodeString(b.Statement.Signature.Value)
	requireNoErr(t, "honest", err)
	h := honestParts{bundle: b, pub: append([]byte{}, s.key[32:]...), a: clampedScalar(t, s.key.Seed()), payload: payload, message: g.prof.signingInput(KindStatement, payload), sig: sig}
	if !bytes.Equal(new(edwards25519.Point).ScalarBaseMult(h.a).Bytes(), h.pub) {
		t.Fatal("honest: secret scalar does not match the fixture key")
	}
	return h
}

func (h honestParts) withSignature(sig []byte) Bundle {
	b := h.bundle
	b.Statement.Signature.Value = rawURL.EncodeToString(sig)
	return b
}

// searchSmallOrderSignature finds a message (by nonce) and a small-order R for
// which (R, S=0) satisfies [S]B = R + [k]A under the decoded key A, and that
// crypto/ed25519 accepts: R = -[k]A.
func (g caseGen) searchSmallOrderSignature(t *testing.T, pub []byte) (payload, sig []byte) {
	t.Helper()
	A := mustPoint(t, pub)
	for n := 0; n < 1<<16; n++ {
		payload := g.statementPayload(t, Fingerprint(pub), n)
		message := g.prof.signingInput(KindStatement, payload)
		for _, h := range smallOrderHex {
			r := mustHex(t, h)
			want := new(edwards25519.Point).ScalarMult(challenge(t, r, pub, message), A)
			if !bytes.Equal(want.Negate(want).Bytes(), r) {
				continue
			}
			sig := append(append([]byte{}, r...), make([]byte, 32)...)
			if ed25519.Verify(ed25519.PublicKey(pub), message, sig) {
				return payload, sig
			}
		}
	}
	t.Fatalf("no cofactorless-accepted signature found for key %x", pub)
	return nil, nil
}

// mixedOrderSignature signs under A = [a]B + torsion with R = [r]B and
// S = r + k*a, iterating r until k is a multiple of 8, so that [k]torsion is
// the identity and a cofactorless verifier accepts the signature.
func (g caseGen) mixedOrderSignature(t *testing.T, label string, a *edwards25519.Scalar, torsion *edwards25519.Point) (pub, payload, sig []byte) {
	t.Helper()
	pub = new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(a), torsion).Bytes()
	payload = g.statementPayload(t, Fingerprint(pub), 0)
	message := g.prof.signingInput(KindStatement, payload)
	for j := 0; j < 1<<12; j++ {
		seed := sha512.Sum512([]byte(fmt.Sprintf("iff-apostille/core-0.2/test-r/%s/%d", label, j)))
		r, err := new(edwards25519.Scalar).SetUniformBytes(seed[:])
		requireNoErr(t, label, err)
		R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
		k := challenge(t, R, pub, message)
		if k.Bytes()[0]&7 != 0 {
			continue
		}
		sig = append(append([]byte{}, R...), new(edwards25519.Scalar).MultiplyAdd(k, a, r).Bytes()...)
		if !ed25519.Verify(ed25519.PublicKey(pub), message, sig) {
			t.Fatalf("%s: constructed mixed-order signature is not accepted by crypto/ed25519", label)
		}
		return pub, payload, sig
	}
	t.Fatalf("%s: no r with k divisible by 8", label)
	return nil, nil, nil
}

func (g caseGen) ed25519KeyCases(t *testing.T) []bundleCase {
	t.Helper()
	var out []bundleCase
	h := g.honest(t)

	// The eight small-order points as A, each with a signature a cofactorless
	// verifier accepts, so that only the key rule fails.
	for i, hexKey := range smallOrderHex {
		pub := mustHex(t, hexKey)
		payload, sig := g.searchSmallOrderSignature(t, pub)
		wantErr := "invalid public key: point is not in the prime-order subgroup"
		if i == 0 {
			wantErr = "invalid public key: point is the identity"
		}
		out = append(out, rejectCase(t, "reject/ed25519-small-order-key-"+smallOrderNames[i],
			fmt.Sprintf("The small-order point %s as the public key, with an R and S=0 that satisfy the verification equation under crypto/ed25519: only the key rule rejects it.", hexKey),
			rawJSON(t, g.keyBundle(payload, pub, sig)), VerifyOptions{}, wantErr))
	}

	// Mixed-order keys with signatures a cofactorless verifier accepts.
	one, err := new(edwards25519.Scalar).SetCanonicalBytes(append([]byte{1}, make([]byte, 31)...))
	requireNoErr(t, "scalar one", err)
	order2 := mustPoint(t, mustHex(t, smallOrderHex[1]))
	order8 := mustPoint(t, mustHex(t, smallOrderHex[4]))
	for _, tc := range []struct {
		name, reason string
		a            *edwards25519.Scalar
		torsion      *edwards25519.Point
		wantPub      []byte
	}{
		{"base-plus-order-2", "The base point plus the order-2 point (the mixed-order example of the specification, secret scalar 1) as the public key, with a signature crypto/ed25519 accepts because k is a multiple of 8: a small-order blocklist passes it and only the subgroup rule rejects it.", one, order2, mustHex(t, mixedOrderHex)},
		{"fixture-key-plus-order-2", "The fixture key plus the order-2 point as the public key, with a signature crypto/ed25519 accepts because k is a multiple of 8: only the subgroup rule rejects it.", h.a, order2, nil},
		{"fixture-key-plus-order-8", "The fixture key plus an order-8 point as the public key, with a signature crypto/ed25519 accepts because k is a multiple of 8: only the subgroup rule rejects it.", h.a, order8, nil},
	} {
		pub, payload, sig := g.mixedOrderSignature(t, tc.name, tc.a, tc.torsion)
		if tc.wantPub != nil && !bytes.Equal(pub, tc.wantPub) {
			t.Fatalf("%s: key %x, want the specification's %x", tc.name, pub, tc.wantPub)
		}
		out = append(out, rejectCase(t, "reject/ed25519-mixed-order-key-"+tc.name, tc.reason,
			rawJSON(t, g.keyBundle(payload, pub, sig)), VerifyOptions{}, "invalid public key: point is not in the prime-order subgroup"))
	}

	// Non-canonical A: y >= p, and x = 0 with the sign bit set. These decode in
	// the library and in crypto/ed25519; only the re-encoding check rejects them.
	for _, tc := range noncanonicalPoints {
		pub := mustHex(t, tc.hex)
		payload, sig := g.searchSmallOrderSignature(t, pub)
		out = append(out, rejectCase(t, "reject/ed25519-noncanonical-key-"+tc.name,
			fmt.Sprintf("The non-canonical encoding %s (%s) as the public key, with a signature crypto/ed25519 accepts: re-encoding the decoded point does not reproduce the key bytes.", tc.hex, tc.desc),
			rawJSON(t, g.keyBundle(payload, pub, sig)), VerifyOptions{}, "invalid public key: point encoding is not canonical"))
	}
	return out
}

// noncanonicalPoints are encodings the curve library decodes but does not
// reproduce when re-encoding them.
var noncanonicalPoints = []struct{ name, hex, desc string }{
	{"y-equals-p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "y = p, an alias of y = 0"},
	{"y-equals-p-plus-1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "y = p+1, an alias of the identity"},
	{"identity-sign-bit", "0100000000000000000000000000000000000000000000000000000000000080", "the identity with the sign bit set while x = 0"},
	{"order-2-sign-bit", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "the order-2 point with the sign bit set while x = 0"},
}

func (g caseGen) ed25519SignatureCases(t *testing.T) []bundleCase {
	t.Helper()
	var out []bundleCase
	h := g.honest(t)
	identity := mustHex(t, smallOrderHex[0])
	s0 := h.sig[32:]

	// R = identity with the valid S = k*a on an honest key: crypto/ed25519
	// accepts it, so only the identity clause on R rejects it.
	validIdentity := func(r []byte) []byte {
		k := challenge(t, r, h.pub, h.message)
		return append(append([]byte{}, r...), new(edwards25519.Scalar).Multiply(k, h.a).Bytes()...)
	}
	sig := validIdentity(identity)
	if !ed25519.Verify(ed25519.PublicKey(h.pub), h.message, sig) {
		t.Fatal("identity R with S = k*a is not accepted by crypto/ed25519")
	}
	out = append(out, rejectCase(t, "reject/ed25519-identity-r-valid-s-honest-key",
		"R is the identity and S = k*a mod L on an honest key: [S]B = R + [k]A holds and crypto/ed25519 accepts the signature, so only the identity clause of step 3 rejects it (it catches a verifier that checks A and forgets R).",
		rawJSON(t, h.withSignature(sig)), VerifyOptions{}, "R: point is the identity"))

	// The other seven small-order points as R. No signature with such an R can
	// satisfy the equation for an honest key, so these test rejection only.
	for i := 1; i < len(smallOrderHex); i++ {
		sig := append(mustHex(t, smallOrderHex[i]), s0...)
		if ed25519.Verify(ed25519.PublicKey(h.pub), h.message, sig) {
			t.Fatalf("small-order R %d unexpectedly verifies", i)
		}
		out = append(out, rejectCase(t, "reject/ed25519-small-order-r-"+smallOrderNames[i],
			fmt.Sprintf("The small-order point %s as R on an honest key. No such signature can satisfy the equation, so this isolates the subgroup rule on R, not a bad equation.", smallOrderHex[i]),
			rawJSON(t, h.withSignature(sig)), VerifyOptions{}, "R: point is not in the prime-order subgroup"))
	}

	// A mixed-order R: [r]B plus the order-2 point.
	seed := sha512.Sum512([]byte("iff-apostille/core-0.2/test-r/mixed-r"))
	rMixed, err := new(edwards25519.Scalar).SetUniformBytes(seed[:])
	requireNoErr(t, "mixed R", err)
	mixedR := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(rMixed), mustPoint(t, mustHex(t, smallOrderHex[1]))).Bytes()
	k := challenge(t, mixedR, h.pub, h.message)
	mixedSig := append(append([]byte{}, mixedR...), new(edwards25519.Scalar).MultiplyAdd(k, h.a, rMixed).Bytes()...)
	if ed25519.Verify(ed25519.PublicKey(h.pub), h.message, mixedSig) {
		t.Fatal("mixed-order R unexpectedly verifies")
	}
	out = append(out, rejectCase(t, "reject/ed25519-mixed-order-r",
		"R = [r]B plus the order-2 point and S = r + k*a: the signature is genuine apart from the torsion component of R, which only the subgroup rule on R rejects.",
		rawJSON(t, h.withSignature(mixedSig)), VerifyOptions{}, "R: point is not in the prime-order subgroup"))

	// Non-canonical R. For the two aliases of the identity, S = k*a makes the
	// equation hold as a point equation, which a verifier that decodes R without
	// comparing bytes accepts; crypto/ed25519 compares bytes and rejects.
	for _, tc := range noncanonicalPoints {
		r := mustHex(t, tc.hex)
		sig := append(append([]byte{}, r...), s0...)
		reason := fmt.Sprintf("The non-canonical encoding %s (%s) as R on an honest key, with the genuine S: no signature with this R can satisfy the equation.", tc.hex, tc.desc)
		if tc.name == "y-equals-p-plus-1" || tc.name == "identity-sign-bit" {
			sig = validIdentity(r)
			reason = fmt.Sprintf("The non-canonical encoding %s (%s) as R, an alias of the identity, with S = k*a for the hash of those exact bytes: the point equation holds, so a verifier that decodes R without re-encoding it accepts the signature.", tc.hex, tc.desc)
		}
		if ed25519.Verify(ed25519.PublicKey(h.pub), h.message, sig) {
			t.Fatalf("non-canonical R %s unexpectedly verifies under crypto/ed25519", tc.name)
		}
		out = append(out, rejectCase(t, "reject/ed25519-noncanonical-r-"+tc.name, reason,
			rawJSON(t, h.withSignature(sig)), VerifyOptions{}, "R: point encoding is not canonical"))
	}

	// S = L. (S0 + L is reject/signature-s-plus-l-malleated.)
	atOrder := append(append([]byte{}, h.sig[:32]...), ed25519OrderLE[:]...)
	out = append(out, rejectCase(t, "reject/ed25519-s-equals-l",
		"A genuine R with S equal to the group order L: S is not below L, so step 1 rejects it before any point is decoded.",
		rawJSON(t, h.withSignature(atOrder)), VerifyOptions{}, "S is not below the group order"))
	return out
}

// ---------------------------------------------------------------------------
// agent_public_key in a delegation
// ---------------------------------------------------------------------------

func (g caseGen) agentKeyCases(t *testing.T) []bundleCase {
	t.Helper()
	b, admin, _, issuer := g.fixedBundle(t)
	var d Delegation
	requireNoErr(t, "agentKeyCases", DecodePayload(*b.Delegation, KindDelegation, &d))

	one, err := new(edwards25519.Scalar).SetCanonicalBytes(append([]byte{1}, make([]byte, 31)...))
	requireNoErr(t, "scalar one", err)
	mixed := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(one), mustPoint(t, mustHex(t, smallOrderHex[1]))).Bytes()

	var out []bundleCase
	for _, tc := range []struct {
		tag string
		key []byte
		why string
	}{
		{"identity", mustHex(t, smallOrderHex[0]), "the identity"},
		{"order-2", mustHex(t, smallOrderHex[1]), "a small-order point"},
		{"mixed-order", mixed, "a mixed-order point"},
		{"noncanonical", mustHex(t, noncanonicalPoints[1].hex), "a non-canonical alias of the identity"},
	} {
		bad := *b.Delegation
		dd := d
		dd.AgentPublicKey = rawURL.EncodeToString(tc.key)
		dd.AgentKeyID = Fingerprint(tc.key)
		p, err := Canonical(dd)
		requireNoErr(t, tc.tag, err)
		bad = g.signRaw(t, admin, KindDelegation, p)
		bundle := cloneBundle(b)
		bundle.Delegation = &bad
		out = append(out, rejectCase(t, "reject/ed25519-delegation-agent-key-"+tc.tag,
			fmt.Sprintf("A delegation, validly signed by the administrator, whose agent_public_key is %s: the key rule applies to agent_public_key as it does to signature.public_key.", tc.why),
			rawJSON(t, bundle), pin(issuer), "invalid agent delegation: invalid public key"))
	}
	return out
}

// ---------------------------------------------------------------------------
// Cross-version material
// ---------------------------------------------------------------------------

func (g caseGen) crossVersionCases(t *testing.T) []bundleCase {
	t.Helper()
	b2, _, _, issuer := g.fixedBundle(t)
	b1, _, _, _ := gen01.fixedBundle(t)
	opts := pin(issuer)
	var out []bundleCase

	// A 0.1 envelope inside a 0.2 bundle, one per slot. Each envelope is valid
	// under its own version; the bundle is rejected before any signature check.
	for _, slot := range []string{"statement", "delegation", "acceptance", "certificate"} {
		bad := cloneBundle(b2)
		switch slot {
		case "statement":
			bad.Statement = b1.Statement
		case "delegation":
			bad.Delegation = b1.Delegation
		case "acceptance":
			bad.Acceptance = b1.Acceptance
		case "certificate":
			bad.Certificate = b1.Certificate
		}
		out = append(out, rejectCase(t, "reject/cross-version-0.1-"+slot+"-in-0.2-bundle",
			fmt.Sprintf("A genuine 0.1 %s envelope in an otherwise 0.2 bundle: a bundle carries one version.", slot),
			rawJSON(t, bad), opts, "bundle mixes protocol versions"))
	}

	// The same material relabelled at bundle level only.
	relabelled := cloneBundle(b1)
	relabelled.Protocol = Protocol02
	out = append(out, rejectCase(t, "reject/cross-version-0.1-bundle-labelled-0.2",
		"A complete 0.1 bundle with only the bundle protocol changed to 0.2: its envelopes still name 0.1.",
		rawJSON(t, relabelled), opts, "bundle mixes protocol versions"))
	relabelled = cloneBundle(b2)
	relabelled.Protocol = Protocol
	out = append(out, rejectCase(t, "reject/cross-version-0.2-bundle-labelled-0.1",
		"A complete 0.2 bundle with only the bundle protocol changed to 0.1: its envelopes still name 0.2.",
		rawJSON(t, relabelled), opts, "bundle mixes protocol versions"))

	// A 0.2 payload signed under the 0.1 domain, and the reverse.
	base2, s2 := g.producerOnly(t)
	payload2, err := rawURL.DecodeString(base2.Statement.Payload)
	requireNoErr(t, "cross-version", err)
	wrongDomain := ed25519.Sign(s2.key, profile01.signingInput(KindStatement, payload2))
	if err := profile01.verify(s2.key[32:], profile01.signingInput(KindStatement, payload2), wrongDomain); err != nil {
		t.Fatal("0.1-domain signature does not verify under 0.1")
	}
	bad := base2
	bad.Statement.Signature.Value = rawURL.EncodeToString(wrongDomain)
	out = append(out, rejectCase(t, "reject/cross-version-0.2-statement-signed-under-0.1-domain",
		"A 0.2 statement whose signature is a genuine signature over the 0.1 signing input: the domain string differs, so it does not verify under 0.2.",
		rawJSON(t, bad), VerifyOptions{}, "invalid source signature"))

	cert2 := *b2.Certificate
	certPayload, err := rawURL.DecodeString(cert2.Payload)
	requireNoErr(t, "cross-version", err)
	cert2.Signature.Value = rawURL.EncodeToString(ed25519.Sign(issuer.key, profile01.signingInput(KindCertificate, certPayload)))
	bad = cloneBundle(b2)
	bad.Certificate = &cert2
	out = append(out, rejectCase(t, "reject/cross-version-0.2-certificate-signed-under-0.1-domain",
		"A 0.2 certificate whose signature is a genuine signature over the 0.1 signing input.",
		rawJSON(t, bad), opts, "invalid source signature"))

	base1, s1 := gen01.producerOnly(t)
	payload1, err := rawURL.DecodeString(base1.Statement.Payload)
	requireNoErr(t, "cross-version", err)
	bad = base1
	bad.Statement.Signature.Value = rawURL.EncodeToString(ed25519.Sign(s1.key, g.prof.signingInput(KindStatement, payload1)))
	out = append(out, rejectCase(t, "reject/cross-version-0.1-statement-signed-under-0.2-domain",
		"A 0.1 statement in a 0.1 bundle whose signature is a genuine signature over the 0.2 signing input: it does not verify under 0.1 either.",
		rawJSON(t, bad), VerifyOptions{}, "invalid source signature"))

	// A 0.1 signature relabelled 0.2: with the payload re-labelled and its
	// digest recomputed, and with only the envelope and bundle re-labelled.
	relabelPayload := replaceOnce(t, payload1, `spec/0.1"`, `spec/0.2"`)
	bad = base1
	bad.Protocol = Protocol02
	bad.Statement.Protocol = Protocol02
	bad.Statement.Payload = rawURL.EncodeToString(relabelPayload)
	bad.Statement.PayloadSHA256 = Hash(relabelPayload)
	out = append(out, rejectCase(t, "reject/cross-version-0.1-signature-relabelled-0.2",
		"A genuine 0.1 statement with its protocol changed to 0.2 in the bundle, envelope and payload (digest recomputed) but its original signature: the signature covers the 0.1 input.",
		rawJSON(t, bad), VerifyOptions{}, "invalid source signature"))
	bad = base1
	bad.Protocol = Protocol02
	bad.Statement.Protocol = Protocol02
	out = append(out, rejectCase(t, "reject/cross-version-0.1-signature-relabelled-0.2-envelope-only",
		"A genuine 0.1 statement with only the bundle and envelope protocol changed to 0.2, its payload and signature untouched.",
		rawJSON(t, bad), VerifyOptions{}, "invalid source signature"))

	// Unknown versions fail closed.
	for _, tc := range []struct{ name, reason, value, wantErr string }{
		{"reject/unknown-bundle-protocol", "A bundle whose protocol names a version this profile does not define is rejected.", "https://ifandonlyif.io/apostille/spec/0.3", "unsupported bundle protocol"},
		{"reject/empty-bundle-protocol", "An empty bundle protocol selects no rule set.", "", "unsupported bundle protocol"},
	} {
		value := tc.value
		out = append(out, rejectCase(t, tc.name, tc.reason,
			mutateJSON(t, b2, func(m map[string]any) { m["protocol"] = value }), opts, tc.wantErr))
	}
	out = append(out, rejectCase(t, "reject/unknown-envelope-protocol",
		"An envelope naming an unknown version inside a 0.2 bundle.",
		mutateJSON(t, b2, func(m map[string]any) {
			m["statement"].(map[string]any)["protocol"] = "https://ifandonlyif.io/apostille/spec/0.3"
		}), opts, "bundle mixes protocol versions"))
	return out
}
