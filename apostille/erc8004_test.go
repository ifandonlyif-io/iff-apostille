package apostille

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// erc8004Profiles are the binding profiles every shared test runs under.
var erc8004Profiles = []*bindingProfile{bindingProfile01, bindingProfile03}

func erc8004Fixture(t *testing.T) (ERC8004BindingDocument, *Signer, *Signer) {
	t.Helper()
	return erc8004FixtureFor(t, bindingProfile01)
}

// erc8004Wallet is the public test wallet (key 0x0404...04).
func erc8004Wallet(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	wallet, err := crypto.ToECDSA(bytes.Repeat([]byte{4}, 32))
	require.NoError(t, err)
	return wallet
}

// erc8004Material is everything one binding fixture is built from.
type erc8004Material struct {
	doc                  ERC8004BindingDocument
	reg                  AgentRegistration
	admin, agent, issuer *Signer
	wallet               *ecdsa.PrivateKey
	identity             ERC8004Identity
	request              Envelope
}

func erc8004FixtureFor(t *testing.T, prof *bindingProfile) (ERC8004BindingDocument, *Signer, *Signer) {
	t.Helper()
	m := erc8004MaterialFor(t, prof, "")
	return m.doc, m.admin, m.issuer
}

// erc8004MaterialFor builds a signed binding of prof. A nonce makes it
// reproducible; the empty nonce draws a random one.
func erc8004MaterialFor(t *testing.T, prof *bindingProfile, nonce string) erc8004Material {
	t.Helper()
	bundle, admin, agent, issuer := fixtureFor(t, prof.core.protocol)
	reg := AgentRegistration{Delegation: *bundle.Delegation, Acceptance: *bundle.Acceptance}
	wallet := erc8004Wallet(t)
	identity := ERC8004Identity{ChainID: "8453", RegistryAddress: "0x1111111111111111111111111111111111111111", ERC8004AgentID: "115792089237316195423570985008687907853269984665640564039457584007913129639935", OwnerAddress: strings.ToLower(crypto.PubkeyToAddress(wallet.PublicKey).Hex())}
	var req Envelope
	var err error
	if nonce == "" {
		req, err = CreateERC8004Request(admin, reg, identity, exampleIssuer, fixedNow)
	} else {
		req, err = createERC8004Request(admin, reg, identity, exampleIssuer, nonce, fixedNow)
	}
	require.NoError(t, err)
	message, err := ERC8004OwnerMessage(req)
	require.NoError(t, err)
	sig, err := crypto.Sign(accounts.TextHash([]byte(message)), wallet)
	require.NoError(t, err)
	sig[64] += 27
	doc, err := issuer.IssueERC8004Binding(reg, req, "0x"+hex.EncodeToString(sig), ERC8004Observation{BlockNumber: "123456", BlockHash: "0x" + strings.Repeat("a", 64), BlockTimestamp: fixedNow.Add(-time.Minute).Format(TimestampLayout)}, exampleIssuer, fixedNow)
	require.NoError(t, err)
	return erc8004Material{doc: doc, reg: reg, admin: admin, agent: agent, issuer: issuer, wallet: wallet, identity: identity, request: req}
}

// eachERC8004Profile runs a test body once per binding profile.
func eachERC8004Profile(t *testing.T, body func(t *testing.T, prof *bindingProfile)) {
	for _, prof := range erc8004Profiles {
		t.Run(prof.domain, func(t *testing.T) { body(t, prof) })
	}
}

func TestERC8004DetachedProfileAndHistoricalTrust(t *testing.T) {
	eachERC8004Profile(t, func(t *testing.T, prof *bindingProfile) {
		doc, _, issuer := erc8004FixtureFor(t, prof)
		require.Equal(t, prof.protocol, doc.Protocol)
		_, err := VerifyEnvelope(doc.Binding)
		require.Error(t, err, "Core must reject the separate profile")
		for _, tc := range []struct {
			now       time.Time
			freshness string
		}{{fixedNow, "within_validity"}, {fixedNow.Add(time.Hour), "expired"}, {fixedNow.Add(-time.Second), "not_yet_valid"}, {time.Time{}, "not_checked"}} {
			v, err := VerifyERC8004Binding(doc, VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{issuer.KeyID()}, Now: tc.now})
			require.NoError(t, err)
			require.Equal(t, prof.protocol, v.Protocol)
			require.Equal(t, "pinned", v.IssuerTrust)
			require.Equal(t, tc.freshness, v.Freshness)
			require.Equal(t, "unknown", v.CurrentOwnership)
			require.Equal(t, "unproven", v.OrganizationBinding)
			require.Equal(t, "not_established", v.PaymentAuthority)
		}
		v, err := VerifyERC8004Binding(doc, VerifyOptions{TrustedKeyIDs: []string{issuer.KeyID()}})
		require.NoError(t, err)
		require.Equal(t, "unknown", v.IssuerTrust)
		_, err = VerifyERC8004Binding(doc, VerifyOptions{ExpectedIssuer: "https://other.example"})
		require.Error(t, err)
	})
}

func TestERC8004CrossBindingsAndValidity(t *testing.T) {
	eachERC8004Profile(t, func(t *testing.T, prof *bindingProfile) {
		doc, admin, issuer := erc8004FixtureFor(t, prof)
		var snapshot ERC8004Binding
		_, err := decodeERC8004(doc.Binding, KindERC8004Binding, &snapshot)
		require.NoError(t, err)
		var original ERC8004Request
		_, err = decodeERC8004(snapshot.Request, KindERC8004Request, &original)
		require.NoError(t, err)
		for name, change := range map[string]func(*ERC8004Request){
			"agent":      func(p *ERC8004Request) { p.AgentID = nonceID },
			"key":        func(p *ERC8004Request) { p.AgentKeyID = issuer.KeyID() },
			"delegation": func(p *ERC8004Request) { p.DelegationSHA256 = strings.Repeat("0", 64) },
			"audience":   func(p *ERC8004Request) { p.ServiceAudience = "https://other.example" },
			"uint256_overflow": func(p *ERC8004Request) {
				p.ERC8004AgentID = "115792089237316195423570985008687907853269984665640564039457584007913129639936"
			},
			"leading_zero":  func(p *ERC8004Request) { p.ChainID = "08453" },
			"zero_registry": func(p *ERC8004Request) { p.RegistryAddress = "0x" + strings.Repeat("0", 40) },
			"long_request":  func(p *ERC8004Request) { p.ExpiresAt = fixedNow.Add(6 * time.Minute).Format(TimestampLayout) },
			"expired_request_at_issue": func(p *ERC8004Request) {
				p.IssuedAt = fixedNow.Add(-5 * time.Minute).Format(TimestampLayout)
				p.ExpiresAt = fixedNow.Format(TimestampLayout)
			},
		} {
			t.Run(name, func(t *testing.T) {
				p := original
				change(&p)
				s := snapshot
				var err error
				s.Request, err = admin.signERC8004(prof, KindERC8004Request, p)
				require.NoError(t, err)
				changed := doc
				changed.Binding, err = issuer.signERC8004(prof, KindERC8004Binding, s)
				require.NoError(t, err)
				_, err = VerifyERC8004Binding(changed, VerifyOptions{})
				require.Error(t, err)
			})
		}
		for name, change := range map[string]func(*ERC8004Binding){
			"stale_block": func(p *ERC8004Binding) {
				p.BlockTimestamp = fixedNow.Add(-time.Hour - time.Second).Format(TimestampLayout)
			},
			"future_block": func(p *ERC8004Binding) {
				p.BlockTimestamp = fixedNow.Add(2*time.Minute + time.Second).Format(TimestampLayout)
			},
			"long_snapshot":         func(p *ERC8004Binding) { p.ExpiresAt = fixedNow.Add(time.Hour + time.Second).Format(TimestampLayout) },
			"false_scope":           func(p *ERC8004Binding) { p.Check = "organization_verified" },
			"bad_owner_proof_shape": func(p *ERC8004Binding) { p.OwnerSignature = "0x1234" },
		} {
			t.Run(name, func(t *testing.T) {
				s := snapshot
				change(&s)
				changed := doc
				var err error
				changed.Binding, err = issuer.signERC8004(prof, KindERC8004Binding, s)
				require.NoError(t, err)
				_, err = VerifyERC8004Binding(changed, VerifyOptions{})
				require.Error(t, err)
			})
		}
	})
}

// resignRaw replaces an envelope's payload bytes and signs them under prof with key.
func resignRaw(t *testing.T, prof *bindingProfile, key *Signer, e Envelope, modified []byte) Envelope {
	t.Helper()
	e.Payload = rawURL.EncodeToString(modified)
	e.PayloadSHA256 = Hash(modified)
	input, err := prof.input(e.Kind, modified)
	require.NoError(t, err)
	sig, err := key.signMessage(input)
	require.NoError(t, err)
	e.Signature.Value = rawURL.EncodeToString(sig)
	return e
}

func TestERC8004RejectsBOMAndCrossDomainSignature(t *testing.T) {
	eachERC8004Profile(t, func(t *testing.T, prof *bindingProfile) {
		doc, _, issuer := erc8004FixtureFor(t, prof)
		raw, err := rawURL.DecodeString(doc.Binding.Payload)
		require.NoError(t, err)
		for _, modified := range [][]byte{append([]byte{0xef, 0xbb, 0xbf}, raw...), append([]byte(" "), raw...)} {
			changed := doc
			changed.Binding = resignRaw(t, prof, issuer, doc.Binding, modified)
			_, err = VerifyERC8004Binding(changed, VerifyOptions{})
			require.Error(t, err)
		}
		changed := doc
		sig, err := issuer.signMessage(prof.core.signingInput(KindCertificate, raw))
		require.NoError(t, err)
		changed.Binding.Signature.Value = rawURL.EncodeToString(sig)
		_, err = VerifyERC8004Binding(changed, VerifyOptions{})
		require.Error(t, err)
	})
}

func TestERC8004CreatePicksProfileFromRegistrationAndRefusesMismatchedSigner(t *testing.T) {
	for _, prof := range erc8004Profiles {
		m := erc8004MaterialFor(t, prof, "")
		require.Equal(t, prof.protocol, m.request.Protocol)
		require.Equal(t, prof.protocol, m.doc.Binding.Protocol)
		require.Equal(t, prof.core.algorithm, m.request.Signature.Algorithm)
		require.Equal(t, prof.core.algorithm, m.doc.Binding.Signature.Algorithm)
		// An administrator of the other algorithm is refused, as is a registration of no profile.
		other := erc8004Profiles[0]
		if prof == other {
			other = erc8004Profiles[1]
		}
		wrong := testSignerFor(t, other.core.protocol, 1)
		_, err := CreateERC8004Request(wrong, m.reg, m.identity, exampleIssuer, fixedNow)
		require.Error(t, err)
		_, err = m.issuer.IssueERC8004Binding(m.reg, m.request, "0x"+strings.Repeat("11", 65), ERC8004Observation{BlockNumber: "1", BlockHash: "0x" + strings.Repeat("a", 64), BlockTimestamp: fixedNow.Format(TimestampLayout)}, exampleIssuer, fixedNow)
		require.NoError(t, err)
		_, err = wrong.IssueERC8004Binding(m.reg, m.request, "0x"+strings.Repeat("11", 65), ERC8004Observation{BlockNumber: "1", BlockHash: "0x" + strings.Repeat("a", 64), BlockTimestamp: fixedNow.Format(TimestampLayout)}, exampleIssuer, fixedNow)
		require.Error(t, err)
	}
	// There is no binding profile for a Core 0.2 registration.
	bundle, admin, _, _ := fixtureFor(t, Protocol02)
	_, err := CreateERC8004Request(admin, AgentRegistration{Delegation: *bundle.Delegation, Acceptance: *bundle.Acceptance}, ERC8004Identity{ChainID: "1", RegistryAddress: "0x1111111111111111111111111111111111111111", ERC8004AgentID: "1", OwnerAddress: "0x2222222222222222222222222222222222222222"}, exampleIssuer, fixedNow)
	require.Error(t, err)
	require.Equal(t, []string{ERC8004Profile, ERC8004Profile03}, KnownERC8004Profiles())
}

// keyFileOf is the JavaScript key file of a fixture signer: its seed is the
// repeated byte the fixtures use, which the signer no longer exposes directly.
func keyFileOf(s *Signer) map[string]string {
	if s.Algorithm() == Algorithm03 {
		return map[string]string{"protocol": Protocol03, "seed": rawURL.EncodeToString(s.ml.Bytes()), "key_id": s.KeyID(), "public_key": s.PublicKey()}
	}
	return map[string]string{"protocol": Protocol, "seed": rawURL.EncodeToString(s.key.Seed()), "key_id": s.KeyID(), "public_key": s.PublicKey()}
}

func runERC8004Node(t *testing.T, node, script string, args []string, input any) []byte {
	t.Helper()
	raw, err := json.Marshal(input)
	require.NoError(t, err)
	cmd := exec.Command(node, append([]string{"--input-type=module", "-e", script}, args...)...)
	cmd.Stdin = bytes.NewReader(raw)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	require.NoError(t, err, stderr.String())
	return output
}

// TestERC8004GoJavaScriptInteroperability checks, for each binding profile, that
// JavaScript verifies a Go document, that a JavaScript request is verified and
// issued in Go with the same owner text, and that JavaScript verifies the
// document Go issued over it.
func TestERC8004GoJavaScriptInteroperability(t *testing.T) {
	node, err := exec.LookPath("node")
	require.NoError(t, err, "node is required for the Go/JavaScript interoperability tests")
	module, err := filepath.Abs("../web/apostille-erc8004.mjs")
	require.NoError(t, err)
	coreModule, err := filepath.Abs("../web/apostille-core.mjs")
	require.NoError(t, err)
	create := `import {pathToFileURL} from 'node:url'; const m=await import(pathToFileURL(process.argv[1])); const c=await import(pathToFileURL(process.argv[2])); let raw='';for await(const chunk of process.stdin)raw+=chunk;const p=JSON.parse(raw);const v=await m.verifyERC8004Binding(p.document,{issuer:p.issuer,trustedKeyIDs:[p.pin],now:Date.parse(p.now)});const admin=await c.importKeyFile(p.key);const r=v.request;const request=await m.createERC8004Request(admin,{delegation:p.document.delegation,acceptance:p.document.acceptance},{chain_id:r.chain_id,registry_address:r.registry_address,erc8004_agent_id:r.erc8004_agent_id,owner_address:r.owner_address},p.issuer,new Date(p.now));process.stdout.write(JSON.stringify({verification:v,request,message:await m.erc8004OwnerMessage(request)}));`
	verify := `import {pathToFileURL} from 'node:url'; const m=await import(pathToFileURL(process.argv[1])); let raw='';for await(const chunk of process.stdin)raw+=chunk;const p=JSON.parse(raw);process.stdout.write(JSON.stringify(await m.verifyERC8004Binding(p.document,{issuer:p.issuer,trustedKeyIDs:[p.pin],now:Date.parse(p.now)})));`
	eachERC8004Profile(t, func(t *testing.T, prof *bindingProfile) {
		m := erc8004MaterialFor(t, prof, "")
		output := runERC8004Node(t, node, create, []string{module, coreModule}, map[string]any{"document": m.doc, "issuer": exampleIssuer, "pin": m.issuer.KeyID(), "now": fixedNow.Format(TimestampLayout), "key": keyFileOf(m.admin)})
		var result struct {
			Verification ERC8004Verification `json:"verification"`
			Request      Envelope            `json:"request"`
			Message      string              `json:"message"`
		}
		require.NoError(t, json.Unmarshal(output, &result))
		require.Equal(t, "pinned", result.Verification.IssuerTrust)
		require.Equal(t, prof.protocol, result.Verification.Protocol)
		require.Equal(t, prof.protocol, result.Request.Protocol)
		_, err = VerifyERC8004Request(result.Request, &m.reg, fixedNow)
		require.NoError(t, err)
		message, err := ERC8004OwnerMessage(result.Request)
		require.NoError(t, err)
		require.Equal(t, message, result.Message)
		sig, err := crypto.Sign(accounts.TextHash([]byte(message)), m.wallet)
		require.NoError(t, err)
		sig[64] += 27
		issued, err := m.issuer.IssueERC8004Binding(m.reg, result.Request, "0x"+hex.EncodeToString(sig), ERC8004Observation{BlockNumber: "7", BlockHash: "0x" + strings.Repeat("b", 64), BlockTimestamp: fixedNow.Add(-time.Minute).Format(TimestampLayout)}, exampleIssuer, fixedNow)
		require.NoError(t, err)
		_, err = VerifyERC8004Binding(issued, VerifyOptions{ExpectedIssuer: exampleIssuer})
		require.NoError(t, err)
		output = runERC8004Node(t, node, verify, []string{module}, map[string]any{"document": issued, "issuer": exampleIssuer, "pin": m.issuer.KeyID(), "now": fixedNow.Format(TimestampLayout)})
		var checked ERC8004Verification
		require.NoError(t, json.Unmarshal(output, &checked))
		require.Equal(t, "pinned", checked.IssuerTrust)
		require.Equal(t, prof.protocol, checked.Protocol)
	})
}
