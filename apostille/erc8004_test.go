package apostille

import (
	"bytes"
	"crypto/ed25519"
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

func erc8004Fixture(t *testing.T) (ERC8004BindingDocument, *Signer, *Signer) {
	t.Helper()
	bundle, admin, _, issuer := fixture(t)
	reg := AgentRegistration{Delegation: *bundle.Delegation, Acceptance: *bundle.Acceptance}
	wallet, err := crypto.ToECDSA(bytes.Repeat([]byte{4}, 32))
	require.NoError(t, err)
	req, err := CreateERC8004Request(admin, reg, ERC8004Identity{ChainID: "8453", RegistryAddress: "0x1111111111111111111111111111111111111111", ERC8004AgentID: "115792089237316195423570985008687907853269984665640564039457584007913129639935", OwnerAddress: strings.ToLower(crypto.PubkeyToAddress(wallet.PublicKey).Hex())}, exampleIssuer, fixedNow)
	require.NoError(t, err)
	message, err := ERC8004OwnerMessage(req)
	require.NoError(t, err)
	sig, err := crypto.Sign(accounts.TextHash([]byte(message)), wallet)
	require.NoError(t, err)
	sig[64] += 27
	doc, err := issuer.IssueERC8004Binding(reg, req, "0x"+hex.EncodeToString(sig), ERC8004Observation{BlockNumber: "123456", BlockHash: "0x" + strings.Repeat("a", 64), BlockTimestamp: fixedNow.Add(-time.Minute).Format(TimestampLayout)}, exampleIssuer, fixedNow)
	require.NoError(t, err)
	return doc, admin, issuer
}

func TestERC8004DetachedProfileAndHistoricalTrust(t *testing.T) {
	doc, _, issuer := erc8004Fixture(t)
	_, err := VerifyEnvelope(doc.Binding)
	require.Error(t, err, "Core 0.1 must reject the separate profile")
	for _, tc := range []struct {
		now       time.Time
		freshness string
	}{{fixedNow, "within_validity"}, {fixedNow.Add(time.Hour), "expired"}, {fixedNow.Add(-time.Second), "not_yet_valid"}, {time.Time{}, "not_checked"}} {
		v, err := VerifyERC8004Binding(doc, VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{issuer.KeyID()}, Now: tc.now})
		require.NoError(t, err)
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
}

func TestERC8004CrossBindingsAndValidity(t *testing.T) {
	doc, admin, issuer := erc8004Fixture(t)
	var snapshot ERC8004Binding
	require.NoError(t, decodeERC8004(doc.Binding, KindERC8004Binding, &snapshot))
	var original ERC8004Request
	require.NoError(t, decodeERC8004(snapshot.Request, KindERC8004Request, &original))
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
			s.Request, err = admin.signERC8004(KindERC8004Request, p)
			require.NoError(t, err)
			changed := doc
			changed.Binding, err = issuer.signERC8004(KindERC8004Binding, s)
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
			changed.Binding, err = issuer.signERC8004(KindERC8004Binding, s)
			require.NoError(t, err)
			_, err = VerifyERC8004Binding(changed, VerifyOptions{})
			require.Error(t, err)
		})
	}
}

func TestERC8004RejectsBOMAndCrossDomainSignature(t *testing.T) {
	doc, _, issuer := erc8004Fixture(t)
	raw, err := rawURL.DecodeString(doc.Binding.Payload)
	require.NoError(t, err)
	for _, modified := range [][]byte{append([]byte{0xef, 0xbb, 0xbf}, raw...), append([]byte(" "), raw...)} {
		e := doc.Binding
		e.Payload = rawURL.EncodeToString(modified)
		e.PayloadSHA256 = Hash(modified)
		input, err := erc8004Input(e.Kind, modified)
		require.NoError(t, err)
		e.Signature.Value = rawURL.EncodeToString(ed25519.Sign(issuer.key, input))
		changed := doc
		changed.Binding = e
		_, err = VerifyERC8004Binding(changed, VerifyOptions{})
		require.Error(t, err)
	}
	changed := doc
	changed.Binding.Signature.Value = rawURL.EncodeToString(ed25519.Sign(issuer.key, signingInput(KindCertificate, raw)))
	_, err = VerifyERC8004Binding(changed, VerifyOptions{})
	require.Error(t, err)
}

func TestERC8004GoJavaScriptInteroperability(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	doc, admin, issuer := erc8004Fixture(t)
	module, err := filepath.Abs("../web/apostille-erc8004.mjs")
	require.NoError(t, err)
	coreModule, err := filepath.Abs("../web/apostille-core.mjs")
	require.NoError(t, err)
	input, _ := json.Marshal(map[string]any{"document": doc, "issuer": exampleIssuer, "pin": issuer.KeyID(), "now": fixedNow.Format(TimestampLayout), "key": map[string]string{"protocol": Protocol, "seed": rawURL.EncodeToString(admin.key.Seed()), "key_id": admin.KeyID(), "public_key": admin.PublicKey()}})
	script := `import {pathToFileURL} from 'node:url'; const m=await import(pathToFileURL(process.argv[1])); const c=await import(pathToFileURL(process.argv[2])); let raw='';for await(const chunk of process.stdin)raw+=chunk;const p=JSON.parse(raw);const v=await m.verifyERC8004Binding(p.document,{issuer:p.issuer,trustedKeyIDs:[p.pin],now:Date.parse(p.now)});const admin=await c.importKeyFile(p.key);const r=v.request;const request=await m.createERC8004Request(admin,{delegation:p.document.delegation,acceptance:p.document.acceptance},{chain_id:r.chain_id,registry_address:r.registry_address,erc8004_agent_id:r.erc8004_agent_id,owner_address:r.owner_address},p.issuer,new Date(p.now));process.stdout.write(JSON.stringify({verification:v,request,message:await m.erc8004OwnerMessage(request)}));`
	cmd := exec.Command(node, "--input-type=module", "-e", script, module, coreModule)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	require.NoError(t, err, stderr.String())
	var result struct {
		Verification ERC8004Verification `json:"verification"`
		Request      Envelope            `json:"request"`
		Message      string              `json:"message"`
	}
	require.NoError(t, json.Unmarshal(output, &result))
	require.Equal(t, "pinned", result.Verification.IssuerTrust)
	reg := AgentRegistration{Delegation: doc.Delegation, Acceptance: doc.Acceptance}
	_, err = VerifyERC8004Request(result.Request, &reg, fixedNow)
	require.NoError(t, err)
	message, err := ERC8004OwnerMessage(result.Request)
	require.NoError(t, err)
	require.Equal(t, message, result.Message)
}
