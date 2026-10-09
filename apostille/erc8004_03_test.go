package apostille

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// erc8004Vector03Nonce is the fixed request nonce of the published known-answer
// document; a random nonce would make its signatures irreproducible.
const erc8004Vector03Nonce = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

func erc8004Vector03Path() string {
	return filepath.Join("..", "testdata", "apostille", "erc8004-binding-0.3.json")
}

type erc8004Vector03 struct {
	Profile        string                 `json:"profile"`
	CoreProtocol   string                 `json:"core_protocol"`
	EvaluationTime string                 `json:"evaluation_time"`
	Issuer         string                 `json:"issuer"`
	IssuerKeyID    string                 `json:"issuer_key_id"`
	AdminPublicKey string                 `json:"admin_public_key"`
	AgentPublicKey string                 `json:"agent_public_key"`
	OwnerAddress   string                 `json:"owner_address"`
	OwnerMessage   string                 `json:"owner_message"`
	Document       ERC8004BindingDocument `json:"document"`
}

func buildERC8004Vector03(t *testing.T) erc8004Vector03 {
	m := erc8004MaterialFor(t, bindingProfile03, erc8004Vector03Nonce)
	message, err := ERC8004OwnerMessage(m.request)
	require.NoError(t, err)
	return erc8004Vector03{Profile: ERC8004Profile03, CoreProtocol: Protocol03, EvaluationTime: fixedNow.Add(time.Minute).Format(TimestampLayout), Issuer: exampleIssuer, IssuerKeyID: m.issuer.KeyID(), AdminPublicKey: m.admin.PublicKey(), AgentPublicKey: m.agent.PublicKey(), OwnerAddress: m.identity.OwnerAddress, OwnerMessage: message, Document: m.doc}
}

// TestWriteERC8004BindingVector03 compares the 0.3 known-answer document with
// the file on disk and, only when UPDATE_APOSTILLE_ERC8004_03=1 (a variable no
// other writer reads), rewrites it. Every signature in it is deterministic ML-DSA-65
// (test-only path) or RFC 6979 secp256k1.
func TestWriteERC8004BindingVector03(t *testing.T) {
	raw, err := json.MarshalIndent(buildERC8004Vector03(t), "", "  ")
	require.NoError(t, err)
	raw = append(raw, '\n')
	if os.Getenv("UPDATE_APOSTILLE_ERC8004_03") == "1" {
		require.NoError(t, os.WriteFile(erc8004Vector03Path(), raw, 0o644))
	}
	existing, err := os.ReadFile(erc8004Vector03Path())
	require.NoError(t, err)
	require.True(t, bytes.Equal(existing, raw), "vector mismatch; run UPDATE_APOSTILLE_ERC8004_03=1 GOWORK=off go test -run '^TestWriteERC8004BindingVector03$' -count=1 ./apostille to regenerate")
}

func TestERC8004BindingVector03KnownAnswer(t *testing.T) {
	raw, err := os.ReadFile(erc8004Vector03Path())
	require.NoError(t, err)
	var v erc8004Vector03
	require.NoError(t, StrictJSON(raw, &v))
	at, err := Timestamp(v.EvaluationTime)
	require.NoError(t, err)
	got, err := VerifyERC8004Binding(v.Document, VerifyOptions{ExpectedIssuer: v.Issuer, TrustedKeyIDs: []string{v.IssuerKeyID}, Now: at})
	require.NoError(t, err)
	require.Equal(t, ERC8004Profile03, got.Protocol)
	require.Equal(t, "pinned", got.IssuerTrust)
	require.Equal(t, "within_validity", got.Freshness)
	require.Equal(t, Protocol03, v.Document.Delegation.Protocol)
	require.Equal(t, Algorithm03, v.Document.Binding.Signature.Algorithm)
	require.Len(t, v.Document.Binding.Signature.PublicKey, 2603)
	require.Len(t, v.Document.Binding.Signature.Value, 4412)
	message, err := ERC8004OwnerMessage(snapshotRequest(v.Document.Binding))
	require.NoError(t, err)
	require.Equal(t, v.OwnerMessage, message)
	require.True(t, strings.HasPrefix(message, "iff-apostille/erc8004-binding/owner/0.3\nissuer:"))
}

// snapshotRequest returns the request envelope inside a verified snapshot.
func snapshotRequest(e Envelope) Envelope {
	var b ERC8004Binding
	if _, err := decodeERC8004(e, KindERC8004Binding, &b); err != nil {
		panic(err)
	}
	return b.Request
}

// rebind re-signs the snapshot of m with change applied and attaches it to doc.
func rebind(t *testing.T, prof *bindingProfile, m erc8004Material, change func(*ERC8004Binding), doc ERC8004BindingDocument) ERC8004BindingDocument {
	t.Helper()
	var b ERC8004Binding
	_, err := decodeERC8004(m.doc.Binding, KindERC8004Binding, &b)
	require.NoError(t, err)
	change(&b)
	doc.Binding, err = m.issuer.signERC8004(prof, KindERC8004Binding, b)
	require.NoError(t, err)
	return doc
}

func TestERC8004OwnerTextFirstLine03(t *testing.T) {
	m := erc8004MaterialFor(t, bindingProfile03, "")
	message, err := ERC8004OwnerMessage(m.request)
	require.NoError(t, err)
	lines := strings.Split(message, "\n")
	require.Equal(t, "iff-apostille/erc8004-binding/owner/0.3", lines[0])
	m1 := erc8004MaterialFor(t, bindingProfile01, "")
	message1, err := ERC8004OwnerMessage(m1.request)
	require.NoError(t, err)
	require.Equal(t, "iff-apostille/erc8004-binding/owner/0.1", strings.Split(message1, "\n")[0])
	require.Len(t, lines, len(strings.Split(message1, "\n")))
	// An owner signature made over the 0.1 first line does not recover the owner
	// from the 0.3 text: the consent is bound to the profile.
	downgraded := "iff-apostille/erc8004-binding/owner/0.1\n" + strings.Join(lines[1:], "\n")
	sig, err := crypto.Sign(accounts.TextHash([]byte(downgraded)), m.wallet)
	require.NoError(t, err)
	pub, err := crypto.SigToPub(accounts.TextHash([]byte(message)), sig)
	if err == nil {
		require.NotEqual(t, m.identity.OwnerAddress, strings.ToLower(crypto.PubkeyToAddress(*pub).Hex()))
	}
	good, err := crypto.Sign(accounts.TextHash([]byte(message)), m.wallet)
	require.NoError(t, err)
	pub, err = crypto.SigToPub(accounts.TextHash([]byte(message)), good)
	require.NoError(t, err)
	require.Equal(t, m.identity.OwnerAddress, strings.ToLower(crypto.PubkeyToAddress(*pub).Hex()))
}

func TestERC8004Hedged03Signers(t *testing.T) {
	m := erc8004MaterialFor(t, bindingProfile03, "")
	admin, issuer := *m.admin, *m.issuer
	admin.deterministic, issuer.deterministic = false, false
	req, err := CreateERC8004Request(&admin, m.reg, m.identity, exampleIssuer, fixedNow)
	require.NoError(t, err)
	doc, err := issuer.IssueERC8004Binding(m.reg, req, "0x"+strings.Repeat("11", 65), ERC8004Observation{BlockNumber: "1", BlockHash: "0x" + strings.Repeat("a", 64), BlockTimestamp: fixedNow.Format(TimestampLayout)}, exampleIssuer, fixedNow)
	require.NoError(t, err)
	_, err = VerifyERC8004Binding(doc, VerifyOptions{})
	require.NoError(t, err)
}

func TestERC8004Negatives03(t *testing.T) {
	m := erc8004MaterialFor(t, bindingProfile03, "")
	m1 := erc8004MaterialFor(t, bindingProfile01, "")
	reject := func(t *testing.T, doc ERC8004BindingDocument) {
		t.Helper()
		_, err := VerifyERC8004Binding(doc, VerifyOptions{})
		require.Error(t, err)
	}
	t.Run("baseline", func(t *testing.T) {
		_, err := VerifyERC8004Binding(m.doc, VerifyOptions{})
		require.NoError(t, err)
	})
	t.Run("ed25519_signature_in_0.3_document", func(t *testing.T) {
		// The 0.1 snapshot envelope relabelled as 0.3, algorithm and all.
		doc := m.doc
		doc.Binding = m1.doc.Binding
		doc.Binding.Protocol = ERC8004Profile03
		reject(t, doc)
		// An Ed25519 key and signature under a 0.3 label and the 0.3 domain.
		var b ERC8004Binding
		_, err := decodeERC8004(m.doc.Binding, KindERC8004Binding, &b)
		require.NoError(t, err)
		ed := testSigner(t, 3)
		raw, err := Canonical(b)
		require.NoError(t, err)
		input, err := bindingProfile03.input(KindERC8004Binding, raw)
		require.NoError(t, err)
		forged := Envelope{Protocol: ERC8004Profile03, Kind: KindERC8004Binding, Payload: rawURL.EncodeToString(raw), PayloadSHA256: Hash(raw), Signature: Signature{Algorithm: Algorithm, KeyID: ed.KeyID(), PublicKey: ed.PublicKey(), Value: rawURL.EncodeToString(mustMessageSig(t, ed, input))}}
		doc = m.doc
		doc.Binding = forged
		reject(t, doc)
		forged.Signature.Algorithm = Algorithm03
		doc.Binding = forged
		reject(t, doc)
	})
	t.Run("ed25519_signer_refused", func(t *testing.T) {
		_, err := testSigner(t, 1).signERC8004(bindingProfile03, KindERC8004Request, struct{}{})
		require.Error(t, err)
		_, err = m.admin.signERC8004(bindingProfile01, KindERC8004Request, struct{}{})
		require.Error(t, err)
	})
	t.Run("ed25519_key_in_0.3_envelope", func(t *testing.T) {
		doc := m.doc
		doc.Binding.Signature.PublicKey = m1.admin.PublicKey()
		doc.Binding.Signature.KeyID = m1.admin.KeyID()
		reject(t, doc)
	})
	t.Run("0.1_request_inside_0.3_document", func(t *testing.T) {
		reject(t, rebind(t, bindingProfile03, m, func(b *ERC8004Binding) { b.Request = m1.request }, m.doc))
	})
	t.Run("0.3_request_inside_0.1_document", func(t *testing.T) {
		reject(t, rebind(t, bindingProfile01, m1, func(b *ERC8004Binding) { b.Request = m.request }, m1.doc))
	})
	t.Run("0.1_document_with_0.3_envelope", func(t *testing.T) {
		doc := m.doc
		doc.Protocol = ERC8004Profile
		reject(t, doc)
		doc = m1.doc
		doc.Protocol = ERC8004Profile03
		reject(t, doc)
		doc = m.doc
		doc.Binding = m1.doc.Binding
		reject(t, doc)
	})
	t.Run("core_0.1_registration_under_0.3_request", func(t *testing.T) {
		doc := m.doc
		doc.Delegation, doc.Acceptance = m1.doc.Delegation, m1.doc.Acceptance
		reject(t, doc)
		_, err := VerifyERC8004Request(m.request, &m1.reg, fixedNow)
		require.Error(t, err)
		_, err = m.issuer.IssueERC8004Binding(m1.reg, m.request, "0x"+strings.Repeat("11", 65), ERC8004Observation{BlockNumber: "1", BlockHash: "0x" + strings.Repeat("a", 64), BlockTimestamp: fixedNow.Format(TimestampLayout)}, exampleIssuer, fixedNow)
		require.Error(t, err)
	})
	t.Run("core_0.3_registration_under_0.1_request", func(t *testing.T) {
		doc := m1.doc
		doc.Delegation, doc.Acceptance = m.doc.Delegation, m.doc.Acceptance
		reject(t, doc)
		_, err := VerifyERC8004Request(m1.request, &m.reg, fixedNow)
		require.Error(t, err)
	})
	t.Run("mixed_delegation_and_acceptance", func(t *testing.T) {
		doc := m.doc
		doc.Acceptance = m1.doc.Acceptance
		reject(t, doc)
	})
	t.Run("payload_protocol_differs_from_envelope", func(t *testing.T) {
		var p ERC8004Request
		_, err := decodeERC8004(m.request, KindERC8004Request, &p)
		require.NoError(t, err)
		p.Protocol = ERC8004Profile
		raw, err := Canonical(p)
		require.NoError(t, err)
		e := resignRaw(t, bindingProfile03, m.admin, m.request, raw)
		_, err = VerifyERC8004Request(e, nil, time.Time{})
		require.Error(t, err)
	})
	t.Run("0.1_domain_with_0.3_key", func(t *testing.T) {
		for _, kind := range []string{KindERC8004Request, KindERC8004Binding} {
			e := m.request
			signer := m.admin
			if kind == KindERC8004Binding {
				e, signer = m.doc.Binding, m.issuer
			}
			raw, err := rawURL.DecodeString(e.Payload)
			require.NoError(t, err)
			e = resignRaw(t, bindingProfile01, signer, e, raw)
			_, err = decodeERC8004(e, kind, new(struct{}))
			require.Error(t, err)
			doc := m.doc
			if kind == KindERC8004Binding {
				doc.Binding = e
				reject(t, doc)
			} else {
				_, err = VerifyERC8004Request(e, nil, time.Time{})
				require.Error(t, err)
			}
		}
	})
	t.Run("request_and_snapshot_domains_swapped", func(t *testing.T) {
		raw, err := rawURL.DecodeString(m.request.Payload)
		require.NoError(t, err)
		input, err := bindingProfile03.input(KindERC8004Binding, raw)
		require.NoError(t, err)
		e := m.request
		e.Signature.Value = rawURL.EncodeToString(mustMessageSig(t, m.admin, input))
		_, err = VerifyERC8004Request(e, nil, time.Time{})
		require.Error(t, err)
	})
	t.Run("signature_and_key_encoding", func(t *testing.T) {
		sig, key := m.request.Signature.Value, m.request.Signature.PublicKey
		require.Len(t, sig, 4412)
		require.Len(t, key, 2603)
		for name, change := range map[string]func(*Envelope){
			"short_signature":       func(e *Envelope) { e.Signature.Value = sig[:len(sig)-4] },
			"long_signature":        func(e *Envelope) { e.Signature.Value = sig + "AAAA" },
			"padded_signature":      func(e *Envelope) { e.Signature.Value = sig + "=" },
			"noncanonical_key_tail": func(e *Envelope) { e.Signature.PublicKey = nonCanonicalTail(t, key) },
			"short_key":             func(e *Envelope) { e.Signature.PublicKey = key[:len(key)-4] },
			"long_key":              func(e *Envelope) { e.Signature.PublicKey = key + "AAAA" },
			"flipped_signature":     func(e *Envelope) { e.Signature.Value = flipFirst(sig) },
			"wrong_key_id":          func(e *Envelope) { e.Signature.KeyID = m.issuer.KeyID() },
			"payload_digest":        func(e *Envelope) { e.PayloadSHA256 = strings.Repeat("0", 64) },
			"algorithm_ed25519":     func(e *Envelope) { e.Signature.Algorithm = Algorithm },
			"algorithm_lowercase":   func(e *Envelope) { e.Signature.Algorithm = "ml-dsa-65" },
		} {
			t.Run(name, func(t *testing.T) {
				e := m.request
				change(&e)
				_, err := VerifyERC8004Request(e, nil, time.Time{})
				require.Error(t, err)
			})
		}
	})
	t.Run("admin_not_registration_owner", func(t *testing.T) {
		_, err := CreateERC8004Request(m.issuer, m.reg, m.identity, exampleIssuer, fixedNow)
		require.Error(t, err)
	})
	t.Run("pin_and_audience", func(t *testing.T) {
		v, err := VerifyERC8004Binding(m.doc, VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{m.admin.KeyID()}})
		require.NoError(t, err)
		require.Equal(t, "unknown", v.IssuerTrust)
		_, err = VerifyERC8004Binding(m.doc, VerifyOptions{ExpectedIssuer: "https://other.example/apostille"})
		require.Error(t, err)
	})
}

func mustMessageSig(t *testing.T, s *Signer, message []byte) []byte {
	t.Helper()
	sig, err := s.signMessage(message)
	require.NoError(t, err)
	return sig
}

func flipFirst(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}
