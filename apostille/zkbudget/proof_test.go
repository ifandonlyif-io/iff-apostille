package zkbudget

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var testNow = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
var testSetup = sync.OnceValues(Setup)

func fixture(t *testing.T) (PrivateSnapshot, core.Bundle, Request, *core.Signer) {
	t.Helper()
	seed, _, err := core.GenerateKey()
	require.NoError(t, err)
	signer, err := core.NewSigner(seed)
	require.NoError(t, err)
	private, err := NewSnapshot([]string{"12500", "20000", "37500"}, SnapshotOptions{Scope: "project-demo", Currency: "USD", PeriodStart: "2026-09-01T00:00:00Z", PeriodEnd: "2026-09-14T00:00:00Z"})
	require.NoError(t, err)
	source, err := SignSnapshot(private.Snapshot, signer, nil, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", testNow)
	require.NoError(t, err)
	request, err := NewRequest(private.Snapshot, "budget-review-v1", "urn:example:audit", "70000", testNow)
	require.NoError(t, err)
	return private, source, request, signer
}

func testProver(t *testing.T) (*Prover, *Verifier, Parameters) {
	t.Helper()
	params, err := testSetup()
	require.NoError(t, err)
	prover, err := NewProver(params.ProvingKey, params.VerifyingKey, params.VerifyingKeySHA256)
	require.NoError(t, err)
	verifier, err := NewVerifier(params.VerifyingKey, params.VerifyingKeySHA256)
	require.NoError(t, err)
	return prover, verifier, params
}

func TestRealProofOfflineApostillePipeline(t *testing.T) {
	p, v, params := testProver(t)
	private, source, request, signer := fixture(t)
	start := time.Now()
	doc, err := p.Prove(private, source, request, testNow)
	require.NoError(t, err)
	proveDuration := time.Since(start)
	opts := VerifyOptions{ExpectedRequest: request, TrustedSourceKeyIDs: []string{signer.KeyID()}, Now: testNow}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	start = time.Now()
	result, err := v.VerifyJSON(raw, opts)
	require.NoError(t, err)
	require.Equal(t, "valid", result.ProofIntegrity)
	require.Equal(t, testNow.Format(time.RFC3339Nano), result.EvaluatedAt)
	require.Equal(t, "sum_within_limit", result.Predicate)
	require.Equal(t, "pinned_source_key", result.SourceTrust)
	require.Equal(t, "committed_vector_only", result.DatasetCompleteness)
	require.Equal(t, "not_established", result.ContentTruth)
	require.Equal(t, "unknown", result.CurrentAuthorization)
	require.Equal(t, "caller_required", result.ReplayProtection)
	require.Equal(t, "amounts_hidden_metadata_linkable", result.PrivacyScope)
	require.Equal(t, "unknown", result.CoreVerification.IssuerTrust)
	require.NotContains(t, string(raw), `"amounts"`)
	require.NotContains(t, string(raw), `"blinding"`)
	require.NotContains(t, string(raw), private.Blinding)
	t.Logf("real proof: prove=%s verify=%s proof=%d bytes document=%d bytes proving_key=%d bytes", proveDuration, time.Since(start), proofBytes, len(raw), len(params.ProvingKey))
	doc2, err := p.Prove(private, source, request, testNow)
	require.NoError(t, err)
	require.NotEqual(t, doc.Proof, doc2.Proof, "fresh Groth16 randomness")
	_, err = v.Verify(doc2, opts)
	require.NoError(t, err)
	// A proof is not a replay database: consuming the nonce is the caller's job.
	_, err = v.Verify(doc, opts)
	require.NoError(t, err)
	opts.Now = testNow.In(time.FixedZone("receiver", 8*60*60)).Add(1234 * time.Nanosecond)
	evaluated, err := v.Verify(doc, opts)
	require.NoError(t, err)
	require.Equal(t, "2026-09-14T12:00:00.000001234Z", evaluated.EvaluatedAt)
}

func TestProofRejectsChangedPolicySourceAndPrivateData(t *testing.T) {
	p, v, _ := testProver(t)
	private, source, request, signer := fixture(t)
	doc, err := p.Prove(private, source, request, testNow)
	require.NoError(t, err)
	opts := VerifyOptions{ExpectedRequest: request, TrustedSourceKeyIDs: []string{signer.KeyID()}, Now: testNow}
	for name, change := range map[string]func(*Request){
		"limit":    func(r *Request) { r.LimitMinor = "70001" },
		"audience": func(r *Request) { r.Audience = "urn:example:other" },
		"nonce":    func(r *Request) { r.Nonce = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		"policy":   func(r *Request) { r.PolicyID = "another-policy" },
		"expiry":   func(r *Request) { r.ExpiresAt = testNow.Add(6 * time.Minute).Format(core.TimestampLayout) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := doc
			change(&bad.Request)
			_, err := v.Verify(bad, opts)
			require.ErrorContains(t, err, "receiver request")
			changedOpts := opts
			changedOpts.ExpectedRequest = bad.Request
			_, err = v.Verify(bad, changedOpts)
			require.ErrorContains(t, err, "proof verification failed", "even matching outer JSON cannot rebind the proof")
		})
	}
	bad := doc
	bad.SourceBundle, err = SignSnapshot(private.Snapshot, signer, nil, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", testNow)
	require.NoError(t, err)
	_, err = v.Verify(bad, opts)
	require.ErrorContains(t, err, "proof verification failed", "valid replacement source signature is bound into proof")
	wrong := opts
	wrong.TrustedSourceKeyIDs = []string{"sha256:" + strings.Repeat("0", 64)}
	_, err = v.Verify(doc, wrong)
	require.ErrorContains(t, err, "source key")
	wrong = opts
	wrong.ExpectedRequest = Request{}
	_, err = v.Verify(doc, wrong)
	require.Error(t, err)
	wrong = opts
	wrong.Now = testNow.Add(5 * time.Minute)
	_, err = v.Verify(doc, wrong)
	require.ErrorContains(t, err, "expired")
	wrong = opts
	wrong.Now = testNow.Add(-time.Second)
	_, err = v.Verify(doc, wrong)
	require.Error(t, err)
	wrong = opts
	wrong.SourceIssuer = "urn:example:issuer"
	_, err = v.Verify(doc, wrong)
	require.ErrorContains(t, err, "both issuer and key")
	wrong.SourceIssuerKeyIDs = []string{signer.KeyID()}
	_, err = v.Verify(doc, wrong)
	require.ErrorContains(t, err, "certificate")
	private.Amounts = append([]string(nil), private.Amounts...)
	private.Amounts[0] = "1"
	_, err = p.Prove(private, source, request, testNow)
	require.ErrorContains(t, err, "does not open")
	private, source, request, _ = fixture(t)
	private.Amounts = private.Amounts[:2]
	_, err = p.Prove(private, source, request, testNow)
	require.ErrorContains(t, err, "does not open")
	private, source, request, _ = fixture(t)
	request.LimitMinor = "69999"
	_, err = p.Prove(private, source, request, testNow)
	require.ErrorContains(t, err, "predicate is not satisfied")
}

func TestProofStrictEncodingAndIndependentSetupPin(t *testing.T) {
	p, v, params := testProver(t)
	private, source, request, signer := fixture(t)
	doc, err := p.Prove(private, source, request, testNow)
	require.NoError(t, err)
	opts := VerifyOptions{ExpectedRequest: request, TrustedSourceKeyIDs: []string{signer.KeyID()}, Now: testNow}
	for _, pin := range []string{"", strings.Repeat("0", 64), strings.ToUpper(params.VerifyingKeySHA256)} {
		_, err := NewVerifier(params.VerifyingKey, pin)
		require.Error(t, err)
	}
	key := append(append([]byte(nil), params.VerifyingKey...), 0)
	_, err = NewVerifier(key, params.VerifyingKeySHA256)
	require.Error(t, err)
	_, err = NewVerifier(key, core.Hash(key))
	require.ErrorContains(t, err, "invalid trusted verification key")
	for _, proof := range []string{"", doc.Proof + "=", strings.Repeat("A", proofEncoding.EncodedLen(proofBytes)), doc.Proof + doc.Proof, "https://example.com/proof"} {
		bad := doc
		bad.Proof = proof
		_, err := v.Verify(bad, opts)
		require.Error(t, err)
	}
	proofRaw, err := proofEncoding.DecodeString(doc.Proof)
	require.NoError(t, err)
	proofRaw[0] ^= 1
	bad := doc
	bad.Proof = proofEncoding.EncodeToString(proofRaw)
	_, err = v.Verify(bad, opts)
	require.Error(t, err)
	for _, change := range []func(*Document){
		func(d *Document) { d.Profile += "/unknown" },
		func(d *Document) { d.CircuitID = "budget-16x48-mimc-bls12381-v1" },
		func(d *Document) { d.CircuitID += "-unknown" },
		func(d *Document) { d.Scheme += "-unknown" },
		func(d *Document) { d.VerifyingKeySHA256 = strings.Repeat("0", 64) },
		func(d *Document) { d.Snapshot.Currency = "EUR" },
	} {
		bad := doc
		change(&bad)
		_, err := v.Verify(bad, opts)
		require.Error(t, err)
	}
	raw, err := core.Canonical(doc)
	require.NoError(t, err)
	for _, malformed := range [][]byte{
		append([]byte{0xef, 0xbb, 0xbf}, raw...),
		append(raw, []byte("{}")...),
		bytes.Replace(raw, []byte(`"source_bundle":{`), []byte(`"source_bundle":{"extra":true,`), 1),
		bytes.Replace(raw, []byte(`"certificate":null,`), nil, 1),
		bytes.Replace(raw, []byte(`"limit_minor":"70000"`), []byte(`"limit_minor":70000`), 1),
	} {
		_, err := v.VerifyJSON(malformed, opts)
		require.Error(t, err)
	}
}

func assignmentFor(t *testing.T, p PrivateSnapshot, source core.Bundle, request Request) budgetCircuit {
	t.Helper()
	a, err := publicAssignment(p.Snapshot, request, source)
	require.NoError(t, err)
	for i := range a.Amounts {
		a.Amounts[i] = uint64(0)
		if i < len(p.Amounts) {
			a.Amounts[i], err = amount(p.Amounts[i], MaxAmount)
			require.NoError(t, err)
		}
	}
	a.Blinding, err = scalar(p.Blinding)
	require.NoError(t, err)
	return a
}

func field(v frontend.Variable) *big.Int {
	switch n := v.(type) {
	case *big.Int:
		return n
	case uint64:
		return new(big.Int).SetUint64(n)
	case int:
		return big.NewInt(int64(n))
	default:
		panic("unexpected test field")
	}
}

// Recommit malicious raw witnesses so failing constraints cannot be attributed
// merely to a mismatched hash. These tests bypass all Go input validation.
func recommit(a *budgetCircuit) {
	inputs := []*big.Int{domain("snapshot"), field(a.ContextHi), field(a.ContextLo), field(a.Count), field(a.Blinding)}
	for _, x := range a.Amounts {
		inputs = append(inputs, field(x))
	}
	a.Commitment = fieldHash(inputs...)
}

func TestCircuitRejectsAdversarialWitnesses(t *testing.T) {
	private, source, request, _ := fixture(t)
	good := assignmentFor(t, private, source, request)
	ccs, err := compile()
	require.NoError(t, err)
	solve := func(a budgetCircuit) error {
		w, err := frontend.NewWitness(&a, ecc.BLS12_381.ScalarField())
		if err != nil {
			return err
		}
		_, err = ccs.Solve(w, solver.WithLogger(zerolog.Nop()))
		return err
	}
	require.NoError(t, solve(good))
	for name, change := range map[string]func(*budgetCircuit){
		"over budget":         func(a *budgetCircuit) { a.Limit = uint64(69999) },
		"negative amount":     func(a *budgetCircuit) { a.Amounts[0] = new(big.Int).Sub(fr.Modulus(), big.NewInt(1)) },
		"amount overflow":     func(a *budgetCircuit) { a.Amounts[0] = uint64(1) << 48; a.Limit = MaxLimit },
		"field wrapped limit": func(a *budgetCircuit) { a.Limit = new(big.Int).Sub(fr.Modulus(), big.NewInt(1)) },
		"zero count":          func(a *budgetCircuit) { a.Count = 0 },
		"oversized count":     func(a *budgetCircuit) { a.Count = 17 },
		"nonzero padding":     func(a *budgetCircuit) { a.Amounts[15] = uint64(1); a.Limit = MaxLimit },
		"zero blinding":       func(a *budgetCircuit) { a.Blinding = 0 },
		"context overflow":    func(a *budgetCircuit) { a.ContextHi = new(big.Int).Lsh(big.NewInt(1), 128) },
		"source overflow":     func(a *budgetCircuit) { a.SourceHi = new(big.Int).Lsh(big.NewInt(1), 128) },
	} {
		t.Run(name, func(t *testing.T) { bad := good; change(&bad); recommit(&bad); require.Error(t, solve(bad)) })
	}
	max := good
	max.Count = MaxEntries
	max.Limit = MaxAmount * MaxEntries
	for i := range max.Amounts {
		max.Amounts[i] = MaxAmount
	}
	recommit(&max)
	require.NoError(t, solve(max))
	max.Limit = MaxAmount*MaxEntries - 1
	recommit(&max)
	require.Error(t, solve(max))
}

func TestSnapshotInputPrivacyAndBounds(t *testing.T) {
	p, _, _, s := fixture(t)
	p2, err := NewSnapshot(p.Amounts, SnapshotOptions{Scope: p.Snapshot.Scope, Currency: p.Snapshot.Currency, PeriodStart: p.Snapshot.PeriodStart, PeriodEnd: p.Snapshot.PeriodEnd})
	require.NoError(t, err)
	require.NotEqual(t, p.Blinding, p2.Blinding)
	require.NotEqual(t, p.Snapshot.Commitment, p2.Snapshot.Commitment)
	for _, values := range [][]string{nil, {}, {"-1"}, {"1.5"}, {"01"}, {"1e3"}, {strconv.FormatUint(MaxAmount+1, 10)}, make([]string, 17)} {
		_, err := NewSnapshot(values, SnapshotOptions{Scope: "demo", Currency: "USD", PeriodStart: p.Snapshot.PeriodStart, PeriodEnd: p.Snapshot.PeriodEnd})
		require.Error(t, err)
	}
	_, err = SignSnapshot(p.Snapshot, s, nil, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", testNow.Add(-24*time.Hour))
	require.ErrorContains(t, err, "closed")
	p.Blinding = strings.Repeat("f", 64)
	_, err = privateCommitment(p)
	require.Error(t, err)
}
