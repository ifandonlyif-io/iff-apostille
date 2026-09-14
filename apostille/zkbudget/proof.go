package zkbudget

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	g16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/rs/zerolog"
)

type Parameters struct {
	ProvingKey         []byte
	VerifyingKey       []byte
	VerifyingKeySHA256 string
	CircuitSHA256      string
}

// Setup is a SINGLE-PARTY DEVELOPMENT SETUP. A malicious setup operator who
// retains the toxic waste can forge proofs. No ceremony or trusted public setup
// is provided by this alpha. A verifier's independent pin is essential.
func Setup() (Parameters, error) {
	ccs, err := compile()
	if err != nil {
		return Parameters{}, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return Parameters{}, errors.New("budget setup failed")
	}
	p, err := serialize(pk)
	if err != nil {
		return Parameters{}, err
	}
	v, err := serialize(vk)
	if err != nil {
		return Parameters{}, err
	}
	info, err := InspectCircuit()
	if err != nil {
		return Parameters{}, err
	}
	return Parameters{p, v, core.Hash(v), info.CircuitSHA256}, nil
}

// CircuitInfo describes the locally compiled circuit, not a verification key.
// Its fingerprint is useful for reproduction/audit; it cannot establish that
// someone else's setup used this circuit or discarded its toxic waste.
type CircuitInfo struct {
	Profile       string `json:"profile"`
	CircuitID     string `json:"circuit_id"`
	Scheme        string `json:"scheme"`
	CircuitSHA256 string `json:"circuit_sha256"`
	Constraints   int    `json:"constraints"`
	PublicInputs  int    `json:"public_inputs"`
}

var circuitInfo = sync.OnceValues(func() (CircuitInfo, error) {
	ccs, err := compile()
	if err != nil {
		return CircuitInfo{}, err
	}
	raw, err := serialize(ccs)
	if err != nil {
		return CircuitInfo{}, err
	}
	return CircuitInfo{
		Profile: Profile, CircuitID: CircuitID, Scheme: Scheme, CircuitSHA256: core.Hash(raw),
		Constraints: ccs.GetNbConstraints(), PublicInputs: ccs.GetNbPublicVariables() - 1,
	}, nil
})

// InspectCircuit compiles and fingerprints the local circuit without a setup,
// parameter file, private witness or network access.
func InspectCircuit() (CircuitInfo, error) { return circuitInfo() }

var compiled = sync.OnceValues(func() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &budgetCircuit{})
})

func compile() (constraint.ConstraintSystem, error) { return compiled() }

func serialize(v io.WriterTo) ([]byte, error) {
	var b bytes.Buffer
	if _, err := v.WriteTo(&b); err != nil {
		return nil, errors.New("budget parameter serialization failed")
	}
	if b.Len() == 0 || b.Len() > MaxParametersBytes {
		return nil, errors.New("budget parameter size exceeds limit")
	}
	return b.Bytes(), nil
}

type Verifier struct {
	key groth16.VerifyingKey
	pin string
}
type Prover struct {
	key      groth16.ProvingKey
	verifier *Verifier
}

// NewVerifier accepts only an externally pinned verification key. Never copy
// expectedSHA256 from the presentation or an untrusted parameter download.
func NewVerifier(raw []byte, expectedSHA256 string) (*Verifier, error) {
	if len(raw) == 0 || len(raw) > MaxParametersBytes || !hexDigest.MatchString(expectedSHA256) || core.Hash(raw) != expectedSHA256 {
		return nil, errors.New("independent verification-key pin does not match")
	}
	if err := validateVerificationKeyBytes(raw); err != nil {
		return nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	r := bytes.NewReader(raw)
	if _, err := vk.ReadFrom(r); err != nil || r.Len() != 0 {
		return nil, errors.New("invalid trusted verification key")
	}
	k := vk.(*g16.VerifyingKey)
	if vk.NbPublicWitness() != publicInputs || len(k.CommitmentKeys) != 0 || len(k.PublicAndCommitmentCommitted) != 0 || k.G1.Alpha.IsInfinity() || k.G2.Beta.IsInfinity() || k.G2.Gamma.IsInfinity() || k.G2.Delta.IsInfinity() {
		return nil, errors.New("verification key does not support the budget circuit")
	}
	return &Verifier{key: vk, pin: expectedSHA256}, nil
}

// The proving key is a trusted, locally generated setup artifact, not a network
// input. Verify a proof with the independently pinned verifier before returning.
func NewProver(pk, vk []byte, expectedSHA256 string) (*Prover, error) {
	v, err := NewVerifier(vk, expectedSHA256)
	if err != nil {
		return nil, err
	}
	if len(pk) == 0 || len(pk) > MaxParametersBytes {
		return nil, errors.New("invalid proving-key size")
	}
	if err := validateProvingKeyBytes(pk); err != nil {
		return nil, err
	}
	k := groth16.NewProvingKey(ecc.BLS12_381)
	r := bytes.NewReader(pk)
	if _, err := k.ReadFrom(r); err != nil || r.Len() != 0 {
		return nil, errors.New("invalid local proving key")
	}
	return &Prover{key: k, verifier: v}, nil
}

type Document struct {
	Profile            string      `json:"profile"`
	CircuitID          string      `json:"circuit_id"`
	Scheme             string      `json:"scheme"`
	VerifyingKeySHA256 string      `json:"verifying_key_sha256"`
	Snapshot           Snapshot    `json:"snapshot"`
	SourceBundle       core.Bundle `json:"source_bundle"`
	Request            Request     `json:"request"`
	Proof              string      `json:"proof"`
}

type VerifyOptions struct {
	ExpectedRequest     Request
	TrustedSourceKeyIDs []string
	Now                 time.Time
	SourceIssuer        string
	SourceIssuerKeyIDs  []string
}

type Verification struct {
	Profile              string            `json:"profile"`
	EvaluatedAt          string            `json:"evaluated_at"`
	ProofIntegrity       string            `json:"proof_integrity"`
	Predicate            string            `json:"predicate"`
	SourceTrust          string            `json:"source_trust"`
	SnapshotSHA256       string            `json:"snapshot_sha256"`
	PolicyID             string            `json:"policy_id"`
	Audience             string            `json:"audience"`
	Nonce                string            `json:"nonce"`
	SetupTrust           string            `json:"setup_trust"`
	DatasetCompleteness  string            `json:"dataset_completeness"`
	ContentTruth         string            `json:"content_truth"`
	CurrentAuthorization string            `json:"current_authorization"`
	ReplayProtection     string            `json:"replay_protection"`
	PrivacyScope         string            `json:"privacy_scope"`
	CoreVerification     core.Verification `json:"core_verification"`
}

func checkSource(s Snapshot, source core.Bundle, now time.Time, opts core.VerifyOptions) (core.Verification, error) {
	raw, err := SnapshotBytes(s)
	if err != nil {
		return core.Verification{}, err
	}
	v, err := core.VerifyBundle(source, opts)
	if err != nil || !core.VerifyArtifact(v, raw) || v.Statement.ArtifactMediaType != SnapshotMediaType {
		return core.Verification{}, errors.New("source signature does not authenticate this snapshot")
	}
	issued, err := core.Timestamp(v.Statement.IssuedAt)
	end, _ := core.Timestamp(s.PeriodEnd)
	if err != nil || issued.Before(end) || issued.After(now) {
		return core.Verification{}, errors.New("source snapshot has an invalid signing time")
	}
	if source.Delegation != nil {
		// Producer-only Core bundles do not otherwise evaluate delegation time.
		if _, err := core.VerifyRegistration(core.AgentRegistration{Delegation: *source.Delegation, Acceptance: *source.Acceptance}, "", issued); err != nil {
			return core.Verification{}, errors.New("source delegation was not active at signing")
		}
	}
	if opts.ExpectedIssuer != "" || len(opts.TrustedKeyIDs) > 0 {
		if v.IssuerTrust != "accepted_by_policy" || v.Freshness != "valid_at_evaluation_time" {
			return core.Verification{}, errors.New("source certificate does not satisfy issuer policy")
		}
	}
	return v, nil
}

func (p *Prover) Prove(private PrivateSnapshot, source core.Bundle, request Request, now time.Time) (Document, error) {
	if p == nil || p.key == nil || p.verifier == nil {
		return Document{}, errors.New("budget prover is not initialized")
	}
	if err := validateRequest(request, now); err != nil {
		return Document{}, err
	}
	commitment, err := privateCommitment(private)
	if err != nil || commitment != private.Snapshot.Commitment {
		return Document{}, errors.New("private data does not open the signed commitment")
	}
	if _, err := checkSource(private.Snapshot, source, now, core.VerifyOptions{Now: now}); err != nil {
		return Document{}, err
	}
	assignment, err := publicAssignment(private.Snapshot, request, source)
	if err != nil {
		return Document{}, err
	}
	var total uint64
	for i := 0; i < MaxEntries; i++ {
		var n uint64
		if i < len(private.Amounts) {
			n, _ = amount(private.Amounts[i], MaxAmount)
		}
		assignment.Amounts[i] = n
		total += n
	}
	limit, _ := amount(request.LimitMinor, MaxLimit)
	if total > limit {
		return Document{}, errors.New("budget predicate is not satisfied")
	}
	assignment.Blinding, _ = scalar(private.Blinding)
	ccs, err := compile()
	if err != nil {
		return Document{}, errors.New("budget circuit compilation failed")
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return Document{}, errors.New("invalid budget witness")
	}
	proof, err := groth16.Prove(ccs, p.key, witness, backend.WithSolverOptions(solver.WithLogger(zerolog.Nop())))
	if err != nil {
		return Document{}, errors.New("budget proof generation failed")
	}
	public, err := witness.Public()
	if err != nil {
		return Document{}, errors.New("invalid budget public witness")
	}
	if err := groth16.Verify(proof, p.verifier.key, public); err != nil {
		return Document{}, errors.New("proving key does not match pinned verification key")
	}
	encoded, err := encodeProof(proof.(*g16.Proof))
	if err != nil {
		return Document{}, err
	}
	return Document{Profile: Profile, CircuitID: CircuitID, Scheme: Scheme, VerifyingKeySHA256: p.verifier.pin, Snapshot: private.Snapshot, SourceBundle: source, Request: request, Proof: encoded}, nil
}

func (v *Verifier) VerifyJSON(raw []byte, opts VerifyOptions) (Verification, error) {
	var doc Document
	if err := core.StrictJSON(raw, &doc); err != nil {
		return Verification{}, err
	}
	var input any
	if err := core.StrictJSON(raw, &input); err != nil {
		return Verification{}, err
	}
	a, e1 := core.Canonical(input)
	b, e2 := core.Canonical(doc)
	if e1 != nil || e2 != nil || !bytes.Equal(a, b) {
		return Verification{}, errors.New("missing budget document field")
	}
	return v.Verify(doc, opts)
}

func (v *Verifier) Verify(doc Document, opts VerifyOptions) (Verification, error) {
	if v == nil || v.key == nil {
		return Verification{}, errors.New("budget verifier is not initialized")
	}
	if doc.Profile != Profile || doc.CircuitID != CircuitID || doc.Scheme != Scheme || doc.VerifyingKeySHA256 != v.pin {
		return Verification{}, errors.New("unsupported or untrusted budget proof parameters")
	}
	if err := validateRequest(opts.ExpectedRequest, opts.Now); err != nil {
		return Verification{}, err
	}
	if doc.Request != opts.ExpectedRequest {
		return Verification{}, errors.New("proof does not match independently selected receiver request")
	}
	assignment, err := publicAssignment(doc.Snapshot, doc.Request, doc.SourceBundle)
	if err != nil {
		return Verification{}, err
	}
	if (opts.SourceIssuer == "") != (len(opts.SourceIssuerKeyIDs) == 0) {
		return Verification{}, errors.New("issuer policy requires both issuer and key pins")
	}
	source, err := checkSource(doc.Snapshot, doc.SourceBundle, opts.Now, core.VerifyOptions{ExpectedIssuer: opts.SourceIssuer, TrustedKeyIDs: opts.SourceIssuerKeyIDs, Now: opts.Now})
	if err != nil {
		return Verification{}, err
	}
	if !slices.Contains(opts.TrustedSourceKeyIDs, source.Statement.IssuerKeyID) {
		return Verification{}, errors.New("source key does not match independent department policy")
	}
	proof, err := decodeProof(doc.Proof)
	if err != nil {
		return Verification{}, err
	}
	public, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return Verification{}, errors.New("invalid budget public inputs")
	}
	if err := groth16.Verify(proof, v.key, public); err != nil {
		return Verification{}, errors.New("budget proof verification failed")
	}
	return Verification{Profile: Profile, EvaluatedAt: opts.Now.UTC().Format(time.RFC3339Nano), ProofIntegrity: "valid", Predicate: "sum_within_limit", SourceTrust: "pinned_source_key", SnapshotSHA256: doc.Request.SnapshotSHA256, PolicyID: doc.Request.PolicyID, Audience: doc.Request.Audience, Nonce: doc.Request.Nonce, SetupTrust: "externally_pinned_experimental_setup", DatasetCompleteness: "committed_vector_only", ContentTruth: "not_established", CurrentAuthorization: "unknown", ReplayProtection: "caller_required", PrivacyScope: "amounts_hidden_metadata_linkable", CoreVerification: source}, nil
}

// Fixed 192-byte compressed Ar || Bs || Krs encoding, without gnark's variable
// length commitment vectors. Untrusted proof bytes can never request allocations.
const proofBytes = 2*curve.SizeOfG1AffineCompressed + curve.SizeOfG2AffineCompressed

var proofEncoding = base64.RawURLEncoding.Strict()

func encodeProof(p *g16.Proof) (string, error) {
	if len(p.Commitments) != 0 || !p.CommitmentPok.IsInfinity() {
		return "", errors.New("unexpected budget proof commitments")
	}
	a, b, c := p.Ar.Bytes(), p.Bs.Bytes(), p.Krs.Bytes()
	raw := append(append(append(make([]byte, 0, proofBytes), a[:]...), b[:]...), c[:]...)
	return proofEncoding.EncodeToString(raw), nil
}

func decodeProof(s string) (*g16.Proof, error) {
	if len(s) != proofEncoding.EncodedLen(proofBytes) {
		return nil, errors.New("invalid budget proof size")
	}
	raw, err := proofEncoding.DecodeString(s)
	if err != nil || len(raw) != proofBytes || proofEncoding.EncodeToString(raw) != s {
		return nil, errors.New("invalid budget proof encoding")
	}
	p := new(g16.Proof)
	g1, g2 := curve.SizeOfG1AffineCompressed, curve.SizeOfG2AffineCompressed
	if _, err := p.Ar.SetBytes(raw[:g1]); err != nil {
		return nil, errors.New("invalid proof point")
	}
	if _, err := p.Bs.SetBytes(raw[g1 : g1+g2]); err != nil {
		return nil, errors.New("invalid proof point")
	}
	if _, err := p.Krs.SetBytes(raw[g1+g2:]); err != nil {
		return nil, errors.New("invalid proof point")
	}
	if p.Ar.IsInfinity() || p.Bs.IsInfinity() || p.Krs.IsInfinity() {
		return nil, errors.New("invalid proof point at infinity")
	}
	canonical, err := encodeProof(p)
	if err != nil || canonical != s {
		return nil, errors.New("noncanonical proof point")
	}
	return p, nil
}
