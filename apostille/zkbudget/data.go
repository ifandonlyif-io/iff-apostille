package zkbudget

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	core "github.com/ifandonlyif-io/iff-apostille/apostille"
)

const (
	Profile                   = "https://ifandonlyif.io/apostille/profiles/zk-budget/0.1"
	CircuitID                 = "budget-16x48-mimc-bls12381-v2"
	Scheme                    = "groth16-bls12-381-gnark-0.16.3"
	MaxEntries                = 16
	AmountBits                = 48
	MaxAmount          uint64 = 1<<AmountBits - 1
	MaxLimit           uint64 = 1<<52 - 1
	MaxParametersBytes        = 32 << 20
	SnapshotMediaType         = "application/vnd.iff.apostille.zk-budget-snapshot+json"
	publicInputs              = 9 // excludes Groth16's constant ONE
)

var decimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)
var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var currencyCode = regexp.MustCompile(`^[A-Z]{3}$`)

type Snapshot struct {
	Profile     string `json:"profile"`
	SnapshotID  string `json:"snapshot_id"`
	Scope       string `json:"scope"`
	Currency    string `json:"currency"`
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	Entries     string `json:"entries"`
	Commitment  string `json:"commitment"`
}

type SnapshotOptions struct{ Scope, Currency, PeriodStart, PeriodEnd string }

// PrivateSnapshot must remain inside the department, including its blinding.
// Possession of the blinding plus predictable amounts permits dictionary attacks.
type PrivateSnapshot struct {
	Snapshot Snapshot `json:"snapshot"`
	Amounts  []string `json:"amounts"`
	Blinding string   `json:"blinding"`
}

// Request is the receiver's independently selected audit policy, not a policy
// taken on trust from a proof document. It does not authorize spending.
type Request struct {
	Profile        string `json:"profile"`
	PolicyID       string `json:"policy_id"`
	Audience       string `json:"audience"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	LimitMinor     string `json:"limit_minor"`
	Nonce          string `json:"nonce"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
}

func NewSnapshot(amounts []string, opts SnapshotOptions) (PrivateSnapshot, error) {
	if len(amounts) < 1 || len(amounts) > MaxEntries {
		return PrivateSnapshot{}, errors.New("budget snapshot requires 1-16 amounts")
	}
	id, err := core.NewID()
	if err != nil {
		return PrivateSnapshot{}, err
	}
	var salt fr.Element
	for salt.IsZero() {
		if _, err := salt.SetRandom(); err != nil {
			return PrivateSnapshot{}, err
		}
	}
	b := salt.Bytes()
	p := PrivateSnapshot{Snapshot: Snapshot{Profile: Profile, SnapshotID: id, Scope: opts.Scope, Currency: opts.Currency, PeriodStart: opts.PeriodStart, PeriodEnd: opts.PeriodEnd, Entries: strconv.Itoa(len(amounts))}, Amounts: append([]string(nil), amounts...), Blinding: hex.EncodeToString(b[:])}
	root, err := privateCommitment(p)
	if err != nil {
		return PrivateSnapshot{}, err
	}
	p.Snapshot.Commitment = root
	return p, nil
}

func validLabel(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func amount(s string, max uint64) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || !decimal.MatchString(s) || n > max {
		return 0, errors.New("invalid bounded decimal amount")
	}
	return n, nil
}

func scalar(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok || !hexDigest.MatchString(s) || n.Cmp(fr.Modulus()) >= 0 {
		return nil, errors.New("invalid canonical field element")
	}
	return n, nil
}

func validateSnapshot(s Snapshot, requireCommitment bool) error {
	a, e1 := core.Timestamp(s.PeriodStart)
	b, e2 := core.Timestamp(s.PeriodEnd)
	n, e3 := amount(s.Entries, MaxEntries)
	if s.Profile != Profile || !core.ValidID(s.SnapshotID) || !validLabel(s.Scope) || !currencyCode.MatchString(s.Currency) || e1 != nil || e2 != nil || !a.Before(b) || e3 != nil || n == 0 {
		return errors.New("invalid budget snapshot metadata")
	}
	if requireCommitment {
		_, err := scalar(s.Commitment)
		return err
	}
	return nil
}

func SnapshotBytes(s Snapshot) ([]byte, error) {
	if err := validateSnapshot(s, true); err != nil {
		return nil, err
	}
	return core.Canonical(s)
}

func SnapshotDigest(s Snapshot) (string, error) {
	b, err := SnapshotBytes(s)
	if err != nil {
		return "", err
	}
	return core.Hash(b), nil
}

// Metadata's commitment field is an explicit empty string when hashing context.
func contextWords(s Snapshot) (*big.Int, *big.Int) {
	s.Commitment = ""
	b, _ := core.Canonical(s) // only called after validating the exact typed fields
	return hashWords(b)
}

func hashWords(b []byte) (*big.Int, *big.Int) {
	h := sha256.Sum256(b)
	return new(big.Int).SetBytes(h[:16]), new(big.Int).SetBytes(h[16:])
}

func fieldHash(inputs ...*big.Int) *big.Int {
	h := mimc.NewFieldHasher()
	for _, input := range inputs {
		var x fr.Element
		x.SetBigInt(input)
		h.WriteElement(x)
	}
	x := h.SumElement()
	return x.BigInt(new(big.Int))
}

func privateCommitment(p PrivateSnapshot) (string, error) {
	if err := validateSnapshot(p.Snapshot, false); err != nil {
		return "", err
	}
	if len(p.Amounts) == 0 || len(p.Amounts) > MaxEntries || p.Snapshot.Entries != strconv.Itoa(len(p.Amounts)) {
		return "", errors.New("private amount count does not match snapshot")
	}
	salt, err := scalar(p.Blinding)
	if err != nil || salt.Sign() == 0 {
		return "", errors.New("nonzero private blinding required")
	}
	hi, lo := contextWords(p.Snapshot)
	inputs := []*big.Int{domain("snapshot"), hi, lo, big.NewInt(int64(len(p.Amounts))), salt}
	for i := 0; i < MaxEntries; i++ {
		var n uint64
		if i < len(p.Amounts) {
			n, err = amount(p.Amounts[i], MaxAmount)
			if err != nil {
				return "", err
			}
		}
		inputs = append(inputs, new(big.Int).SetUint64(n))
	}
	return hex.EncodeToString(fieldHash(inputs...).FillBytes(make([]byte, 32))), nil
}

// SignSnapshot uses unmodified Core 0.1 to authenticate the canonical blinded
// commitment manifest. It never signs or hashes the private amounts file.
func SignSnapshot(s Snapshot, signer *core.Signer, reg *core.AgentRegistration, agentID string, now time.Time) (core.Bundle, error) {
	raw, err := SnapshotBytes(s)
	if err != nil {
		return core.Bundle{}, err
	}
	end, _ := core.Timestamp(s.PeriodEnd)
	if now.IsZero() || now.Before(end) {
		return core.Bundle{}, errors.New("snapshot period must be closed before signing")
	}
	statement, err := core.CreateStatement(bytes.NewReader(raw), SnapshotMediaType, signer, reg, agentID, now)
	if err != nil {
		return core.Bundle{}, err
	}
	b := core.Bundle{Protocol: core.Protocol, Statement: statement}
	if reg != nil {
		b.Delegation = &reg.Delegation
		b.Acceptance = &reg.Acceptance
	}
	return b, nil
}

func NewRequest(s Snapshot, policyID, audience, limit string, now time.Time) (Request, error) {
	digest, err := SnapshotDigest(s)
	if err != nil {
		return Request{}, err
	}
	nonce, err := core.NewID()
	if err != nil {
		return Request{}, err
	}
	r := Request{Profile: Profile, PolicyID: policyID, Audience: audience, SnapshotSHA256: digest, LimitMinor: limit, Nonce: nonce, IssuedAt: now.UTC().Format(core.TimestampLayout), ExpiresAt: now.Add(5 * time.Minute).UTC().Format(core.TimestampLayout)}
	if err := validateRequest(r, now); err != nil {
		return Request{}, err
	}
	return r, nil
}

func validateRequest(r Request, now time.Time) error {
	a, e1 := core.Timestamp(r.IssuedAt)
	b, e2 := core.Timestamp(r.ExpiresAt)
	_, e3 := amount(r.LimitMinor, MaxLimit)
	if r.Profile != Profile || !validLabel(r.PolicyID) || !core.ValidIssuer(r.Audience) || !hexDigest.MatchString(r.SnapshotSHA256) || !core.ValidID(r.Nonce) || e1 != nil || e2 != nil || e3 != nil || !a.Before(b) || b.Sub(a) > 15*time.Minute || now.IsZero() || now.Before(a) || !now.Before(b) {
		return errors.New("invalid or expired receiver budget request")
	}
	return nil
}

func publicAssignment(s Snapshot, r Request, source core.Bundle) (budgetCircuit, error) {
	digest, err := SnapshotDigest(s)
	if err != nil || digest != r.SnapshotSHA256 {
		return budgetCircuit{}, errors.New("request does not match snapshot")
	}
	root, err := scalar(s.Commitment)
	if err != nil {
		return budgetCircuit{}, err
	}
	limit, err := amount(r.LimitMinor, MaxLimit)
	if err != nil {
		return budgetCircuit{}, err
	}
	hi, lo := contextWords(s)
	raw, err := core.Canonical(r)
	if err != nil {
		return budgetCircuit{}, err
	}
	rhi, rlo := hashWords(raw)
	sourceRaw, err := core.Canonical(source)
	if err != nil {
		return budgetCircuit{}, err
	}
	shi, slo := hashWords(sourceRaw)
	count, _ := amount(s.Entries, MaxEntries)
	lim := new(big.Int).SetUint64(limit)
	ctr := new(big.Int).SetUint64(count)
	return budgetCircuit{Commitment: root, Limit: lim, ContextHi: hi, ContextLo: lo, Count: ctr, RequestHi: rhi, RequestLo: rlo, SourceHi: shi, SourceLo: slo}, nil
}
