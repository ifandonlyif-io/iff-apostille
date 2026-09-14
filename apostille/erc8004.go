package apostille

// This detached profile deliberately does not extend Core 0.1's envelope kinds,
// payloads, or Bundle. Its signatures have independent protocol/domain values.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

const (
	ERC8004Profile     = "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.1"
	KindERC8004Request = "erc8004-binding-request"
	KindERC8004Binding = "erc8004-binding"
	ERC8004RequestTTL  = 5 * time.Minute
	ERC8004BindingTTL  = time.Hour
)

var (
	ercAddressPattern   = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	ercHashPattern      = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	ercSignaturePattern = regexp.MustCompile(`^0x[0-9a-f]{130}$`)
	ercUintPattern      = regexp.MustCompile(`^(0|[1-9][0-9]{0,77})$`)
)

type ERC8004Identity struct {
	ChainID         string `json:"chain_id"`
	RegistryAddress string `json:"registry_address"`
	ERC8004AgentID  string `json:"erc8004_agent_id"`
	OwnerAddress    string `json:"owner_address"`
}

type ERC8004Request struct {
	Header
	ERC8004Identity
	AgentID          string `json:"agent_id"`
	AgentKeyID       string `json:"agent_key_id"`
	DelegationSHA256 string `json:"delegation_sha256"`
	ServiceAudience  string `json:"service_audience"`
	Nonce            string `json:"nonce"`
	ExpiresAt        string `json:"expires_at"`
	Purpose          string `json:"purpose"`
}

type ERC8004Observation struct {
	BlockNumber    string `json:"block_number"`
	BlockHash      string `json:"block_hash"`
	BlockTimestamp string `json:"block_timestamp"`
}

type ERC8004Binding struct {
	Header
	ERC8004Observation
	Request        Envelope `json:"request"`
	OwnerSignature string   `json:"owner_signature"`
	ExpiresAt      string   `json:"expires_at"`
	Check          string   `json:"check"`
}

type ERC8004BindingDocument struct {
	Protocol   string   `json:"protocol"`
	Binding    Envelope `json:"binding"`
	Delegation Envelope `json:"delegation"`
	Acceptance Envelope `json:"acceptance"`
}

type ERC8004Verification struct {
	Protocol            string         `json:"protocol"`
	ArtifactIntegrity   string         `json:"artifact_integrity"`
	IssuerTrust         string         `json:"issuer_trust"`
	ProviderEvidence    string         `json:"provider_evidence"`
	CurrentOwnership    string         `json:"current_ownership"`
	OrganizationBinding string         `json:"organization_binding"`
	PaymentAuthority    string         `json:"payment_authority"`
	Freshness           string         `json:"freshness"`
	Issuer              string         `json:"issuer"`
	IssuerKeyID         string         `json:"issuer_key_id"`
	CheckedAt           string         `json:"checked_at"`
	ExpiresAt           string         `json:"expires_at"`
	Request             ERC8004Request `json:"request"`
}

func ValidERC8004Uint(value string) bool {
	if !ercUintPattern.MatchString(value) {
		return false
	}
	n, ok := new(big.Int).SetString(value, 10)
	return ok && n.Sign() >= 0 && n.BitLen() <= 256
}

func ValidERC8004Address(value string) bool {
	return ercAddressPattern.MatchString(value) && value != "0x0000000000000000000000000000000000000000"
}

func erc8004Input(kind string, raw []byte) ([]byte, error) {
	part := ""
	switch kind {
	case KindERC8004Request:
		part = "request"
	case KindERC8004Binding:
		part = "snapshot"
	default:
		return nil, errors.New("unsupported ERC-8004 binding kind")
	}
	h := sha256.Sum256(raw)
	return append([]byte("iff-apostille/erc8004-binding/"+part+"/0.1\n"), h[:]...), nil
}

func (s *Signer) signERC8004(kind string, value any) (Envelope, error) {
	if !s.Enabled() {
		return Envelope{}, errors.New("signing key required")
	}
	raw, err := Canonical(value)
	if err != nil {
		return Envelope{}, err
	}
	input, err := erc8004Input(kind, raw)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Protocol: ERC8004Profile, Kind: kind, Payload: rawURL.EncodeToString(raw), PayloadSHA256: Hash(raw), Signature: Signature{Algorithm: Algorithm, KeyID: s.KeyID(), PublicKey: s.PublicKey(), Value: rawURL.EncodeToString(ed25519.Sign(s.key, input))}}, nil
}

func decodeERC8004(e Envelope, kind string, dst any) error {
	if e.Protocol != ERC8004Profile || e.Kind != kind || e.Signature.Algorithm != Algorithm || len(e.Payload) > MaxInputBytes || len(e.Signature.Value) > 128 || len(e.Signature.PublicKey) > 64 {
		return errors.New("invalid ERC-8004 envelope")
	}
	raw, err := rawURL.DecodeString(e.Payload)
	if err != nil || rawURL.EncodeToString(raw) != e.Payload || Hash(raw) != e.PayloadSHA256 {
		return errors.New("invalid ERC-8004 payload bytes")
	}
	if err = StrictJSON(raw, dst); err != nil {
		return err
	}
	canonical, err := Canonical(dst)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("noncanonical ERC-8004 payload")
	}
	var header struct {
		Protocol, Kind, Issuer string
		IssuerKeyID            string `json:"issuer_key_id"`
		IssuedAt               string `json:"issued_at"`
	}
	// The complete typed payload has already been parsed strictly above.
	if err = json.Unmarshal(raw, &header); err != nil {
		return err
	}
	pub, err := ParsePublicKey(e.Signature.PublicKey)
	if err != nil || Fingerprint(pub) != e.Signature.KeyID || header.IssuerKeyID != e.Signature.KeyID || header.Protocol != ERC8004Profile || header.Kind != kind || !ValidIssuer(header.Issuer) {
		return errors.New("invalid ERC-8004 signer or header")
	}
	if _, err = Timestamp(header.IssuedAt); err != nil {
		return err
	}
	sig, err := rawURL.DecodeString(e.Signature.Value)
	input, inputErr := erc8004Input(kind, raw)
	if err != nil || inputErr != nil || len(sig) != ed25519.SignatureSize || rawURL.EncodeToString(sig) != e.Signature.Value || !ed25519.Verify(pub, input, sig) {
		return errors.New("invalid ERC-8004 signature")
	}
	return nil
}

func validateERC8004Request(p ERC8004Request, now time.Time) error {
	start, e1 := Timestamp(p.IssuedAt)
	end, e2 := Timestamp(p.ExpiresAt)
	if p.Protocol != ERC8004Profile || p.Kind != KindERC8004Request || p.Issuer != KeyIdentity(p.IssuerKeyID) || !ValidIssuer(p.ServiceAudience) || !ValidID(p.AgentID) || !ValidID(p.Nonce) || !digestPattern.MatchString(p.DelegationSHA256) || len(p.AgentKeyID) != 71 || p.AgentKeyID[:7] != "sha256:" || !digestPattern.MatchString(p.AgentKeyID[7:]) || !ValidERC8004Uint(p.ChainID) || p.ChainID == "0" || !ValidERC8004Uint(p.ERC8004AgentID) || !ValidERC8004Address(p.RegistryAddress) || !ValidERC8004Address(p.OwnerAddress) || p.Purpose != "link_identity_private" || e1 != nil || e2 != nil || !end.After(start) || end.Sub(start) > ERC8004RequestTTL {
		return errors.New("invalid ERC-8004 binding request")
	}
	if !now.IsZero() && (start.After(now.Add(2*time.Minute)) || !now.Before(end)) {
		return errors.New("ERC-8004 binding request expired or not yet valid")
	}
	return nil
}

// VerifyERC8004Request validates administrator consent and, when supplied, its
// exact existing registration. It never consults a registry or wallet.
func VerifyERC8004Request(e Envelope, reg *AgentRegistration, now time.Time) (ERC8004Request, error) {
	var p ERC8004Request
	if err := decodeERC8004(e, KindERC8004Request, &p); err != nil {
		return p, err
	}
	if err := validateERC8004Request(p, now); err != nil {
		return p, err
	}
	if reg != nil {
		d, err := VerifyRegistration(*reg, p.ServiceAudience, now)
		if err != nil {
			return p, err
		}
		digest, err := EnvelopeDigest(reg.Delegation)
		if err != nil || digest != p.DelegationSHA256 || d.IssuerKeyID != p.IssuerKeyID || d.AgentID != p.AgentID || d.AgentKeyID != p.AgentKeyID {
			return p, errors.New("ERC-8004 request registration mismatch")
		}
	}
	return p, nil
}

func CreateERC8004Request(admin *Signer, reg AgentRegistration, identity ERC8004Identity, audience string, now time.Time) (Envelope, error) {
	if now.IsZero() || !admin.Enabled() {
		return Envelope{}, errors.New("administrator and time required")
	}
	d, err := VerifyRegistration(reg, audience, now)
	if err != nil {
		return Envelope{}, err
	}
	if d.IssuerKeyID != admin.KeyID() {
		return Envelope{}, errors.New("administrator does not own registration")
	}
	digest, err := EnvelopeDigest(reg.Delegation)
	if err != nil {
		return Envelope{}, err
	}
	nonce, err := NewID()
	if err != nil {
		return Envelope{}, err
	}
	h := NewHeader(KindERC8004Request, KeyIdentity(admin.KeyID()), admin, now)
	h.Protocol = ERC8004Profile
	p := ERC8004Request{Header: h, ERC8004Identity: identity, AgentID: d.AgentID, AgentKeyID: d.AgentKeyID, DelegationSHA256: digest, ServiceAudience: audience, Nonce: nonce, ExpiresAt: now.Add(ERC8004RequestTTL).UTC().Format(TimestampLayout), Purpose: "link_identity_private"}
	if err = validateERC8004Request(p, now); err != nil {
		return Envelope{}, err
	}
	return admin.signERC8004(KindERC8004Request, p)
}

func ERC8004OwnerMessage(request Envelope) (string, error) {
	p, err := VerifyERC8004Request(request, nil, time.Time{})
	if err != nil {
		return "", err
	}
	digest, err := EnvelopeDigest(request)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("iff-apostille/erc8004-binding/owner/0.1\nissuer:%s\nadmin_key_id:%s\nagent_id:%s\nagent_key_id:%s\ndelegation_sha256:%s\nchain_id:%s\nregistry_address:%s\nerc8004_agent_id:%s\nowner_address:%s\nnonce:%s\nissued_at:%s\nexpires_at:%s\npurpose:link_identity_private\nrequest_sha256:%s", p.ServiceAudience, p.IssuerKeyID, p.AgentID, p.AgentKeyID, p.DelegationSHA256, p.ChainID, p.RegistryAddress, p.ERC8004AgentID, p.OwnerAddress, p.Nonce, p.IssuedAt, p.ExpiresAt, digest), nil
}

// IssueERC8004Binding signs an issuer-checked snapshot. The caller MUST verify
// the EOA signature and observe matching ownership via its configured registry
// before calling it; the offline core deliberately performs no provider I/O.
func (s *Signer) IssueERC8004Binding(reg AgentRegistration, request Envelope, ownerSignature string, observation ERC8004Observation, issuer string, now time.Time) (ERC8004BindingDocument, error) {
	if now.IsZero() || !s.Enabled() || !ValidIssuer(issuer) {
		return ERC8004BindingDocument{}, errors.New("issuer and evaluation time required")
	}
	p, err := VerifyERC8004Request(request, &reg, now)
	if err != nil {
		return ERC8004BindingDocument{}, err
	}
	if p.ServiceAudience != issuer {
		return ERC8004BindingDocument{}, errors.New("ERC-8004 issuer audience mismatch")
	}
	var d Delegation
	if err = DecodePayload(reg.Delegation, KindDelegation, &d); err != nil {
		return ERC8004BindingDocument{}, err
	}
	expires := now.Add(ERC8004BindingTTL)
	dEnd, _ := Timestamp(d.ExpiresAt)
	if dEnd.Before(expires) {
		expires = dEnd
	}
	h := NewHeader(KindERC8004Binding, issuer, s, now)
	h.Protocol = ERC8004Profile
	b := ERC8004Binding{Header: h, ERC8004Observation: observation, Request: request, OwnerSignature: ownerSignature, ExpiresAt: expires.UTC().Format(TimestampLayout), Check: "owner_of_eoa"}
	if err = validateERC8004Snapshot(b); err != nil {
		return ERC8004BindingDocument{}, err
	}
	e, err := s.signERC8004(KindERC8004Binding, b)
	return ERC8004BindingDocument{Protocol: ERC8004Profile, Binding: e, Delegation: reg.Delegation, Acceptance: reg.Acceptance}, err
}

func validateERC8004Snapshot(b ERC8004Binding) error {
	start, e1 := Timestamp(b.IssuedAt)
	end, e2 := Timestamp(b.ExpiresAt)
	block, e3 := Timestamp(b.BlockTimestamp)
	if e1 != nil || e2 != nil || e3 != nil || !end.After(start) || end.Sub(start) > ERC8004BindingTTL || block.After(start.Add(2*time.Minute)) || start.Sub(block) > time.Hour || !ValidERC8004Uint(b.BlockNumber) || !ercHashPattern.MatchString(b.BlockHash) || b.BlockHash == "0x0000000000000000000000000000000000000000000000000000000000000000" || !ercSignaturePattern.MatchString(b.OwnerSignature) || b.Check != "owner_of_eoa" {
		return errors.New("invalid ERC-8004 ownership snapshot")
	}
	return nil
}

func VerifyERC8004Binding(doc ERC8004BindingDocument, opts VerifyOptions) (ERC8004Verification, error) {
	var result ERC8004Verification
	if doc.Protocol != ERC8004Profile {
		return result, errors.New("unsupported ERC-8004 document profile")
	}
	var b ERC8004Binding
	if err := decodeERC8004(doc.Binding, KindERC8004Binding, &b); err != nil {
		return result, err
	}
	if err := validateERC8004Snapshot(b); err != nil {
		return result, err
	}
	issued, _ := Timestamp(b.IssuedAt)
	reg := AgentRegistration{Delegation: doc.Delegation, Acceptance: doc.Acceptance}
	p, err := VerifyERC8004Request(b.Request, &reg, issued)
	if err != nil {
		return result, err
	}
	if p.ServiceAudience != b.Issuer || (opts.ExpectedIssuer != "" && opts.ExpectedIssuer != b.Issuer) {
		return result, errors.New("ERC-8004 binding issuer mismatch")
	}
	var d Delegation
	if err = DecodePayload(doc.Delegation, KindDelegation, &d); err != nil {
		return result, err
	}
	expires, _ := Timestamp(b.ExpiresAt)
	dEnd, _ := Timestamp(d.ExpiresAt)
	if expires.After(dEnd) {
		return result, errors.New("ERC-8004 binding outlives delegation")
	}
	trust := "unknown"
	if opts.ExpectedIssuer != "" {
		for _, key := range opts.TrustedKeyIDs {
			if key == b.IssuerKeyID {
				trust = "pinned"
				break
			}
		}
	}
	freshness := "not_checked"
	if !opts.Now.IsZero() {
		switch {
		case opts.Now.Before(issued):
			freshness = "not_yet_valid"
		case !opts.Now.Before(expires):
			freshness = "expired"
		default:
			freshness = "within_validity"
		}
	}
	return ERC8004Verification{Protocol: ERC8004Profile, ArtifactIntegrity: "valid", IssuerTrust: trust, ProviderEvidence: "issuer_checked", CurrentOwnership: "unknown", OrganizationBinding: "unproven", PaymentAuthority: "not_established", Freshness: freshness, Issuer: b.Issuer, IssuerKeyID: b.IssuerKeyID, CheckedAt: b.IssuedAt, ExpiresAt: b.ExpiresAt, Request: p}, nil
}
