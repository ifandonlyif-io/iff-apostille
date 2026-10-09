package apostille

// This detached profile deliberately does not extend Core 0.1's envelope kinds,
// payloads, or Bundle. Its signatures have independent protocol/domain values.
import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

const (
	// ERC8004Profile is binding profile 0.1 (Core 0.1 registrations, Ed25519).
	ERC8004Profile = "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.1"
	// ERC8004Profile03 is binding profile 0.3 (Core 0.3 registrations,
	// ML-DSA-65). See docs/apostille/spec/erc8004-binding-0.3.md.
	ERC8004Profile03   = "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.3"
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

// bindingProfile holds everything that differs between ERC-8004 binding
// profiles; the rest of this file never branches on the version. core is the
// Core profile whose signatures, key and signature sizes, verifier and
// identifier grammar the binding uses, and whose registrations it binds.
type bindingProfile struct {
	protocol string
	// domain closes "iff-apostille/erc8004-binding/{request,snapshot}/<domain>\n"
	// and the first line of the owner consent text.
	domain string
	core   *profile
}

var (
	bindingProfile01 = &bindingProfile{protocol: ERC8004Profile, domain: "0.1", core: profile01}
	bindingProfile03 = &bindingProfile{protocol: ERC8004Profile03, domain: "0.3", core: profile03}
	// bindingProfiles lists every known binding profile, oldest first. There is
	// no binding profile 0.2.
	bindingProfiles = []*bindingProfile{bindingProfile01, bindingProfile03}
)

// KnownERC8004Profiles returns every ERC-8004 binding profile identifier this
// implementation verifies and signs, oldest first.
func KnownERC8004Profiles() []string {
	out := make([]string, len(bindingProfiles))
	for i, p := range bindingProfiles {
		out[i] = p.protocol
	}
	return out
}

func bindingProfileFor(protocol string) (*bindingProfile, error) {
	for _, p := range bindingProfiles {
		if p.protocol == protocol {
			return p, nil
		}
	}
	return nil, errors.New("unsupported ERC-8004 binding profile")
}

// bindingProfileForCore is the binding profile of a Core protocol identifier:
// the profile whose version equals the Core version of the registration.
func bindingProfileForCore(protocol string) (*bindingProfile, error) {
	for _, p := range bindingProfiles {
		if p.core.protocol == protocol {
			return p, nil
		}
	}
	return nil, errors.New("no ERC-8004 binding profile for this Core version")
}

func (p *bindingProfile) input(kind string, raw []byte) ([]byte, error) {
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
	return append([]byte("iff-apostille/erc8004-binding/"+part+"/"+p.domain+"\n"), h[:]...), nil
}

// checkRegistration refuses a registration of another Core version.
func (p *bindingProfile) checkRegistration(reg AgentRegistration) error {
	if reg.Delegation.Protocol != p.core.protocol || reg.Acceptance.Protocol != p.core.protocol {
		return errors.New("registration Core version does not match the ERC-8004 binding profile")
	}
	return nil
}

func (s *Signer) signERC8004(prof *bindingProfile, kind string, value any) (Envelope, error) {
	if !s.Enabled() {
		return Envelope{}, errors.New("signing key required")
	}
	if s.Algorithm() != prof.core.algorithm {
		return Envelope{}, errors.New("signer does not support the ERC-8004 binding profile's signature algorithm")
	}
	raw, err := Canonical(value)
	if err != nil {
		return Envelope{}, err
	}
	input, err := prof.input(kind, raw)
	if err != nil {
		return Envelope{}, err
	}
	signature, err := s.signMessage(input)
	if err != nil {
		return Envelope{}, err
	}
	// As in SignFor, check the signer's own signature before releasing it.
	if err := prof.core.verify(s.publicKeyBytes(), input, signature); err != nil {
		return Envelope{}, err
	}
	return Envelope{Protocol: prof.protocol, Kind: kind, Payload: rawURL.EncodeToString(raw), PayloadSHA256: Hash(raw), Signature: Signature{Algorithm: prof.core.algorithm, KeyID: s.KeyID(), PublicKey: s.PublicKey(), Value: rawURL.EncodeToString(signature)}}, nil
}

// decodeERC8004 verifies one envelope under the binding profile its protocol
// names and returns that profile.
func decodeERC8004(e Envelope, kind string, dst any) (*bindingProfile, error) {
	prof, err := bindingProfileFor(e.Protocol)
	if err != nil || e.Kind != kind || e.Signature.Algorithm != prof.core.algorithm || len(e.Payload) > MaxInputBytes || len(e.Signature.Value) > prof.core.fieldLimit(prof.core.signatureSize) || len(e.Signature.PublicKey) > prof.core.fieldLimit(prof.core.publicKeySize) {
		return nil, errors.New("invalid ERC-8004 envelope")
	}
	raw, err := rawURL.DecodeString(e.Payload)
	if err != nil || rawURL.EncodeToString(raw) != e.Payload || Hash(raw) != e.PayloadSHA256 {
		return nil, errors.New("invalid ERC-8004 payload bytes")
	}
	if err = StrictJSON(raw, dst); err != nil {
		return nil, err
	}
	canonical, err := Canonical(dst)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errors.New("noncanonical ERC-8004 payload")
	}
	var header struct {
		Protocol, Kind, Issuer string
		IssuerKeyID            string `json:"issuer_key_id"`
		IssuedAt               string `json:"issued_at"`
	}
	// The complete typed payload has already been parsed strictly above.
	if err = json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	pub, err := prof.core.decodePublicKey(e.Signature.PublicKey)
	if err != nil || Fingerprint(pub) != e.Signature.KeyID || header.IssuerKeyID != e.Signature.KeyID || header.Protocol != prof.protocol || header.Kind != kind || !prof.core.validIssuer(header.Issuer) {
		return nil, errors.New("invalid ERC-8004 signer or header")
	}
	if err = prof.core.checkKey(pub); err != nil {
		return nil, err
	}
	if _, err = Timestamp(header.IssuedAt); err != nil {
		return nil, err
	}
	sig, err := prof.core.decodeSignature(e.Signature.Value)
	input, inputErr := prof.input(kind, raw)
	if err != nil || inputErr != nil || prof.core.verify(pub, input, sig) != nil {
		return nil, errors.New("invalid ERC-8004 signature")
	}
	return prof, nil
}

func validateERC8004Request(prof *bindingProfile, p ERC8004Request, now time.Time) error {
	start, e1 := Timestamp(p.IssuedAt)
	end, e2 := Timestamp(p.ExpiresAt)
	if p.Protocol != prof.protocol || p.Kind != KindERC8004Request || p.Issuer != KeyIdentity(p.IssuerKeyID) || !prof.core.validIssuer(p.ServiceAudience) || !ValidID(p.AgentID) || !ValidID(p.Nonce) || !digestPattern.MatchString(p.DelegationSHA256) || len(p.AgentKeyID) != 71 || p.AgentKeyID[:7] != "sha256:" || !digestPattern.MatchString(p.AgentKeyID[7:]) || !ValidERC8004Uint(p.ChainID) || p.ChainID == "0" || !ValidERC8004Uint(p.ERC8004AgentID) || !ValidERC8004Address(p.RegistryAddress) || !ValidERC8004Address(p.OwnerAddress) || p.Purpose != "link_identity_private" || e1 != nil || e2 != nil || !end.After(start) || end.Sub(start) > ERC8004RequestTTL {
		return errors.New("invalid ERC-8004 binding request")
	}
	if !now.IsZero() && (start.After(now.Add(2*time.Minute)) || !now.Before(end)) {
		return errors.New("ERC-8004 binding request expired or not yet valid")
	}
	return nil
}

func verifyERC8004Request(e Envelope, reg *AgentRegistration, now time.Time) (*bindingProfile, ERC8004Request, error) {
	var p ERC8004Request
	prof, err := decodeERC8004(e, KindERC8004Request, &p)
	if err != nil {
		return nil, p, err
	}
	if err := validateERC8004Request(prof, p, now); err != nil {
		return nil, p, err
	}
	if reg != nil {
		// The registration must be of the profile's Core version before any of
		// its signatures are checked: a 0.1 and a 0.3 artifact are never mixed.
		if err := prof.checkRegistration(*reg); err != nil {
			return nil, p, err
		}
		d, err := VerifyRegistration(*reg, p.ServiceAudience, now)
		if err != nil {
			return nil, p, err
		}
		digest, err := EnvelopeDigest(reg.Delegation)
		if err != nil || digest != p.DelegationSHA256 || d.IssuerKeyID != p.IssuerKeyID || d.AgentID != p.AgentID || d.AgentKeyID != p.AgentKeyID {
			return nil, p, errors.New("ERC-8004 request registration mismatch")
		}
	}
	return prof, p, nil
}

// VerifyERC8004Request validates administrator consent and, when supplied, its
// exact existing registration, under the binding profile the request names. It
// never consults a registry or wallet.
func VerifyERC8004Request(e Envelope, reg *AgentRegistration, now time.Time) (ERC8004Request, error) {
	_, p, err := verifyERC8004Request(e, reg, now)
	return p, err
}

// CreateERC8004Request signs an administrator's consent. The binding profile is
// that of the registration's Core version (Core 0.1 selects binding 0.1, Core
// 0.3 selects 0.3) and the administrator's key must be of its algorithm.
func CreateERC8004Request(admin *Signer, reg AgentRegistration, identity ERC8004Identity, audience string, now time.Time) (Envelope, error) {
	nonce, err := NewID()
	if err != nil {
		return Envelope{}, err
	}
	return createERC8004Request(admin, reg, identity, audience, nonce, now)
}

// createERC8004Request is CreateERC8004Request with the nonce supplied, so the
// published known-answer vector can be reproduced.
func createERC8004Request(admin *Signer, reg AgentRegistration, identity ERC8004Identity, audience, nonce string, now time.Time) (Envelope, error) {
	if now.IsZero() || !admin.Enabled() {
		return Envelope{}, errors.New("administrator and time required")
	}
	prof, err := bindingProfileForCore(reg.Delegation.Protocol)
	if err != nil {
		return Envelope{}, err
	}
	if admin.Algorithm() != prof.core.algorithm {
		return Envelope{}, errors.New("administrator key does not match the registration's signature algorithm")
	}
	if err = prof.checkRegistration(reg); err != nil {
		return Envelope{}, err
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
	h := headerFor(prof.protocol, KindERC8004Request, KeyIdentity(admin.KeyID()), admin, now)
	p := ERC8004Request{Header: h, ERC8004Identity: identity, AgentID: d.AgentID, AgentKeyID: d.AgentKeyID, DelegationSHA256: digest, ServiceAudience: audience, Nonce: nonce, ExpiresAt: now.Add(ERC8004RequestTTL).UTC().Format(TimestampLayout), Purpose: "link_identity_private"}
	if err = validateERC8004Request(prof, p, now); err != nil {
		return Envelope{}, err
	}
	return admin.signERC8004(prof, KindERC8004Request, p)
}

// ERC8004OwnerMessage is the exact EIP-191 text the wallet owner signs; its
// first line names the request's binding profile.
func ERC8004OwnerMessage(request Envelope) (string, error) {
	prof, p, err := verifyERC8004Request(request, nil, time.Time{})
	if err != nil {
		return "", err
	}
	digest, err := EnvelopeDigest(request)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("iff-apostille/erc8004-binding/owner/%s\nissuer:%s\nadmin_key_id:%s\nagent_id:%s\nagent_key_id:%s\ndelegation_sha256:%s\nchain_id:%s\nregistry_address:%s\nerc8004_agent_id:%s\nowner_address:%s\nnonce:%s\nissued_at:%s\nexpires_at:%s\npurpose:link_identity_private\nrequest_sha256:%s", prof.domain, p.ServiceAudience, p.IssuerKeyID, p.AgentID, p.AgentKeyID, p.DelegationSHA256, p.ChainID, p.RegistryAddress, p.ERC8004AgentID, p.OwnerAddress, p.Nonce, p.IssuedAt, p.ExpiresAt, digest), nil
}

// IssueERC8004Binding signs an issuer-checked snapshot under the request's
// binding profile; the issuer key must be of that profile's algorithm. The
// caller MUST verify the EOA signature and observe matching ownership via its
// configured registry before calling it; the offline core deliberately
// performs no provider I/O.
func (s *Signer) IssueERC8004Binding(reg AgentRegistration, request Envelope, ownerSignature string, observation ERC8004Observation, issuer string, now time.Time) (ERC8004BindingDocument, error) {
	if now.IsZero() || !s.Enabled() {
		return ERC8004BindingDocument{}, errors.New("issuer and evaluation time required")
	}
	prof, p, err := verifyERC8004Request(request, &reg, now)
	if err != nil {
		return ERC8004BindingDocument{}, err
	}
	if !prof.core.validIssuer(issuer) {
		return ERC8004BindingDocument{}, errors.New("issuer and evaluation time required")
	}
	if s.Algorithm() != prof.core.algorithm {
		return ERC8004BindingDocument{}, errors.New("issuer key does not match the ERC-8004 binding profile's signature algorithm")
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
	h := headerFor(prof.protocol, KindERC8004Binding, issuer, s, now)
	b := ERC8004Binding{Header: h, ERC8004Observation: observation, Request: request, OwnerSignature: ownerSignature, ExpiresAt: expires.UTC().Format(TimestampLayout), Check: "owner_of_eoa"}
	if err = validateERC8004Snapshot(b); err != nil {
		return ERC8004BindingDocument{}, err
	}
	e, err := s.signERC8004(prof, KindERC8004Binding, b)
	return ERC8004BindingDocument{Protocol: prof.protocol, Binding: e, Delegation: reg.Delegation, Acceptance: reg.Acceptance}, err
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

// VerifyERC8004Binding verifies a document under the binding profile it names.
// The snapshot, the request inside it, the delegation and the acceptance must
// all belong to that one profile and its Core version.
func VerifyERC8004Binding(doc ERC8004BindingDocument, opts VerifyOptions) (ERC8004Verification, error) {
	var result ERC8004Verification
	prof, err := bindingProfileFor(doc.Protocol)
	if err != nil {
		return result, errors.New("unsupported ERC-8004 document profile")
	}
	var b ERC8004Binding
	if p, err := decodeERC8004(doc.Binding, KindERC8004Binding, &b); err != nil || p != prof {
		return result, errors.New("invalid ERC-8004 binding envelope")
	}
	if err := validateERC8004Snapshot(b); err != nil {
		return result, err
	}
	issued, _ := Timestamp(b.IssuedAt)
	reg := AgentRegistration{Delegation: doc.Delegation, Acceptance: doc.Acceptance}
	requestProfile, p, err := verifyERC8004Request(b.Request, &reg, issued)
	if err != nil {
		return result, err
	}
	if requestProfile != prof {
		return result, errors.New("ERC-8004 request belongs to another binding profile")
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
	return ERC8004Verification{Protocol: prof.protocol, ArtifactIntegrity: "valid", IssuerTrust: trust, ProviderEvidence: "issuer_checked", CurrentOwnership: "unknown", OrganizationBinding: "unproven", PaymentAuthority: "not_established", Freshness: freshness, Issuer: b.Issuer, IssuerKeyID: b.IssuerKeyID, CheckedAt: b.IssuedAt, ExpiresAt: b.ExpiresAt, Request: p}, nil
}
