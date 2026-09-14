package apostille

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
)

func validatePayload(kind string, raw []byte) (Header, error) {
	var header Header
	var problem error
	var typed any
	switch kind {
	case KindStatement:
		var p Statement
		if err := StrictJSON(raw, &p); err != nil {
			return header, err
		}
		header = p.Header
		typed = p
		if !ValidID(p.AgentID) || !digestPattern.MatchString(p.ArtifactSHA256) || !decimalPattern.MatchString(p.ArtifactSize) || !ValidID(p.Nonce) || len(p.ArtifactMediaType) > 128 || !strings.Contains(p.ArtifactMediaType, "/") || strings.ContainsAny(p.ArtifactMediaType, "\r\n\x00") {
			problem = errors.New("invalid origin statement")
		}
		if p.DelegationSHA256 != "" && !digestPattern.MatchString(p.DelegationSHA256) {
			problem = errors.New("invalid delegation digest")
		}
	case KindDelegation:
		var p Delegation
		if err := StrictJSON(raw, &p); err != nil {
			return header, err
		}
		header = p.Header
		typed = p
		pub, err := ParsePublicKey(p.AgentPublicKey)
		if err != nil || Fingerprint(pub) != p.AgentKeyID || !ValidID(p.AgentID) || !ValidIssuer(p.ServiceAudience) || len(p.Scopes) != 1 || p.Scopes[0] != "sign_origin_statement" {
			problem = errors.New("invalid agent delegation")
		}
		if err := interval(p.NotBefore, p.ExpiresAt); err != nil {
			problem = err
		}
		if header.Issuer != KeyIdentity(header.IssuerKeyID) {
			problem = errors.New("delegation issuer must identify administrator key")
		}
	case KindAcceptance:
		var p Acceptance
		if err := StrictJSON(raw, &p); err != nil {
			return header, err
		}
		header = p.Header
		typed = p
		if !ValidID(p.AgentID) || !digestPattern.MatchString(p.DelegationSHA256) || header.Issuer != KeyIdentity(header.IssuerKeyID) {
			problem = errors.New("invalid agent acceptance")
		}
	case KindGrant:
		var p PublicationGrant
		if err := StrictJSON(raw, &p); err != nil {
			return header, err
		}
		header = p.Header
		typed = p
		if !digestPattern.MatchString(p.StatementSHA256) || !digestPattern.MatchString(p.DelegationSHA256) || !ValidIssuer(p.ServiceAudience) || (p.Visibility != "private" && p.Visibility != "public") || p.Purpose != "issue_origin_certificate" || !ValidID(p.Nonce) || header.Issuer != KeyIdentity(header.IssuerKeyID) {
			problem = errors.New("invalid publication grant")
		}
		if err := interval(p.IssuedAt, p.ExpiresAt); err != nil {
			problem = err
		}
	case KindCertificate:
		var p Certificate
		if err := StrictJSON(raw, &p); err != nil {
			return header, err
		}
		header = p.Header
		typed = p
		if !ValidID(p.CertificateID) || !digestPattern.MatchString(p.StatementSHA256) || !validKeyID(p.SourceKeyID) || p.SignatureCheck != "valid" || p.OrganizationBinding != "unproven" || p.ContentTruth != "not_established" || (p.AgentBinding != "admin_key_delegation" && p.AgentBinding != "not_provided") {
			problem = errors.New("unsupported certificate assertion")
		}
		if p.DelegationSHA256 != "" && !digestPattern.MatchString(p.DelegationSHA256) {
			problem = errors.New("invalid certificate delegation digest")
		}
		if (p.AgentBinding == "admin_key_delegation") != (p.DelegationSHA256 != "") {
			problem = errors.New("contradictory certificate binding")
		}
		if err := interval(p.IssuedAt, p.ExpiresAt); err != nil {
			problem = err
		}
	default:
		return header, errors.New("unsupported artifact kind")
	}
	if header.Protocol != Protocol || header.Kind != kind || !ValidIssuer(header.Issuer) || !validKeyID(header.IssuerKeyID) {
		return header, errors.New("invalid signed protocol header")
	}
	if _, err := Timestamp(header.IssuedAt); err != nil {
		return header, err
	}
	if problem == nil {
		canonical, err := Canonical(typed)
		if err != nil || !bytes.Equal(canonical, raw) {
			return header, errors.New("missing, null, or noncanonical payload field")
		}
	}
	return header, problem
}
func validKeyID(s string) bool {
	return strings.HasPrefix(s, "sha256:") && digestPattern.MatchString(strings.TrimPrefix(s, "sha256:"))
}
func interval(start, end string) error {
	a, err := Timestamp(start)
	if err != nil {
		return err
	}
	b, err := Timestamp(end)
	if err != nil {
		return err
	}
	if !b.After(a) {
		return errors.New("invalid validity interval")
	}
	return nil
}

// VerifyRegistration checks both administrator authorization and fresh agent
// proof of possession. It does not establish a legal organization identity.
func VerifyRegistration(reg AgentRegistration, audience string, now time.Time) (Delegation, error) {
	return new(Verifier).VerifyRegistration(reg, audience, now)
}

func (v *Verifier) VerifyRegistration(reg AgentRegistration, audience string, now time.Time) (Delegation, error) {
	var d Delegation
	var a Acceptance
	if err := v.DecodePayload(reg.Delegation, KindDelegation, &d); err != nil {
		return d, err
	}
	if err := v.DecodePayload(reg.Acceptance, KindAcceptance, &a); err != nil {
		return d, err
	}
	digest, err := v.envelopeDigest(reg.Delegation)
	if err != nil {
		return d, err
	}
	if a.DelegationSHA256 != digest || a.AgentID != d.AgentID || a.IssuerKeyID != d.AgentKeyID || reg.Acceptance.Signature.PublicKey != d.AgentPublicKey {
		return d, errors.New("agent proof is not bound to this delegation")
	}
	if audience != "" && d.ServiceAudience != audience {
		return d, errors.New("delegation audience mismatch")
	}
	if !now.IsZero() {
		start, _ := Timestamp(d.NotBefore)
		end, _ := Timestamp(d.ExpiresAt)
		issued, _ := Timestamp(d.IssuedAt)
		accepted, _ := Timestamp(a.IssuedAt)
		if now.Before(start) || !now.Before(end) || issued.After(now.Add(2*time.Minute)) || accepted.After(now.Add(2*time.Minute)) || accepted.Before(start) {
			return d, errors.New("delegation is not active at the evaluation time")
		}
	}
	return d, nil
}
func (v *Verifier) verifySource(bundle Bundle) (Statement, *Delegation, error) {
	var s Statement
	if bundle.Protocol != Protocol {
		return s, nil, errors.New("unsupported bundle protocol")
	}
	if err := v.DecodePayload(bundle.Statement, KindStatement, &s); err != nil {
		return s, nil, err
	}
	if s.Issuer != KeyIdentity(s.IssuerKeyID) {
		return s, nil, errors.New("source issuer must identify agent key")
	}
	if (bundle.Delegation == nil) != (bundle.Acceptance == nil) {
		return s, nil, errors.New("incomplete agent registration")
	}
	if bundle.Delegation == nil {
		if s.DelegationSHA256 != "" {
			return s, nil, errors.New("missing referenced delegation")
		}
		return s, nil, nil
	}
	d, err := v.VerifyRegistration(AgentRegistration{Delegation: *bundle.Delegation, Acceptance: *bundle.Acceptance}, "", time.Time{})
	if err != nil {
		return s, nil, err
	}
	dh, err := v.envelopeDigest(*bundle.Delegation)
	if err != nil {
		return s, nil, err
	}
	if s.DelegationSHA256 != dh || s.AgentID != d.AgentID || s.IssuerKeyID != d.AgentKeyID || bundle.Statement.Signature.PublicKey != d.AgentPublicKey {
		return s, nil, errors.New("statement is not authorized by this delegation")
	}
	return s, &d, nil
}
func ValidateGrant(grant Envelope, statement Envelope, delegation Envelope, adminKeyID, audience string, now time.Time) (PublicationGrant, error) {
	return new(Verifier).ValidateGrant(grant, statement, delegation, adminKeyID, audience, now)
}

func (v *Verifier) ValidateGrant(grant Envelope, statement Envelope, delegation Envelope, adminKeyID, audience string, now time.Time) (PublicationGrant, error) {
	var g PublicationGrant
	if err := v.DecodePayload(grant, KindGrant, &g); err != nil {
		return g, err
	}
	sh, err := v.envelopeDigest(statement)
	if err != nil {
		return g, err
	}
	dh, err := v.envelopeDigest(delegation)
	if err != nil {
		return g, err
	}
	if g.IssuerKeyID != adminKeyID || g.ServiceAudience != audience || g.StatementSHA256 != sh || g.DelegationSHA256 != dh {
		return g, errors.New("publication grant does not authorize this request")
	}
	issued, _ := Timestamp(g.IssuedAt)
	expires, _ := Timestamp(g.ExpiresAt)
	if now.IsZero() || issued.After(now.Add(2*time.Minute)) || !now.Before(expires) || expires.Sub(issued) > 15*time.Minute {
		return g, errors.New("publication grant is expired or outside its validity window")
	}
	return g, nil
}

// Issue creates a new certificate over a verified statement. The caller owns
// service authorization and durable idempotency. It must not use a transport
// login as a substitute for a PublicationGrant.
func Issue(bundle Bundle, signer *Signer, issuer string, now time.Time) (Bundle, error) {
	return new(Verifier).Issue(bundle, signer, issuer, now)
}

// Issue has the same service-authorization requirements as the package function.
func (v *Verifier) Issue(bundle Bundle, signer *Signer, issuer string, now time.Time) (Bundle, error) {
	if now.IsZero() {
		return Bundle{}, errors.New("issuance time required")
	}
	if bundle.Certificate != nil {
		return Bundle{}, errors.New("cannot replace an existing certificate")
	}
	s, d, err := v.verifySource(bundle)
	if err != nil {
		return Bundle{}, err
	}
	sourceTime, _ := Timestamp(s.IssuedAt)
	if sourceTime.After(now.Add(2 * time.Minute)) {
		return Bundle{}, errors.New("source claims a future signing time")
	}
	expiry := now.UTC().Truncate(time.Second).Add(24 * time.Hour)
	binding := "not_provided"
	if d != nil {
		if _, err := v.VerifyRegistration(AgentRegistration{Delegation: *bundle.Delegation, Acceptance: *bundle.Acceptance}, issuer, now); err != nil {
			return Bundle{}, err
		}
		start, _ := Timestamp(d.NotBefore)
		end, _ := Timestamp(d.ExpiresAt)
		if sourceTime.Before(start) {
			return Bundle{}, errors.New("source claims a time before delegation")
		}
		if expiry.After(end) {
			expiry = end
		}
		binding = "admin_key_delegation"
	}
	id, err := NewID()
	if err != nil {
		return Bundle{}, err
	}
	sh, err := v.envelopeDigest(bundle.Statement)
	if err != nil {
		return Bundle{}, err
	}
	cert := Certificate{Header: NewHeader(KindCertificate, issuer, signer, now), CertificateID: id, StatementSHA256: sh, DelegationSHA256: s.DelegationSHA256, SourceKeyID: s.IssuerKeyID, ExpiresAt: expiry.Format(TimestampLayout), SignatureCheck: "valid", AgentBinding: binding, OrganizationBinding: "unproven", ContentTruth: "not_established"}
	signed, err := signer.Sign(KindCertificate, cert)
	if err != nil {
		return Bundle{}, err
	}
	bundle.Certificate = &signed
	return bundle, nil
}
func Verify(raw []byte, opts VerifyOptions) (Verification, error) {
	var bundle Bundle
	if err := StrictJSON(raw, &bundle); err != nil {
		return Verification{}, err
	}
	// The outer transport may use whitespace, but its exact field names and
	// explicit null attachments must match the portable bundle schema.
	var input any
	if err := StrictJSON(raw, &input); err != nil {
		return Verification{}, err
	}
	a, err := Canonical(input)
	if err != nil {
		return Verification{}, err
	}
	b, err := Canonical(bundle)
	if err != nil || !bytes.Equal(a, b) {
		return Verification{}, errors.New("missing or noncanonical bundle field")
	}
	return VerifyBundle(bundle, opts)
}
func VerifyBundle(bundle Bundle, opts VerifyOptions) (Verification, error) {
	return new(Verifier).VerifyBundle(bundle, opts)
}

func (v *Verifier) VerifyBundle(bundle Bundle, opts VerifyOptions) (Verification, error) {
	s, d, err := v.verifySource(bundle)
	if err != nil {
		return Verification{}, err
	}
	out := Verification{Protocol: Protocol, ArtifactIntegrity: "valid", IssuerTrust: "unknown", CertificateScope: "producer_only", AgentBinding: "not_provided", OrganizationBinding: "unproven", AuthorizationPolicy: "unknown", Freshness: "unknown", TimeBasis: "producer_claimed", ContentTruth: "not_established", ProviderEvidence: "not_provided", LogInclusion: "not_registered", Anchor: "not_requested", Issuer: s.Issuer, IssuerKeyID: s.IssuerKeyID, Statement: s}
	if d != nil {
		out.AgentBinding = "admin_key_delegation"
	}
	if bundle.Certificate == nil {
		return out, nil
	}
	var c Certificate
	if err := v.DecodePayload(*bundle.Certificate, KindCertificate, &c); err != nil {
		return out, err
	}
	sh, err := v.envelopeDigest(bundle.Statement)
	if err != nil {
		return out, err
	}
	if c.StatementSHA256 != sh || c.DelegationSHA256 != s.DelegationSHA256 || c.SourceKeyID != s.IssuerKeyID || c.AgentBinding != out.AgentBinding {
		return out, errors.New("certificate is attached to the wrong source")
	}
	issued, _ := Timestamp(c.IssuedAt)
	sourceTime, _ := Timestamp(s.IssuedAt)
	if sourceTime.After(issued.Add(2 * time.Minute)) {
		return out, errors.New("certificate predates claimed source signature")
	}
	if d != nil {
		if _, err := v.VerifyRegistration(AgentRegistration{Delegation: *bundle.Delegation, Acceptance: *bundle.Acceptance}, c.Issuer, issued); err != nil {
			return out, fmt.Errorf("certificate delegation: %w", err)
		}
		start, _ := Timestamp(d.NotBefore)
		expiry, _ := Timestamp(d.ExpiresAt)
		certExpiry, _ := Timestamp(c.ExpiresAt)
		if sourceTime.Before(start) || certExpiry.After(expiry) {
			return out, errors.New("certificate exceeds delegation scope")
		}
	}
	out.CertificateScope = "origin_signature_checked"
	out.TimeBasis = "issuer_claimed_check_time"
	out.Issuer = c.Issuer
	out.IssuerKeyID = c.IssuerKeyID
	out.CertificateID = c.CertificateID
	if opts.ExpectedIssuer != "" || len(opts.TrustedKeyIDs) > 0 {
		out.IssuerTrust = "untrusted"
	}
	if opts.ExpectedIssuer == c.Issuer {
		for _, key := range opts.TrustedKeyIDs {
			if key == c.IssuerKeyID {
				out.IssuerTrust = "accepted_by_policy"
			}
		}
	}
	if !opts.Now.IsZero() {
		end, _ := Timestamp(c.ExpiresAt)
		switch {
		case opts.Now.Before(issued):
			out.Freshness = "not_yet_valid"
		case !opts.Now.Before(end):
			out.Freshness = "expired"
		default:
			out.Freshness = "valid_at_evaluation_time"
		}
	}
	// No live key/delegation status is consulted. A valid historical signature
	// does not establish current authority or absence of later revocation.
	out.AuthorizationPolicy = "current_revocation_unknown"
	return out, nil
}
func VerifyArtifact(result Verification, raw []byte) bool {
	return result.Statement.ArtifactSHA256 == Hash(raw) && result.Statement.ArtifactSize == fmt.Sprint(len(raw))
}
