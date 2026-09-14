// Package apostille implements the issuer-neutral Apostille 0.1 draft profile.
// It has no server, database, wallet, network, or IFF account dependency.
package apostille

import (
	"encoding/json"
	"time"
)

const (
	Protocol        = "https://ifandonlyif.io/apostille/spec/0.1"
	Algorithm       = "Ed25519"
	MaxInputBytes   = 256 << 10
	TimestampLayout = "2006-01-02T15:04:05Z"
	KindStatement   = "origin-statement"
	KindDelegation  = "agent-delegation"
	KindAcceptance  = "agent-acceptance"
	KindGrant       = "publication-grant"
	KindCertificate = "origin-certificate"
)

type Header struct {
	Protocol    string `json:"protocol"`
	Kind        string `json:"kind"`
	Issuer      string `json:"issuer"`
	IssuerKeyID string `json:"issuer_key_id"`
	IssuedAt    string `json:"issued_at"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}

type Envelope struct {
	Protocol      string    `json:"protocol"`
	Kind          string    `json:"kind"`
	Payload       string    `json:"payload"`
	PayloadSHA256 string    `json:"payload_sha256"`
	Signature     Signature `json:"signature"`
}

type Statement struct {
	Header
	AgentID           string `json:"agent_id"`
	DelegationSHA256  string `json:"delegation_sha256"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	ArtifactSize      string `json:"artifact_size"`
	ArtifactMediaType string `json:"artifact_media_type"`
	Nonce             string `json:"nonce"`
}

type Delegation struct {
	Header
	AgentID         string   `json:"agent_id"`
	AgentKeyID      string   `json:"agent_key_id"`
	AgentPublicKey  string   `json:"agent_public_key"`
	ServiceAudience string   `json:"service_audience"`
	NotBefore       string   `json:"not_before"`
	ExpiresAt       string   `json:"expires_at"`
	Scopes          []string `json:"scopes"`
}

type Acceptance struct {
	Header
	AgentID          string `json:"agent_id"`
	DelegationSHA256 string `json:"delegation_sha256"`
}

type PublicationGrant struct {
	Header
	StatementSHA256  string `json:"statement_sha256"`
	DelegationSHA256 string `json:"delegation_sha256"`
	ServiceAudience  string `json:"service_audience"`
	Visibility       string `json:"visibility"`
	Purpose          string `json:"purpose"`
	ExpiresAt        string `json:"expires_at"`
	Nonce            string `json:"nonce"`
}

type Certificate struct {
	Header
	CertificateID       string `json:"certificate_id"`
	StatementSHA256     string `json:"statement_sha256"`
	DelegationSHA256    string `json:"delegation_sha256"`
	SourceKeyID         string `json:"source_key_id"`
	ExpiresAt           string `json:"expires_at"`
	SignatureCheck      string `json:"signature_check"`
	AgentBinding        string `json:"agent_binding"`
	OrganizationBinding string `json:"organization_binding"`
	ContentTruth        string `json:"content_truth"`
}

type Bundle struct {
	Protocol    string    `json:"protocol"`
	Statement   Envelope  `json:"statement"`
	Delegation  *Envelope `json:"delegation"`
	Acceptance  *Envelope `json:"acceptance"`
	Certificate *Envelope `json:"certificate"`
}

type AgentRegistration struct {
	Delegation Envelope `json:"delegation"`
	Acceptance Envelope `json:"acceptance"`
}

type Verification struct {
	Protocol            string    `json:"protocol"`
	ArtifactIntegrity   string    `json:"artifact_integrity"`
	IssuerTrust         string    `json:"issuer_trust"`
	CertificateScope    string    `json:"certificate_scope"`
	AgentBinding        string    `json:"agent_binding"`
	OrganizationBinding string    `json:"organization_binding"`
	AuthorizationPolicy string    `json:"authorization_policy"`
	Freshness           string    `json:"freshness"`
	TimeBasis           string    `json:"time_basis"`
	ContentTruth        string    `json:"content_truth"`
	ProviderEvidence    string    `json:"provider_evidence"`
	LogInclusion        string    `json:"log_inclusion"`
	Anchor              string    `json:"anchor"`
	Issuer              string    `json:"issuer"`
	IssuerKeyID         string    `json:"issuer_key_id"`
	CertificateID       string    `json:"certificate_id"`
	Statement           Statement `json:"statement"`
}

type VerifyOptions struct {
	ExpectedIssuer string
	TrustedKeyIDs  []string
	// Zero time never establishes freshness. The caller supplies the evaluation time.
	Now time.Time
}

type VerifiedEnvelope struct {
	Header  Header
	Payload json.RawMessage
	KeyID   string
}
