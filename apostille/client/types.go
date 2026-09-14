// Package client is the explicit online Apostille hosted API client. The parent
// apostille package remains network-free; importing either performs no I/O.
package client

import (
	"fmt"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
)

type Config struct {
	TrustedKeyIDs          []string
	BaseURL                string
	Issuer                 string
	AccessToken            string
	Timeout                time.Duration
	AllowInsecureLocalhost bool
	// AllowPrivateNetwork permits explicitly configured HTTPS services on a
	// private network. It never enables HTTP or redirects.
	AllowPrivateNetwork bool
}

type APIError struct {
	StatusCode int
	Code       string
	RetryAfter string
}

func (e *APIError) Error() string { return fmt.Sprintf("Apostille API: %s (%d)", e.Code, e.StatusCode) }

type Workspace struct {
	ID             string    `json:"id"`
	AdminKeyID     string    `json:"admin_key_id"`
	AdminPublicKey string    `json:"admin_public_key"`
	Name           string    `json:"name"`
	PublicID       string    `json:"public_id"`
	IsPublic       bool      `json:"is_public"`
	CreatedAt      time.Time `json:"created_at"`
}
type Agent struct {
	ID          string        `json:"id"`
	WorkspaceID string        `json:"workspace_id"`
	Name        string        `json:"name"`
	KeyID       string        `json:"key_id"`
	PublicKey   string        `json:"public_key"`
	Delegation  core.Envelope `json:"delegation"`
	Acceptance  core.Envelope `json:"acceptance"`
	ExpiresAt   time.Time     `json:"expires_at"`
	CreatedAt   time.Time     `json:"created_at"`
	RevokedAt   *time.Time    `json:"revoked_at,omitempty"`
}
type Certificate struct {
	ID             string      `json:"id"`
	WorkspaceID    string      `json:"workspace_id"`
	AgentID        string      `json:"agent_id"`
	PublicID       string      `json:"public_id"`
	IdempotencyKey string      `json:"idempotency_key"`
	BodyHash       string      `json:"body_hash"`
	Bundle         core.Bundle `json:"bundle"`
	IsPublic       bool        `json:"is_public"`
	CreatedAt      time.Time   `json:"created_at"`
}
type WorkspaceState struct {
	Workspace    Workspace     `json:"workspace"`
	Agents       []Agent       `json:"agents"`
	Certificates []Certificate `json:"certificates"`
}
type Status struct {
	Protocol string   `json:"protocol"`
	Issuer   string   `json:"issuer"`
	Enabled  bool     `json:"enabled"`
	Features []string `json:"features"`
	Planned  []string `json:"planned"`
	Limits   Limits   `json:"limits"`
}
type Limits struct {
	MaxAgents            int `json:"max_agents"`
	MaxDailyCertificates int `json:"max_daily_certificates"`
}
type PublicKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Algorithm string `json:"algorithm"`
}
type KeyDirectory struct {
	Protocol string      `json:"protocol"`
	Issuer   string      `json:"issuer"`
	Keys     []PublicKey `json:"keys"`
	Trust    string      `json:"trust"`
}
type Challenge struct {
	ChallengeID string    `json:"challenge_id"`
	Message     string    `json:"message"`
	ExpiresAt   time.Time `json:"expires_at"`
	Issuer      string    `json:"issuer"`
}
type LoginResult struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int       `json:"expires_in"`
	Workspace   Workspace `json:"workspace"`
}
type HiddenCertificate struct {
	ID       string `json:"id"`
	IsPublic bool   `json:"is_public"`
}
type VerifiedBundle struct {
	Bundle       core.Bundle       `json:"bundle"`
	Verification core.Verification `json:"verification"`
}

type PublicCertificate struct {
	Verification core.Verification `json:"-"`
	PublicID     string            `json:"public_id"`
	Bundle       core.Bundle       `json:"bundle"`
	CreatedAt    time.Time         `json:"created_at"`
}
type PublicOrganization struct {
	Profile struct {
		PublicID  string    `json:"public_id"`
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
	} `json:"profile"`
	OrganizationBinding string `json:"organization_binding"`
}
