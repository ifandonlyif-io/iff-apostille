package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
)

var ownerSignaturePattern = regexp.MustCompile(`^0x[0-9a-f]{130}$`)

// ERC8004Config describes the optional hosted binding profile. Network entries
// are allowlisted identity registries; they never disclose an RPC endpoint.
type ERC8004Config struct {
	Profile              string           `json:"profile"`
	Enabled              bool             `json:"enabled"`
	Networks             []ERC8004Network `json:"networks"`
	MaxBindingAgeSeconds int              `json:"max_binding_age_seconds"`
	WalletSupport        string           `json:"wallet_support"`
}

type ERC8004Network struct {
	ChainID         string `json:"chain_id"`
	RegistryAddress string `json:"registry_address"`
}

// ERC8004BindingRecord is a private hosted record. Verification is local and
// intentionally omitted from JSON so callers retain the portable document.
type ERC8004BindingRecord struct {
	ID           string                      `json:"id"`
	AgentID      string                      `json:"agent_id"`
	Document     core.ERC8004BindingDocument `json:"document"`
	CreatedAt    time.Time                   `json:"created_at"`
	ExpiresAt    time.Time                   `json:"expires_at"`
	Verification core.ERC8004Verification    `json:"-"`
}

// ERC8004Config fetches public capability metadata without sending a session.
func (c *Client) ERC8004Config(ctx context.Context) (out ERC8004Config, err error) {
	_, err = c.request(ctx, "GET", "/erc8004/config", nil, false, &out)
	if err != nil {
		return out, err
	}
	if out.Profile != core.ERC8004Profile || out.Networks == nil || out.MaxBindingAgeSeconds != 3600 || out.WalletSupport != "eoa_only" {
		return out, sdkError("invalid_erc8004_config")
	}
	for _, network := range out.Networks {
		if (network.ChainID != "1" && network.ChainID != "8453") || !core.ValidERC8004Address(network.RegistryAddress) {
			return out, sdkError("invalid_erc8004_config")
		}
	}
	return out, nil
}

// CreateERC8004Binding submits one locally verified administrator request and
// EOA consent. It verifies the returned issuer snapshot before returning it.
func (c *Client) CreateERC8004Binding(ctx context.Context, agentID string, request core.Envelope, ownerSignature string) (out ERC8004BindingRecord, err error) {
	if err = c.validateERC8004Request(agentID, request); err != nil {
		return out, err
	}
	if !ownerSignaturePattern.MatchString(ownerSignature) {
		return out, sdkError("invalid_owner_signature")
	}
	raw, err := c.request(ctx, "POST", "/agents/"+agentID+"/erc8004", struct {
		Request        core.Envelope `json:"request"`
		OwnerSignature string        `json:"owner_signature"`
	}{request, ownerSignature}, true, &out)
	if err != nil {
		return out, err
	}
	return c.checkedERC8004Binding(raw, agentID, &request, ownerSignature)
}

// GetERC8004Binding gets the latest private snapshot for one registered agent.
func (c *Client) GetERC8004Binding(ctx context.Context, agentID string) (out ERC8004BindingRecord, err error) {
	if !core.ValidID(agentID) {
		return out, sdkError("invalid_id")
	}
	raw, err := c.request(ctx, "GET", "/agents/"+agentID+"/erc8004", nil, true, &out)
	if err != nil {
		return out, err
	}
	return c.checkedERC8004Binding(raw, agentID, nil, "")
}

func (c *Client) validateERC8004Request(agentID string, request core.Envelope) error {
	if !core.ValidID(agentID) {
		return sdkError("invalid_id")
	}
	// The server may return an identical historical nonce retry after expiry.
	checked, err := core.VerifyERC8004Request(request, nil, time.Time{})
	if err != nil || checked.AgentID != agentID || checked.ServiceAudience != c.issuer {
		return sdkError("invalid_erc8004_request")
	}
	return nil
}

func (c *Client) checkedERC8004Binding(raw []byte, agentID string, expectedRequest *core.Envelope, expectedOwnerSignature string) (ERC8004BindingRecord, error) {
	var record ERC8004BindingRecord
	if err := core.StrictJSON(raw, &record); err != nil || !core.ValidID(record.ID) || record.AgentID != agentID || record.CreatedAt.IsZero() || record.ExpiresAt.IsZero() {
		return ERC8004BindingRecord{}, sdkError("invalid_binding_response")
	}
	verification, err := core.VerifyERC8004Binding(record.Document, core.VerifyOptions{ExpectedIssuer: c.issuer, TrustedKeyIDs: c.trustedKeyIDs, Now: time.Now()})
	if err != nil || verification.Request.AgentID != agentID || verification.CheckedAt != record.CreatedAt.UTC().Format(core.TimestampLayout) || verification.ExpiresAt != record.ExpiresAt.UTC().Format(core.TimestampLayout) || (len(c.trustedKeyIDs) > 0 && verification.IssuerTrust != "pinned") {
		return ERC8004BindingRecord{}, sdkError("invalid_binding_response")
	}
	binding, err := decodeERC8004BindingPayload(record.Document.Binding)
	if err != nil || binding.Request.Kind != core.KindERC8004Request || binding.OwnerSignature == "" {
		return ERC8004BindingRecord{}, sdkError("invalid_binding_response")
	}
	if expectedRequest != nil {
		actual, actualErr := core.EnvelopeDigest(binding.Request)
		expected, expectedErr := core.EnvelopeDigest(*expectedRequest)
		if actualErr != nil || expectedErr != nil || actual != expected || binding.OwnerSignature != expectedOwnerSignature {
			return ERC8004BindingRecord{}, sdkError("invalid_binding_response")
		}
	}
	record.Verification = verification
	return record, nil
}

func decodeERC8004BindingPayload(envelope core.Envelope) (core.ERC8004Binding, error) {
	if envelope.Protocol != core.ERC8004Profile || envelope.Kind != core.KindERC8004Binding {
		return core.ERC8004Binding{}, fmt.Errorf("wrong binding envelope")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		return core.ERC8004Binding{}, err
	}
	var binding core.ERC8004Binding
	if err = core.StrictJSON(raw, &binding); err != nil {
		return core.ERC8004Binding{}, err
	}
	return binding, nil
}
