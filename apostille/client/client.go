package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/ifandonlyif-io/iff-apostille/util"
)

const maxResponseBytes = 8 << 20

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
var codePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
var keyIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Client struct {
	base, issuer  string
	trustedKeyIDs []string
	http          *http.Client
	mu            sync.Mutex
	token         string
	revision      uint64
}

// New configures a client without making any network requests. BaseURL is the
// exact API base, e.g. https://ifandonlyif.io/api/apostille/v1. Issuer is pinned
// separately; fetching a key directory never establishes certificate trust.
func New(config Config) (*Client, error) {
	u, err := url.Parse(config.BaseURL)
	if err != nil || len(config.BaseURL) > 2048 || u.Hostname() == "" || u.User != nil || strings.ContainsAny(config.BaseURL, "?#%\\\r\n\t ") || !strings.HasSuffix(strings.TrimSuffix(u.Path, "/"), "/api/apostille/v1") || !core.ValidIssuer(config.Issuer) {
		return nil, sdkError("invalid_configuration")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	allowHTTP := config.AllowInsecureLocalhost && local
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, sdkError("https_required")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, sdkError("invalid_base_url")
		}
	}
	if config.Timeout < 0 || config.Timeout > 2*time.Minute {
		return nil, sdkError("invalid_timeout")
	}
	for _, keyID := range config.TrustedKeyIDs {
		if !keyIDPattern.MatchString(keyID) {
			return nil, sdkError("invalid_trusted_key_id")
		}
	}
	c := &Client{trustedKeyIDs: append([]string(nil), config.TrustedKeyIDs...), base: strings.TrimSuffix(config.BaseURL, "/"), issuer: config.Issuer, http: util.NewSafeHTTPClient(util.SafeHTTPClientConfig{Timeout: config.Timeout, AllowPrivateIPs: config.AllowPrivateNetwork || allowHTTP, AllowNonTLS: allowHTTP, AllowNonStandard: true})}
	if config.AccessToken != "" {
		if err := c.SetAccessToken(config.AccessToken); err != nil {
			return nil, err
		}
	}
	return c, nil
}
func sdkError(code string) error   { return &APIError{Code: code} }
func validToken(token string) bool { return len(token) <= 4096 && tokenPattern.MatchString(token) }
func (c *Client) SetAccessToken(token string) error {
	if !validToken(token) {
		return sdkError("invalid_access_token")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revision++
	c.token = token
	return nil
}
func (c *Client) ClearSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revision++
	c.token = ""
}
func (c *Client) session() (string, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token, c.revision
}
func (c *Client) request(ctx context.Context, method, path string, body any, authenticated bool, out any) ([]byte, error) {
	token, revision := c.session()
	if !authenticated {
		token = ""
	} else if token == "" {
		return nil, sdkError("authentication_required")
	}
	var raw []byte
	var err error
	if body != nil {
		raw, err = core.Canonical(body)
		if err != nil || len(raw) > core.MaxInputBytes {
			return nil, sdkError("invalid_request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return nil, sdkError("invalid_request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, sdkError("network_error")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, &APIError{StatusCode: res.StatusCode, Code: "redirect_rejected"}
	}
	if res.StatusCode == 401 && token != "" {
		c.mu.Lock()
		if c.revision == revision {
			c.token = ""
			c.revision++
		}
		c.mu.Unlock()
	}
	if res.ContentLength > maxResponseBytes {
		return nil, &APIError{StatusCode: res.StatusCode, Code: "response_too_large"}
	}
	raw, err = io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, sdkError("response_unavailable")
	}
	if len(raw) > maxResponseBytes {
		return nil, &APIError{StatusCode: res.StatusCode, Code: "response_too_large"}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var problem struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(raw, &problem)
		if !codePattern.MatchString(problem.Code) {
			problem.Code = "http_error"
		}
		retry := res.Header.Get("Retry-After")
		if len(retry) > 128 {
			retry = ""
		}
		return nil, &APIError{StatusCode: res.StatusCode, Code: problem.Code, RetryAfter: retry}
	}
	if err := json.Unmarshal(raw, out); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, &APIError{StatusCode: res.StatusCode, Code: "invalid_response"}
	}
	return raw, nil
}
func (c *Client) Status(ctx context.Context) (out Status, err error) {
	_, err = c.request(ctx, "GET", "/status", nil, false, &out)
	if err == nil && (out.Protocol != core.Protocol || out.Issuer != c.issuer) {
		err = sdkError("issuer_mismatch")
	}
	return
}
func (c *Client) Keys(ctx context.Context) (out KeyDirectory, err error) {
	_, err = c.request(ctx, "GET", "/keys", nil, false, &out)
	if err != nil {
		return
	}
	if out.Protocol != core.Protocol || out.Issuer != c.issuer || out.Keys == nil {
		return out, sdkError("invalid_key_directory")
	}
	for _, key := range out.Keys {
		pub, e := core.ParsePublicKey(key.PublicKey)
		if e != nil || key.Algorithm != core.Algorithm || core.Fingerprint(pub) != key.KeyID {
			return out, sdkError("invalid_key_directory")
		}
	}
	return
}
func (c *Client) CreateChallenge(ctx context.Context, publicKey string) (out Challenge, err error) {
	pub, err := core.ParsePublicKey(publicKey)
	if err != nil {
		return out, err
	}
	_, err = c.request(ctx, "POST", "/auth/challenges", map[string]string{"public_key": publicKey}, false, &out)
	if err != nil {
		return
	}
	now := time.Now()
	expected := fmt.Sprintf("iff-apostille/login/0.1\nissuer:%s\nkey_id:%s\nchallenge:%s\nexpires_at:%s\npurpose:register_or_login", c.issuer, core.Fingerprint(pub), out.ChallengeID, out.ExpiresAt.UTC().Format(core.TimestampLayout))
	if out.Issuer != c.issuer || !core.ValidID(out.ChallengeID) || !out.ExpiresAt.After(now) || out.ExpiresAt.After(now.Add(7*time.Minute)) || out.Message != expected {
		err = sdkError("invalid_challenge")
	}
	return
}
func (c *Client) Login(ctx context.Context, signer *core.Signer) (out LoginResult, err error) {
	if !signer.Enabled() {
		return out, sdkError("signing_key_required")
	}
	c.mu.Lock()
	c.token = ""
	c.revision++
	revision := c.revision
	c.mu.Unlock()
	challenge, err := c.CreateChallenge(ctx, signer.PublicKey())
	if err != nil {
		return out, err
	}
	if _, current := c.session(); current != revision {
		return out, sdkError("session_changed")
	}
	sig, err := signer.SignChallenge(challenge.Message)
	if err != nil {
		return out, err
	}
	_, err = c.request(ctx, "POST", "/auth/verify", map[string]string{"challenge_id": challenge.ChallengeID, "message": challenge.Message, "signature": sig}, false, &out)
	if err != nil {
		return
	}
	if out.TokenType != "Bearer" || out.ExpiresIn <= 0 || !validToken(out.AccessToken) || out.Workspace.AdminKeyID != signer.KeyID() || out.Workspace.AdminPublicKey != signer.PublicKey() {
		return out, sdkError("invalid_session")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revision != revision {
		return out, sdkError("session_changed")
	}
	c.token = out.AccessToken
	c.revision++
	return
}
func (c *Client) Me(ctx context.Context) (out WorkspaceState, err error) {
	_, err = c.request(ctx, "GET", "/me", nil, true, &out)
	return
}
func (c *Client) UpdateWorkspace(ctx context.Context, name string, public bool) (out Workspace, err error) {
	_, err = c.request(ctx, "PUT", "/workspace", struct {
		Name   string `json:"name"`
		Public bool   `json:"is_public"`
	}{name, public}, true, &out)
	return
}
func (c *Client) RegisterAgent(ctx context.Context, name string, reg core.AgentRegistration) (out Agent, err error) {
	if _, err = core.VerifyRegistration(reg, c.issuer, time.Now()); err != nil {
		return
	}
	_, err = c.request(ctx, "POST", "/agents", struct {
		Name string `json:"name"`
		core.AgentRegistration
	}{name, reg}, true, &out)
	return
}
func (c *Client) RevokeAgent(ctx context.Context, id string) (out Agent, err error) {
	if !core.ValidID(id) {
		return out, sdkError("invalid_id")
	}
	_, err = c.request(ctx, "POST", "/agents/"+id+"/revoke", nil, true, &out)
	return
}
func (c *Client) checkedBundle(raw []byte) (VerifiedBundle, error) {
	verification, err := core.Verify(raw, core.VerifyOptions{ExpectedIssuer: c.issuer, TrustedKeyIDs: c.trustedKeyIDs, Now: time.Now()})
	if err != nil || verification.Issuer != c.issuer || verification.CertificateScope != "origin_signature_checked" || (len(c.trustedKeyIDs) > 0 && verification.IssuerTrust != "accepted_by_policy") {
		return VerifiedBundle{}, sdkError("invalid_certificate_response")
	}
	var b core.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return VerifiedBundle{}, sdkError("invalid_certificate_response")
	}
	return VerifiedBundle{Bundle: b, Verification: verification}, nil
}
func (c *Client) recordBundle(raw []byte) (VerifiedBundle, error) {
	var record struct {
		Bundle json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return VerifiedBundle{}, sdkError("invalid_certificate_response")
	}
	return c.checkedBundle(record.Bundle)
}
func (c *Client) Submit(ctx context.Context, statement, grant core.Envelope) (out Certificate, err error) {
	if _, err = core.VerifyEnvelope(statement); err != nil || statement.Kind != core.KindStatement {
		return out, sdkError("invalid_source_statement")
	}
	var g core.PublicationGrant
	if err = core.DecodePayload(grant, core.KindGrant, &g); err != nil {
		return
	}
	digest, err := core.EnvelopeDigest(statement)
	if err != nil {
		return out, err
	}
	issued, _ := core.Timestamp(g.IssuedAt)
	expires, _ := core.Timestamp(g.ExpiresAt)
	now := time.Now()
	if g.ServiceAudience != c.issuer || g.StatementSHA256 != digest || issued.After(now.Add(2*time.Minute)) || !expires.After(now) || expires.Sub(issued) > 15*time.Minute {
		return out, sdkError("invalid_publication_grant")
	}
	raw, err := c.request(ctx, "POST", "/submissions", struct {
		Statement core.Envelope `json:"statement"`
		Grant     core.Envelope `json:"grant"`
	}{statement, grant}, true, &out)
	if err != nil {
		return out, err
	}
	checked, err := c.recordBundle(raw)
	if err != nil {
		return out, sdkError("invalid_certificate_response")
	}
	out.Bundle = checked.Bundle
	verified := checked.Verification
	actual, _ := core.EnvelopeDigest(out.Bundle.Statement)
	if err != nil || verified.Issuer != c.issuer || verified.CertificateScope != "origin_signature_checked" || actual != digest || (g.Visibility == "private" && out.IsPublic) {
		return out, sdkError("invalid_certificate_response")
	}
	return out, nil
}
func (c *Client) GetBundle(ctx context.Context, id string) (out VerifiedBundle, err error) {
	if !core.ValidID(id) {
		return out, sdkError("invalid_id")
	}
	raw, err := c.request(ctx, "GET", "/certificates/"+id+"/bundle", nil, true, &out)
	if err != nil {
		return out, err
	}
	return c.checkedBundle(raw)
}
func (c *Client) HideCertificate(ctx context.Context, id string) (out HiddenCertificate, err error) {
	if !core.ValidID(id) {
		return out, sdkError("invalid_id")
	}
	_, err = c.request(ctx, "POST", "/certificates/"+id+"/hide", nil, true, &out)
	return
}
func (c *Client) GetPublicCertificate(ctx context.Context, id string) (out PublicCertificate, err error) {
	if !core.ValidID(id) {
		return out, sdkError("invalid_id")
	}
	raw, err := c.request(ctx, "GET", "/public/certificates/"+id, nil, false, &out)
	if err == nil {
		var checked VerifiedBundle
		checked, err = c.recordBundle(raw)
		out.Bundle, out.Verification = checked.Bundle, checked.Verification
	}
	return
}
func (c *Client) GetPublicOrganization(ctx context.Context, id string) (out PublicOrganization, err error) {
	if !core.ValidID(id) {
		return out, sdkError("invalid_id")
	}
	_, err = c.request(ctx, "GET", "/public/organizations/"+id, nil, false, &out)
	return
}

// IsAPIError permits callers to handle typed HTTP/SDK failures without matching
// text; use errors.As for status/code/retry-after details.
func IsAPIError(err error) bool { var target *APIError; return errors.As(err, &target) }
