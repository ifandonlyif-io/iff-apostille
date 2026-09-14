package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/stretchr/testify/require"
)

const testIssuer = "https://issuer.example/apostille"

func localClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	c, err := New(Config{BaseURL: s.URL + "/api/apostille/v1", Issuer: testIssuer, AllowInsecureLocalhost: true})
	require.NoError(t, err)
	return c, s
}
func TestConfigurationAndTokenBounds(t *testing.T) {
	for _, base := range []string{"http://issuer.example/api/apostille/v1", "https://secret@issuer.example/api/apostille/v1", "https://issuer.example/api/apostille/v1?secret", "https://issuer.example/a/../api/apostille/v1", "http://127.0.0.1/api/apostille/v1"} {
		_, err := New(Config{BaseURL: base, Issuer: testIssuer})
		require.Error(t, err, base)
	}
	c, err := New(Config{BaseURL: "https://issuer.example/api/apostille/v1", Issuer: testIssuer})
	require.NoError(t, err)
	for _, token := range []string{"", "secret\r\nheader", strings.Repeat("a", 4097)} {
		require.Error(t, c.SetAccessToken(token))
	}
	require.NoError(t, c.SetAccessToken("jwt.token-value_1"))
}
func TestRedirectNeverForwardsBearer(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	})
	require.NoError(t, c.SetAccessToken("secret-token"))
	_, err := c.Me(context.Background())
	require.Error(t, err)
	require.Zero(t, destinationCalls.Load())
}
func TestTypedErrorsAreSanitizedAndNeverRetried(t *testing.T) {
	var calls atomic.Int32
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"code":"daily_submission_limit","message":"secret response data"}`))
	})
	require.NoError(t, c.SetAccessToken("secret-token"))
	_, err := c.Me(context.Background())
	var apiError *APIError
	require.ErrorAs(t, err, &apiError)
	require.Equal(t, 429, apiError.StatusCode)
	require.Equal(t, "30", apiError.RetryAfter)
	require.NotContains(t, err.Error(), "secret")
	require.EqualValues(t, 1, calls.Load())
}
func TestPublicRequestsOmitSessionAndResponseBodyIsBounded(t *testing.T) {
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("public endpoint received session")
		}
		chunk := strings.Repeat("x", 1<<20)
		for i := 0; i < 9; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	})
	require.NoError(t, c.SetAccessToken("secret-token"))
	_, err := c.Status(context.Background())
	var apiError *APIError
	require.ErrorAs(t, err, &apiError)
	require.Equal(t, "response_too_large", apiError.Code)
}
func TestOldUnauthorizedResponseCannotClearNewSession(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"code":"invalid_session"}`))
	})
	require.NoError(t, c.SetAccessToken("old"))
	finished := make(chan error, 1)
	go func() { _, err := c.Me(context.Background()); finished <- err }()
	<-entered
	require.NoError(t, c.SetAccessToken("new"))
	close(release)
	require.Error(t, <-finished)
	token, _ := c.session()
	require.Equal(t, "new", token)
}
func TestClearSessionCancelsPendingLogin(t *testing.T) {
	seed, _, err := core.GenerateKey()
	require.NoError(t, err)
	signer, err := core.NewSigner(seed)
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/auth/challenges") {
			id, _ := core.NewID()
			expires := time.Now().UTC().Truncate(time.Second).Add(5 * time.Minute)
			message := "iff-apostille/login/0.1\nissuer:" + testIssuer + "\nkey_id:" + signer.KeyID() + "\nchallenge:" + id + "\nexpires_at:" + expires.Format(core.TimestampLayout) + "\npurpose:register_or_login"
			_ = json.NewEncoder(w).Encode(Challenge{ChallengeID: id, Message: message, ExpiresAt: expires, Issuer: testIssuer})
			return
		}
		close(entered)
		<-release
		_ = json.NewEncoder(w).Encode(LoginResult{AccessToken: "late-token", TokenType: "Bearer", ExpiresIn: 900, Workspace: Workspace{AdminKeyID: signer.KeyID(), AdminPublicKey: signer.PublicKey()}})
	})
	finished := make(chan error, 1)
	go func() { _, err := c.Login(context.Background(), signer); finished <- err }()
	<-entered
	c.ClearSession()
	close(release)
	var apiError *APIError
	require.ErrorAs(t, <-finished, &apiError)
	require.Equal(t, "session_changed", apiError.Code)
	token, _ := c.session()
	require.Empty(t, token)
}
func TestContextCancellationDuringResponseRead(t *testing.T) {
	started := make(chan struct{})
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := c.Status(ctx); finished <- err }()
	<-started
	cancel()
	require.True(t, errors.Is(<-finished, context.Canceled))
}

func TestFetchedCertificateRequiresConfiguredIssuer(t *testing.T) {
	seed, _, err := core.GenerateKey()
	require.NoError(t, err)
	signer, err := core.NewSigner(seed)
	require.NoError(t, err)
	agentID, err := core.NewID()
	require.NoError(t, err)
	statement, err := core.CreateStatement(strings.NewReader("local original"), "text/plain", signer, nil, agentID, time.Now())
	require.NoError(t, err)
	bundle, err := core.Issue(core.Bundle{Protocol: core.Protocol, Statement: statement}, signer, "https://other.example/apostille", time.Now())
	require.NoError(t, err)
	id, err := core.NewID()
	require.NoError(t, err)
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/bundle") {
			_ = json.NewEncoder(w).Encode(bundle)
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"public_id": id, "bundle": bundle})
		}
	})
	require.NoError(t, c.SetAccessToken("test-token"))
	for _, public := range []bool{false, true} {
		if public {
			_, err = c.GetPublicCertificate(context.Background(), id)
		} else {
			_, err = c.GetBundle(context.Background(), id)
		}
		var apiError *APIError
		require.ErrorAs(t, err, &apiError, "public=%v", public)
		require.Equal(t, "invalid_certificate_response", apiError.Code)
	}
}

func TestFetchedCertificateReturnsTrustAndEnforcesIndependentPins(t *testing.T) {
	seed, _, err := core.GenerateKey()
	require.NoError(t, err)
	signer, err := core.NewSigner(seed)
	require.NoError(t, err)
	id, err := core.NewID()
	require.NoError(t, err)
	statement, err := core.CreateStatement(strings.NewReader("local original"), "text/plain", signer, nil, id, time.Now())
	require.NoError(t, err)
	bundle, err := core.Issue(core.Bundle{Protocol: core.Protocol, Statement: statement}, signer, testIssuer, time.Now())
	require.NoError(t, err)
	_, server := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/bundle") {
			_ = json.NewEncoder(w).Encode(bundle)
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"public_id": id, "bundle": bundle})
		}
	})
	for _, pins := range [][]string{nil, {signer.KeyID()}, {"sha256:" + strings.Repeat("0", 64)}} {
		c, err := New(Config{BaseURL: server.URL + "/api/apostille/v1", Issuer: testIssuer, AllowInsecureLocalhost: true, TrustedKeyIDs: pins})
		require.NoError(t, err)
		require.NoError(t, c.SetAccessToken("test-token"))
		for _, public := range []bool{false, true} {
			var verification core.Verification
			if public {
				var fetched PublicCertificate
				fetched, err = c.GetPublicCertificate(context.Background(), id)
				verification = fetched.Verification
			} else {
				var fetched VerifiedBundle
				fetched, err = c.GetBundle(context.Background(), id)
				verification = fetched.Verification
			}
			if len(pins) > 0 && pins[0] != signer.KeyID() {
				var problem *APIError
				require.ErrorAs(t, err, &problem)
				require.Equal(t, "invalid_certificate_response", problem.Code)
				continue
			}
			require.NoError(t, err)
			want := "untrusted"
			if len(pins) > 0 {
				want = "accepted_by_policy"
			}
			require.Equal(t, want, verification.IssuerTrust)
			require.Equal(t, "valid_at_evaluation_time", verification.Freshness)
			require.True(t, core.VerifyArtifact(verification, []byte("local original")))
		}
	}
}
