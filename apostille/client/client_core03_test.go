package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/stretchr/testify/require"
)

func newEd25519(t *testing.T) *core.Signer {
	t.Helper()
	seed, _, err := core.GenerateKey()
	require.NoError(t, err)
	signer, err := core.NewSigner(seed)
	require.NoError(t, err)
	return signer
}

func newMLDSA(t *testing.T) *core.Signer {
	t.Helper()
	seed, _, err := core.GenerateMLDSAKey()
	require.NoError(t, err)
	signer, err := core.NewMLDSASigner(seed)
	require.NoError(t, err)
	return signer
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var problem *APIError
	require.ErrorAs(t, err, &problem)
	require.Equal(t, code, problem.Code)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func directory(protocol string, signer *core.Signer, algorithm string) KeyDirectory {
	return KeyDirectory{Protocol: protocol, Issuer: testIssuer, Keys: []PublicKey{{KeyID: signer.KeyID(), PublicKey: signer.PublicKey(), Algorithm: algorithm}}, Trust: "online_bootstrap_only"}
}

func TestStatusExposesProtocols(t *testing.T) {
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, Status{Protocol: core.Protocol, Protocols: []string{core.Protocol, core.Protocol03}, Issuer: testIssuer, Enabled: true, Features: []string{"ml_dsa_65_keys"}})
	})
	status, err := c.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{core.Protocol, core.Protocol03}, status.Protocols)
	// A 0.1-only service omits the field.
	old, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"protocol": core.Protocol, "issuer": testIssuer, "enabled": true, "features": []string{}, "planned": []string{}})
	})
	status, err = old.Status(context.Background())
	require.NoError(t, err)
	require.Empty(t, status.Protocols)
}

func TestKeysForCore03(t *testing.T) {
	issuerKey := newMLDSA(t)
	var query url.Values
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		writeJSON(w, 200, directory(query.Get("protocol"), issuerKey, core.Algorithm03))
	})
	out, err := c.KeysFor(context.Background(), core.Protocol03)
	require.NoError(t, err)
	require.Equal(t, core.Protocol03, query.Get("protocol"))
	require.Equal(t, core.Protocol03, out.Protocol)
	require.Equal(t, issuerKey.KeyID(), out.Keys[0].KeyID)
	require.Len(t, out.Keys[0].PublicKey, 2603)
}

func TestKeysForCore01UsesPlainKeysRoute(t *testing.T) {
	issuerKey := newEd25519(t)
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.URL.RawQuery)
		require.True(t, strings.HasSuffix(r.URL.Path, "/keys"))
		writeJSON(w, 200, directory(core.Protocol, issuerKey, core.Algorithm))
	})
	out, err := c.KeysFor(context.Background(), core.Protocol)
	require.NoError(t, err)
	require.Equal(t, core.Protocol, out.Protocol)
	plain, err := c.Keys(context.Background())
	require.NoError(t, err)
	require.Equal(t, out, plain)
}

func TestKeysForRejectsEveryInvalidDirectory(t *testing.T) {
	issuerKey, other, ed := newMLDSA(t), newMLDSA(t), newEd25519(t)
	good := func() KeyDirectory { return directory(core.Protocol03, issuerKey, core.Algorithm03) }
	cases := map[string]func(*KeyDirectory){
		"wrong protocol echo": func(d *KeyDirectory) { d.Protocol = core.Protocol },
		"0.2 echo":            func(d *KeyDirectory) { d.Protocol = core.Protocol02 },
		"wrong issuer":        func(d *KeyDirectory) { d.Issuer = "https://other.example/apostille" },
		"wrong algorithm":     func(d *KeyDirectory) { d.Keys[0].Algorithm = core.Algorithm },
		"short key":           func(d *KeyDirectory) { d.Keys[0].PublicKey = d.Keys[0].PublicKey[:2602] },
		"long key":            func(d *KeyDirectory) { d.Keys[0].PublicKey += "A" },
		"ed25519 key": func(d *KeyDirectory) {
			d.Keys[0] = PublicKey{KeyID: ed.KeyID(), PublicKey: ed.PublicKey(), Algorithm: core.Algorithm03}
		},
		"fingerprint": func(d *KeyDirectory) { d.Keys[0].KeyID = other.KeyID() },
		"nil keys":    func(d *KeyDirectory) { d.Keys = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir := good()
			mutate(&dir)
			c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, dir) })
			_, err := c.KeysFor(context.Background(), core.Protocol03)
			requireCode(t, err, "invalid_key_directory")
		})
	}
}

func TestKeysForUnsupportedVersions(t *testing.T) {
	var calls int
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeJSON(w, 400, map[string]string{"code": "unsupported_protocol_version"})
	})
	// The hosted service does not issue 0.2.
	_, err := c.KeysFor(context.Background(), core.Protocol02)
	requireCode(t, err, "unsupported_protocol_version")
	var problem *APIError
	require.ErrorAs(t, err, &problem)
	require.Equal(t, 400, problem.StatusCode)
	require.Equal(t, 1, calls)
	// An unknown version is refused without a request.
	for _, protocol := range []string{"", "https://ifandonlyif.io/apostille/spec/0.4", strings.ToUpper(core.Protocol03)} {
		_, err = c.KeysFor(context.Background(), protocol)
		requireCode(t, err, "unsupported_protocol_version")
	}
	require.Equal(t, 1, calls)
}

// loginServer implements the hosted login contract for either algorithm.
func loginServer(t *testing.T, signer *core.Signer, messageFor func(id, expires string) string) http.HandlerFunc {
	t.Helper()
	verify := core.VerifyChallenge
	if signer.Algorithm() == core.Algorithm03 {
		verify = core.VerifyChallenge03
	}
	var message, challengeID string
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/auth/challenges") {
			var in struct {
				PublicKey string `json:"public_key"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			require.Equal(t, signer.PublicKey(), in.PublicKey)
			challengeID, _ = core.NewID()
			expires := time.Now().UTC().Truncate(time.Second).Add(5 * time.Minute)
			message = messageFor(challengeID, expires.Format(core.TimestampLayout))
			writeJSON(w, 201, Challenge{ChallengeID: challengeID, Message: message, ExpiresAt: expires, Issuer: testIssuer})
			return
		}
		var in struct {
			ChallengeID, Message, Signature string
		}
		var raw map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&raw))
		in.ChallengeID, in.Message, in.Signature = raw["challenge_id"], raw["message"], raw["signature"]
		if in.ChallengeID != challengeID || in.Message != message || !verify(signer.PublicKey(), in.Message, in.Signature) {
			writeJSON(w, 401, map[string]string{"code": "invalid_signature"})
			return
		}
		writeJSON(w, 200, LoginResult{AccessToken: "session-token", TokenType: "Bearer", ExpiresIn: 900, Workspace: Workspace{AdminKeyID: signer.KeyID(), AdminPublicKey: signer.PublicKey()}})
	}
}

func loginMessage(prefix string, signer *core.Signer) func(id, expires string) string {
	return func(id, expires string) string {
		return prefix + "\nissuer:" + testIssuer + "\nkey_id:" + signer.KeyID() + "\nchallenge:" + id + "\nexpires_at:" + expires + "\npurpose:register_or_login"
	}
}

func TestLoginWithBothAlgorithms(t *testing.T) {
	for name, tc := range map[string]struct {
		signer *core.Signer
		prefix string
		sigLen int
	}{
		"ed25519": {newEd25519(t), "iff-apostille/login/0.1", 86},
		"ml-dsa":  {newMLDSA(t), "iff-apostille/login/0.3", 4412},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := localClient(t, loginServer(t, tc.signer, loginMessage(tc.prefix, tc.signer)))
			challenge, err := c.CreateChallenge(context.Background(), tc.signer.PublicKey())
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(challenge.Message, tc.prefix+"\n"))
			result, err := c.Login(context.Background(), tc.signer)
			require.NoError(t, err)
			require.Equal(t, tc.signer.KeyID(), result.Workspace.AdminKeyID)
			token, _ := c.session()
			require.Equal(t, "session-token", token)
		})
	}
}

func TestChallengeRequiresMatchingPrefixAndExactMessage(t *testing.T) {
	ml, ed := newMLDSA(t), newEd25519(t)
	cases := map[string]struct {
		signer *core.Signer
		build  func(id, expires string) string
	}{
		"ml-dsa key with the 0.1 prefix":  {ml, loginMessage("iff-apostille/login/0.1", ml)},
		"ed25519 key with the 0.3 prefix": {ed, loginMessage("iff-apostille/login/0.3", ed)},
		"ml-dsa key with an extra line": {ml, func(id, expires string) string {
			return loginMessage("iff-apostille/login/0.3", ml)(id, expires) + "\nextra:1"
		}},
		"ml-dsa message for another key": {ml, loginMessage("iff-apostille/login/0.3", ed)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var verified int
			handler := loginServer(t, tc.signer, tc.build)
			c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/auth/verify") {
					verified++
				}
				handler(w, r)
			})
			_, err := c.CreateChallenge(context.Background(), tc.signer.PublicKey())
			requireCode(t, err, "invalid_challenge")
			_, err = c.Login(context.Background(), tc.signer)
			requireCode(t, err, "invalid_challenge")
			require.Zero(t, verified, "no proof is sent for a mismatching challenge")
		})
	}
}

func TestCreateChallengeRejectsMalformedKeysLocally(t *testing.T) {
	var calls int
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
	ml := newMLDSA(t)
	for _, key := range []string{"", "short", ml.PublicKey() + "A", ml.PublicKey()[:2602]} {
		_, err := c.CreateChallenge(context.Background(), key)
		require.Error(t, err)
	}
	require.Zero(t, calls)
}

// core03Fixture is a registered 0.3 agent with a statement and grant.
type core03Fixture struct {
	admin, agent, hosted *core.Signer
	reg                  core.AgentRegistration
	statement, grant     core.Envelope
}

func newCore03Fixture(t *testing.T) core03Fixture {
	t.Helper()
	f := core03Fixture{admin: newMLDSA(t), agent: newMLDSA(t), hosted: newMLDSA(t)}
	now := time.Now()
	var err error
	f.reg, err = core.CreateRegistrationFor(core.Protocol03, f.admin, f.agent, testIssuer, time.Hour, now)
	require.NoError(t, err)
	f.statement, err = core.CreateStatementFor(core.Protocol03, strings.NewReader("local original"), "text/plain", f.agent, &f.reg, "", now)
	require.NoError(t, err)
	f.grant, err = core.CreateGrantFor(core.Protocol03, f.statement, f.reg, f.admin, testIssuer, "private", now)
	require.NoError(t, err)
	return f
}

func (f core03Fixture) issue(t *testing.T, signer *core.Signer) core.Bundle {
	t.Helper()
	bundle, err := new(core.Verifier).Issue(core.Bundle{Protocol: core.Protocol03, Statement: f.statement, Delegation: &f.reg.Delegation, Acceptance: &f.reg.Acceptance}, signer, testIssuer, time.Now())
	require.NoError(t, err)
	return bundle
}

func submissionServer(t *testing.T, bundle func() core.Bundle) *Client {
	t.Helper()
	id, err := core.NewID()
	require.NoError(t, err)
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.True(t, strings.HasSuffix(r.URL.Path, "/submissions"))
		writeJSON(w, 201, Certificate{ID: id, Bundle: bundle(), IsPublic: false})
	})
	require.NoError(t, c.SetAccessToken("session-token"))
	return c
}

func pinned(t *testing.T, c *Client, keyIDs ...string) *Client {
	t.Helper()
	pinnedClient, err := New(Config{BaseURL: c.base, Issuer: testIssuer, AllowInsecureLocalhost: true, TrustedKeyIDs: keyIDs})
	require.NoError(t, err)
	require.NoError(t, pinnedClient.SetAccessToken("session-token"))
	return pinnedClient
}

func TestSubmitCore03(t *testing.T) {
	f := newCore03Fixture(t)
	certified := f.issue(t, f.hosted)
	c := pinned(t, submissionServer(t, func() core.Bundle { return certified }), f.hosted.KeyID())
	out, err := c.Submit(context.Background(), f.statement, f.grant)
	require.NoError(t, err)
	require.Equal(t, core.Protocol03, out.Bundle.Protocol)
	require.Equal(t, core.Algorithm03, out.Bundle.Certificate.Signature.Algorithm)

	// An unpinned client still accepts it and reports the issuer as untrusted;
	// a pin on another key is refused.
	_, err = submissionServer(t, func() core.Bundle { return certified }).Submit(context.Background(), f.statement, f.grant)
	require.NoError(t, err)
	wrongPin := pinned(t, c, f.admin.KeyID())
	_, err = wrongPin.Submit(context.Background(), f.statement, f.grant)
	requireCode(t, err, "invalid_certificate_response")
}

func TestSubmitCore03RejectsAnotherVersionsBundle(t *testing.T) {
	f := newCore03Fixture(t)
	// A complete, valid 0.1 bundle certified by an Ed25519 hosted key.
	now := time.Now()
	hosted01, admin01, agent01 := newEd25519(t), newEd25519(t), newEd25519(t)
	reg, err := core.CreateRegistration(admin01, agent01, testIssuer, time.Hour, now)
	require.NoError(t, err)
	statement01, err := core.CreateStatement(strings.NewReader("local original"), "text/plain", agent01, &reg, "", now)
	require.NoError(t, err)
	bundle01, err := core.Issue(core.Bundle{Protocol: core.Protocol, Statement: statement01, Delegation: &reg.Delegation, Acceptance: &reg.Acceptance}, hosted01, testIssuer, now)
	require.NoError(t, err)
	c := submissionServer(t, func() core.Bundle { return bundle01 })
	_, err = c.Submit(context.Background(), f.statement, f.grant)
	requireCode(t, err, "invalid_certificate_response")

	// And the reverse: a 0.3 bundle for a 0.1 submission.
	g01, err := core.CreateGrant(statement01, reg, admin01, testIssuer, "private", now)
	require.NoError(t, err)
	c = submissionServer(t, func() core.Bundle { return f.issue(t, f.hosted) })
	_, err = c.Submit(context.Background(), statement01, g01)
	requireCode(t, err, "invalid_certificate_response")

	// The matching 0.1 submission still works.
	c = submissionServer(t, func() core.Bundle { return bundle01 })
	out, err := c.Submit(context.Background(), statement01, g01)
	require.NoError(t, err)
	require.Equal(t, core.Protocol, out.Bundle.Protocol)
}

func TestSubmitRejectsBundleOfAnotherStatement(t *testing.T) {
	f, other := newCore03Fixture(t), newCore03Fixture(t)
	c := submissionServer(t, func() core.Bundle { return other.issue(t, other.hosted) })
	_, err := c.Submit(context.Background(), f.statement, f.grant)
	requireCode(t, err, "invalid_certificate_response")
}

func TestGetBundleCore03(t *testing.T) {
	f := newCore03Fixture(t)
	certified := f.issue(t, f.hosted)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, certified) }))
	t.Cleanup(server.Close)
	c, err := New(Config{BaseURL: server.URL + "/api/apostille/v1", Issuer: testIssuer, AllowInsecureLocalhost: true, TrustedKeyIDs: []string{f.hosted.KeyID()}})
	require.NoError(t, err)
	require.NoError(t, c.SetAccessToken("session-token"))
	id, _ := core.NewID()
	got, err := c.GetBundle(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, core.Protocol03, got.Verification.Protocol)
	require.Equal(t, "accepted_by_policy", got.Verification.IssuerTrust)
}

// A 0.1 grant that names a 0.3 statement's exact digest is refused before any
// request, so the version check, not the digest check, is what rejects it.
func TestSubmitRefusesGrantOfAnotherVersion(t *testing.T) {
	f := newCore03Fixture(t)
	admin01 := newEd25519(t)
	now := time.Now()
	digest, err := core.EnvelopeDigest(f.statement)
	require.NoError(t, err)
	delegation, err := core.EnvelopeDigest(f.reg.Delegation)
	require.NoError(t, err)
	header, err := core.NewHeaderFor(core.Protocol, core.KindGrant, core.KeyIdentity(admin01.KeyID()), admin01, now)
	require.NoError(t, err)
	nonce, err := core.NewID()
	require.NoError(t, err)
	grant01, err := admin01.SignFor(core.Protocol, core.KindGrant, core.PublicationGrant{Header: header, StatementSHA256: digest, DelegationSHA256: delegation, ServiceAudience: testIssuer, Visibility: "private", Purpose: "issue_origin_certificate", ExpiresAt: now.Add(5 * time.Minute).UTC().Format(core.TimestampLayout), Nonce: nonce})
	require.NoError(t, err)
	var calls int
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
	require.NoError(t, c.SetAccessToken("session-token"))
	_, err = c.Submit(context.Background(), f.statement, grant01)
	require.ErrorContains(t, err, "invalid_publication_grant")
	require.Zero(t, calls)
}

// A server that predates Core 0.3 ignores the query and answers with its 0.1
// directory, and refuses an ML-DSA-65 key at the challenge.
func TestOldServerCompatibility(t *testing.T) {
	hosted, admin := newEd25519(t), newMLDSA(t)
	var paths []string
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/keys"):
			writeJSON(w, 200, directory(core.Protocol, hosted, core.Algorithm))
		case strings.HasSuffix(r.URL.Path, "/status"):
			writeJSON(w, 200, map[string]any{"protocol": core.Protocol, "issuer": testIssuer, "enabled": true})
		default:
			writeJSON(w, 400, map[string]string{"code": "invalid_public_key"})
		}
	})
	status, err := c.Status(context.Background())
	require.NoError(t, err)
	require.Nil(t, status.Protocols)
	_, err = c.KeysFor(context.Background(), core.Protocol03)
	require.ErrorContains(t, err, "invalid_key_directory")
	_, err = c.Login(context.Background(), admin)
	requireCode(t, err, "invalid_public_key")
	require.Equal(t, "/api/apostille/v1/auth/challenges", paths[len(paths)-1], "no proof is sent after a refused challenge")
}

// A current server with Core 0.3 disabled refuses the 0.3 directory and an
// ML-DSA-65 challenge with their documented codes; no 0.1 fallback happens.
func TestServerWithCore03Disabled(t *testing.T) {
	admin := newMLDSA(t)
	var verifyCalls int
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/status"):
			writeJSON(w, 200, map[string]any{"protocol": core.Protocol, "protocols": []string{core.Protocol}, "issuer": testIssuer, "enabled": true})
		case strings.HasSuffix(r.URL.Path, "/keys"):
			writeJSON(w, 400, map[string]string{"code": "unsupported_protocol_version"})
		case strings.HasSuffix(r.URL.Path, "/auth/challenges"):
			writeJSON(w, 400, map[string]string{"code": "unsupported_key_algorithm"})
		default:
			verifyCalls++
			writeJSON(w, 500, map[string]string{"code": "unexpected"})
		}
	})
	status, err := c.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{core.Protocol}, status.Protocols)
	_, err = c.KeysFor(context.Background(), core.Protocol03)
	requireCode(t, err, "unsupported_protocol_version")
	_, err = c.Login(context.Background(), admin)
	requireCode(t, err, "unsupported_key_algorithm")
	require.Zero(t, verifyCalls)
}

// Downloading a historical certificate is not tied to the version of the key
// used to sign in: with both hosted issuer keys pinned, a 0.1 bundle is still
// accepted after an ML-DSA-65 session.
func TestHistoricalBundleIsNotLimitedBySessionVersion(t *testing.T) {
	now := time.Now()
	hosted01, admin01, agent01 := newEd25519(t), newEd25519(t), newEd25519(t)
	hosted03 := newMLDSA(t)
	reg, err := core.CreateRegistration(admin01, agent01, testIssuer, time.Hour, now)
	require.NoError(t, err)
	statement01, err := core.CreateStatement(strings.NewReader("historical"), "text/plain", agent01, &reg, "", now)
	require.NoError(t, err)
	bundle01, err := core.Issue(core.Bundle{Protocol: core.Protocol, Statement: statement01, Delegation: &reg.Delegation, Acceptance: &reg.Acceptance}, hosted01, testIssuer, now)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, bundle01) }))
	t.Cleanup(server.Close)
	c, err := New(Config{BaseURL: server.URL + "/api/apostille/v1", Issuer: testIssuer, AllowInsecureLocalhost: true, TrustedKeyIDs: []string{hosted01.KeyID(), hosted03.KeyID()}})
	require.NoError(t, err)
	require.NoError(t, c.SetAccessToken("ml-dsa-session-token"))
	id, _ := core.NewID()
	got, err := c.GetBundle(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, core.Protocol, got.Verification.Protocol)
	require.Equal(t, "accepted_by_policy", got.Verification.IssuerTrust)
}
