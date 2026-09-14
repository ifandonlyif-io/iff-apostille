package client

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/stretchr/testify/require"
)

func testERC8004ClientRecord(t *testing.T, issuer string) (core.Envelope, string, ERC8004BindingRecord, *core.Signer) {
	return testERC8004ClientRecordAt(t, issuer, time.Now().UTC().Truncate(time.Second))
}

func testERC8004ClientRecordAt(t *testing.T, issuer string, now time.Time) (core.Envelope, string, ERC8004BindingRecord, *core.Signer) {
	t.Helper()
	adminSeed, _, err := core.GenerateKey()
	require.NoError(t, err)
	admin, err := core.NewSigner(adminSeed)
	require.NoError(t, err)
	agentSeed, _, err := core.GenerateKey()
	require.NoError(t, err)
	agent, err := core.NewSigner(agentSeed)
	require.NoError(t, err)
	issuerSeed, _, err := core.GenerateKey()
	require.NoError(t, err)
	issuerSigner, err := core.NewSigner(issuerSeed)
	require.NoError(t, err)
	now = now.UTC().Truncate(time.Second)
	reg, err := core.CreateRegistration(admin, agent, issuer, time.Hour, now)
	require.NoError(t, err)
	request, err := core.CreateERC8004Request(admin, reg, core.ERC8004Identity{
		ChainID: "8453", RegistryAddress: "0x1111111111111111111111111111111111111111", ERC8004AgentID: "7", OwnerAddress: "0x2222222222222222222222222222222222222222",
	}, issuer, now)
	require.NoError(t, err)
	ownerSignature := "0x" + strings.Repeat("1", 130)
	document, err := issuerSigner.IssueERC8004Binding(reg, request, ownerSignature, core.ERC8004Observation{
		BlockNumber: "1", BlockHash: "0x" + strings.Repeat("2", 64), BlockTimestamp: now.Format(core.TimestampLayout),
	}, issuer, now)
	require.NoError(t, err)
	requestPayload, err := core.VerifyERC8004Request(request, &reg, now)
	require.NoError(t, err)
	return request, ownerSignature, ERC8004BindingRecord{ID: mustClientID(t), AgentID: requestPayload.AgentID, Document: document, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, issuerSigner
}

func mustClientID(t *testing.T) string {
	t.Helper()
	id, err := core.NewID()
	require.NoError(t, err)
	return id
}

func TestERC8004ConfigWithholdsBearer(t *testing.T) {
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/apostille/v1/erc8004/config", r.URL.Path)
		require.Empty(t, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(ERC8004Config{Profile: core.ERC8004Profile, Enabled: true, Networks: []ERC8004Network{{ChainID: "8453", RegistryAddress: "0x1111111111111111111111111111111111111111"}}, MaxBindingAgeSeconds: 3600, WalletSupport: "eoa_only"})
	})
	require.NoError(t, c.SetAccessToken("secret-token"))
	config, err := c.ERC8004Config(context.Background())
	require.NoError(t, err)
	require.True(t, config.Enabled)
}

func TestERC8004BindingClientVerifiesReturnedDocument(t *testing.T) {
	request, ownerSignature, record, issuerSigner := testERC8004ClientRecord(t, testIssuer)
	for _, pins := range [][]string{nil, {issuerSigner.KeyID()}, {"sha256:" + strings.Repeat("0", 64)}} {
		t.Run(strings.Join(pins, ","), func(t *testing.T) {
			_, server := localClient(t, func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "Bearer secret-token", r.Header.Get("Authorization"))
				require.True(t, strings.HasSuffix(r.URL.Path, "/agents/"+record.AgentID+"/erc8004"))
				_ = json.NewEncoder(w).Encode(record)
			})
			configured, err := New(Config{BaseURL: server.URL + "/api/apostille/v1", Issuer: testIssuer, AllowInsecureLocalhost: true, TrustedKeyIDs: pins})
			require.NoError(t, err)
			require.NoError(t, configured.SetAccessToken("secret-token"))
			if len(pins) > 0 && pins[0] != issuerSigner.KeyID() {
				_, err = configured.CreateERC8004Binding(context.Background(), record.AgentID, request, ownerSignature)
				var problem *APIError
				require.ErrorAs(t, err, &problem)
				require.Equal(t, "invalid_binding_response", problem.Code)
				return
			}
			got, err := configured.CreateERC8004Binding(context.Background(), record.AgentID, request, ownerSignature)
			require.NoError(t, err)
			wantTrust := "unknown"
			if len(pins) > 0 {
				wantTrust = "pinned"
			}
			require.Equal(t, wantTrust, got.Verification.IssuerTrust)
		})
	}
}

func TestERC8004BindingClientRejectsMismatchedResponse(t *testing.T) {
	request, ownerSignature, record, _ := testERC8004ClientRecord(t, testIssuer)
	for _, mutate := range []func(*ERC8004BindingRecord){
		func(r *ERC8004BindingRecord) { r.AgentID = mustClientID(t) },
		func(r *ERC8004BindingRecord) { r.CreatedAt = r.CreatedAt.Add(time.Second) },
		func(r *ERC8004BindingRecord) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) },
		func(r *ERC8004BindingRecord) {
			r.Document.Binding.Signature.Value = strings.Repeat("A", len(r.Document.Binding.Signature.Value))
		},
	} {
		candidate := record
		mutate(&candidate)
		c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(candidate) })
		require.NoError(t, c.SetAccessToken("secret-token"))
		_, err := c.CreateERC8004Binding(context.Background(), record.AgentID, request, ownerSignature)
		var problem *APIError
		require.ErrorAs(t, err, &problem)
		require.Equal(t, "invalid_binding_response", problem.Code)
	}
	// The returned snapshot is valid, but it was not consented by this caller.
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(record) })
	require.NoError(t, c.SetAccessToken("secret-token"))
	_, err := c.CreateERC8004Binding(context.Background(), record.AgentID, request, "0x"+strings.Repeat("3", 130))
	var problem *APIError
	require.ErrorAs(t, err, &problem)
	require.Equal(t, "invalid_binding_response", problem.Code)
}

func TestERC8004BindingClientAcceptsHistoricalSameNonceReplay(t *testing.T) {
	issued := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	request, ownerSignature, record, _ := testERC8004ClientRecordAt(t, testIssuer, issued)
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(record)
	})
	require.NoError(t, c.SetAccessToken("secret-token"))
	got, err := c.CreateERC8004Binding(context.Background(), record.AgentID, request, ownerSignature)
	require.NoError(t, err)
	require.Equal(t, "expired", got.Verification.Freshness)
}

func TestERC8004BindingClientRejectsMismatchedIssuerOnRetrieval(t *testing.T) {
	_, _, record, _ := testERC8004ClientRecord(t, "https://other.example/apostille")
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(record) })
	require.NoError(t, c.SetAccessToken("secret-token"))
	_, err := c.GetERC8004Binding(context.Background(), record.AgentID)
	var problem *APIError
	require.ErrorAs(t, err, &problem)
	require.Equal(t, "invalid_binding_response", problem.Code)
}
