package apostille

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVerifierSubmissionRetainsOnlyImmutableChecks(t *testing.T) {
	bundle, admin, _, issuer := fixture(t)
	bundle.Certificate = nil
	reg := AgentRegistration{Delegation: *bundle.Delegation, Acceptance: *bundle.Acceptance}
	now := fixedNow.Add(time.Minute)
	grant, err := CreateGrant(bundle.Statement, reg, admin, exampleIssuer, "private", now)
	require.NoError(t, err)
	var verifier Verifier
	var statement Statement
	require.NoError(t, verifier.DecodePayload(bundle.Statement, KindStatement, &statement))
	_, err = verifier.ValidateGrant(grant, bundle.Statement, reg.Delegation, admin.KeyID(), exampleIssuer, now)
	require.NoError(t, err)
	issued, err := verifier.Issue(bundle, issuer, exampleIssuer, now)
	require.NoError(t, err)
	require.Len(t, verifier.verified, 4, "statement, grant, delegation and acceptance each have one immutable check")
	require.Len(t, verifier.digests, 2, "only statement and delegation envelope digests are needed")
	_, err = VerifyBundle(issued, VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{issuer.KeyID()}, Now: now})
	require.NoError(t, err)

	// Reuse must never turn a past grant check into current authorization.
	_, err = verifier.ValidateGrant(grant, bundle.Statement, reg.Delegation, admin.KeyID(), "https://other.example", now)
	require.ErrorContains(t, err, "does not authorize")
	_, err = verifier.ValidateGrant(grant, bundle.Statement, reg.Delegation, admin.KeyID(), exampleIssuer, now.Add(6*time.Minute))
	require.ErrorContains(t, err, "expired")
	_, err = verifier.Issue(bundle, issuer, exampleIssuer, fixedNow.Add(49*time.Hour))
	require.ErrorContains(t, err, "not active")
}

func TestVerifierCannotReuseChecksForChangedEnvelopesOrPayloads(t *testing.T) {
	bundle, _, _, _ := fixture(t)
	var verifier Verifier
	reg := AgentRegistration{Delegation: *bundle.Delegation, Acceptance: *bundle.Acceptance}
	delegation, err := verifier.VerifyRegistration(reg, exampleIssuer, fixedNow)
	require.NoError(t, err)
	delegation.Scopes[0] = "untrusted mutation"
	delegation, err = verifier.VerifyRegistration(reg, exampleIssuer, fixedNow)
	require.NoError(t, err)
	require.Equal(t, []string{"sign_origin_statement"}, delegation.Scopes)

	var statement Statement
	require.NoError(t, verifier.DecodePayload(bundle.Statement, KindStatement, &statement))
	statement.AgentID = "untrusted mutation"
	require.NoError(t, verifier.DecodePayload(bundle.Statement, KindStatement, &statement))
	require.Equal(t, agentID, statement.AgentID)
	require.Error(t, verifier.DecodePayload(bundle.Statement, KindGrant, &PublicationGrant{}))
	bad := bundle.Statement
	bad.Signature.Value = strings.Repeat("A", len(bad.Signature.Value))
	require.ErrorContains(t, verifier.DecodePayload(bad, KindStatement, &statement), "signature")
	bad = bundle.Statement
	bad.PayloadSHA256 = strings.Repeat("0", 64)
	require.ErrorContains(t, verifier.DecodePayload(bad, KindStatement, &statement), "digest")
	require.Len(t, verifier.verified, 3, "invalid envelopes must not enter the cache")
}
