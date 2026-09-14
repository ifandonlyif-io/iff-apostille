package zkbudget

import (
	"testing"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/stretchr/testify/require"
)

func reviewSigner(t *testing.T) *core.Signer {
	t.Helper()
	seed, _, err := core.GenerateKey()
	require.NoError(t, err)
	signer, err := core.NewSigner(seed)
	require.NoError(t, err)
	return signer
}

func TestCertifiedDelegatedSourceRequiresIndependentIssuerAndSourcePins(t *testing.T) {
	prover, verifier, _ := testProver(t)
	private, _, _, _ := fixture(t)

	const issuerID = "https://budget-issuer.example/apostille"
	admin := reviewSigner(t)
	agent := reviewSigner(t)
	issuer := reviewSigner(t)
	other := reviewSigner(t)

	// Keep the certificate lifetime shorter than the receiver request so the
	// expired-certificate case is isolated from request expiry.
	registration, err := core.CreateRegistration(admin, agent, issuerID, 61*time.Minute, testNow.Add(-time.Hour))
	require.NoError(t, err)
	source, err := SignSnapshot(private.Snapshot, agent, &registration, "", testNow)
	require.NoError(t, err)
	source, err = core.Issue(source, issuer, issuerID, testNow)
	require.NoError(t, err)
	request, err := NewRequest(private.Snapshot, "certified-budget-review", "urn:example:certified-audit", "70000", testNow)
	require.NoError(t, err)
	document, err := prover.Prove(private, source, request, testNow)
	require.NoError(t, err)

	valid := VerifyOptions{
		ExpectedRequest:     request,
		TrustedSourceKeyIDs: []string{agent.KeyID()},
		Now:                 testNow,
		SourceIssuer:        issuerID,
		SourceIssuerKeyIDs:  []string{issuer.KeyID()},
	}
	result, err := verifier.Verify(document, valid)
	require.NoError(t, err)
	require.Equal(t, "accepted_by_policy", result.CoreVerification.IssuerTrust)
	require.Equal(t, "valid_at_evaluation_time", result.CoreVerification.Freshness)
	require.Equal(t, "admin_key_delegation", result.CoreVerification.AgentBinding)
	require.Equal(t, agent.KeyID(), result.CoreVerification.Statement.IssuerKeyID)

	t.Run("wrong issuer", func(t *testing.T) {
		bad := valid
		bad.SourceIssuer = "https://other-issuer.example/apostille"
		_, err := verifier.Verify(document, bad)
		require.ErrorContains(t, err, "certificate does not satisfy issuer policy")
	})
	t.Run("wrong issuer key", func(t *testing.T) {
		bad := valid
		bad.SourceIssuerKeyIDs = []string{other.KeyID()}
		_, err := verifier.Verify(document, bad)
		require.ErrorContains(t, err, "certificate does not satisfy issuer policy")
	})
	t.Run("wrong source key", func(t *testing.T) {
		bad := valid
		bad.TrustedSourceKeyIDs = []string{other.KeyID()}
		_, err := verifier.Verify(document, bad)
		require.ErrorContains(t, err, "source key does not match independent department policy")
	})
	t.Run("expired certificate", func(t *testing.T) {
		bad := valid
		bad.Now = testNow.Add(2 * time.Minute)
		_, err := verifier.Verify(document, bad)
		require.ErrorContains(t, err, "certificate does not satisfy issuer policy")
	})
}

func TestProverRejectsProvingAndVerifyingKeysFromDifferentSetups(t *testing.T) {
	first, err := testSetup()
	require.NoError(t, err)
	second, err := Setup()
	require.NoError(t, err)
	require.NotEqual(t, first.VerifyingKeySHA256, second.VerifyingKeySHA256)

	prover, err := NewProver(first.ProvingKey, second.VerifyingKey, second.VerifyingKeySHA256)
	require.NoError(t, err, "same-circuit keys have compatible serialization layouts")
	private, source, request, _ := fixture(t)
	document, err := prover.Prove(private, source, request, testNow)
	require.EqualError(t, err, "proving key does not match pinned verification key")
	require.Zero(t, document)
}
