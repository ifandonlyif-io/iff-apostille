package apostille

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNaturalVersionDefaults covers the version-less signing helpers: an Ed25519
// signer signs Core 0.1 exactly as before, an ML-DSA-65 signer signs Core 0.3.
func TestNaturalVersionDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, algorithm string
	}{{"ed25519", Protocol, Algorithm}, {"ml-dsa-65", Protocol03, Algorithm03}} {
		t.Run(tc.name, func(t *testing.T) {
			admin, agent, issuer := testSignerFor(t, tc.protocol, 1), testSignerFor(t, tc.protocol, 2), testSignerFor(t, tc.protocol, 3)
			require.Equal(t, tc.algorithm, admin.Algorithm())
			require.Equal(t, tc.protocol, admin.NaturalProtocol())
			require.Equal(t, tc.protocol, NewHeader(KindStatement, "x", admin, fixedNow).Protocol)

			reg, err := CreateRegistration(admin, agent, exampleIssuer, 48*time.Hour, fixedNow)
			require.NoError(t, err)
			require.Equal(t, tc.protocol, reg.Delegation.Protocol)
			require.Equal(t, tc.algorithm, reg.Acceptance.Signature.Algorithm)
			statement, err := CreateStatement(strings.NewReader("hello\n"), "text/plain", agent, &reg, "", fixedNow)
			require.NoError(t, err)
			require.Equal(t, tc.protocol, statement.Protocol)
			grant, err := CreateGrant(statement, reg, admin, exampleIssuer, "private", fixedNow)
			require.NoError(t, err)
			require.Equal(t, tc.protocol, grant.Protocol)
			producer, err := CreateStatement(strings.NewReader("hello\n"), "text/plain", agent, nil, agentID, fixedNow)
			require.NoError(t, err)
			require.Equal(t, tc.protocol, producer.Protocol)

			// Issue follows the bundle, and the result verifies under its own version.
			bundle, err := Issue(Bundle{Protocol: tc.protocol, Statement: statement, Delegation: &reg.Delegation, Acceptance: &reg.Acceptance}, issuer, exampleIssuer, fixedNow.Add(time.Minute))
			require.NoError(t, err)
			require.Equal(t, tc.protocol, bundle.Certificate.Protocol)
			v, err := VerifyBundle(bundle, VerifyOptions{AcceptedProtocols: []string{tc.protocol}})
			require.NoError(t, err)
			require.Equal(t, tc.protocol, v.Protocol)

			// The version-less forms are the explicit ones with the natural version.
			var d Delegation
			require.NoError(t, DecodePayload(reg.Delegation, KindDelegation, &d))
			implicit, err := admin.Sign(KindDelegation, d)
			require.NoError(t, err)
			explicit, err := admin.SignFor(tc.protocol, KindDelegation, d)
			require.NoError(t, err)
			require.Equal(t, explicit, implicit)
		})
	}
}

func TestNaturalVersionRefusesMixedKeysAndKeepsExplicitForms(t *testing.T) {
	edAdmin, edAgent := testSignerFor(t, Protocol, 1), testSignerFor(t, Protocol, 2)
	mlAdmin, mlAgent := testSignerFor(t, Protocol03, 1), testSignerFor(t, Protocol03, 2)
	_, err := CreateRegistration(mlAdmin, edAgent, exampleIssuer, time.Hour, fixedNow)
	require.Error(t, err)
	_, err = CreateRegistration(edAdmin, mlAgent, exampleIssuer, time.Hour, fixedNow)
	require.Error(t, err)
	// A Core 0.2 registration needs the explicit forms; the natural Ed25519 version is 0.1.
	reg02, err := CreateRegistrationFor(Protocol02, edAdmin, edAgent, exampleIssuer, time.Hour, fixedNow)
	require.NoError(t, err)
	_, err = CreateStatement(strings.NewReader("x"), "", edAgent, &reg02, "", fixedNow)
	require.Error(t, err)
	_, err = CreateStatementFor(Protocol02, strings.NewReader("x"), "", edAgent, &reg02, "", fixedNow)
	require.NoError(t, err)
	// A disabled signer signs nothing and reports Core 0.1.
	require.Equal(t, Protocol, (&Signer{}).NaturalProtocol())
	_, err = (&Signer{}).Sign(KindStatement, Statement{})
	require.Error(t, err)
	// An ML-DSA-65 signer still signs Core 0.1 or 0.2 payloads only through a key of that algorithm.
	_, err = mlAdmin.SignFor(Protocol, KindStatement, Statement{})
	require.Error(t, err)
}
