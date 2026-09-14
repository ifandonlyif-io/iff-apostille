package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/stretchr/testify/require"
)

var cliNow = time.Date(2026, 9, 13, 10, 11, 12, 987654321, time.FixedZone("test", 8*60*60))

func invokeCLI(t *testing.T, now time.Time, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := application{stdout: &stdout, stderr: &stderr, now: func() time.Time { return now }}
	err := app.run(context.Background(), args)
	return stdout.String(), stderr.String(), err
}

func generateTestKey(t *testing.T, dir, name, role string) string {
	t.Helper()
	path := filepath.Join(dir, name+".json")
	stdout, _, err := invokeCLI(t, cliNow, "keygen", "--out", path, "--role", role)
	require.NoError(t, err)
	require.NotContains(t, stdout, "seed")
	require.NotContains(t, stdout, "private")
	return path
}

func TestKeygenPermissionsAndNoClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	stdout, _, err := invokeCLI(t, cliNow, "keygen", "--out", path, "--role", "issuer")
	require.NoError(t, err)
	require.NotContains(t, stdout, "seed")

	info, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var stored keyFile
	require.NoError(t, core.StrictJSON(raw, &stored))
	require.NotEmpty(t, stored.Seed)
	require.Equal(t, "issuer", stored.Role)

	before := append([]byte(nil), raw...)
	_, _, err = invokeCLI(t, cliNow, "keygen", "--out", path)
	require.Error(t, err)
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, before, after)
}

func TestPrivateKeyRejectsGroupOrWorldReadableMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir, "key", "agent")
	require.NoError(t, os.Chmod(keyPath, 0o640))
	_, _, err := invokeCLI(t, cliNow,
		"sign", "--key", keyPath, "--file", keyPath,
		"--agent-id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"--out", filepath.Join(dir, "statement.json"))
	require.ErrorContains(t, err, "expose it to group or other users")
}

func TestDelegateAndGrantRejectNoncanonicalAudienceBeforeReadingFiles(t *testing.T) {
	for _, command := range []struct {
		name string
		args []string
	}{
		{
			name: "delegate uppercase host",
			args: []string{"delegate", "--admin-key", "missing-admin", "--agent-key", "missing-agent", "--audience", "https://Issuer.example/apostille", "--out", "registration.json"},
		},
		{
			name: "grant uppercase host",
			args: []string{"grant", "--admin-key", "missing-admin", "--statement", "missing-statement", "--registration", "missing-registration", "--audience", "https://Issuer.example/apostille", "--visibility", "private", "--out", "grant.json"},
		},
	} {
		t.Run(command.name, func(t *testing.T) {
			_, _, err := invokeCLI(t, cliNow, command.args...)
			require.ErrorContains(t, err, "audience must be an exact HTTPS or URN issuer identifier")
			require.NotContains(t, err.Error(), "missing")
		})
	}
}

func TestFullLocalPipelineAndTrustPolicy(t *testing.T) {
	dir := t.TempDir()
	adminPath := generateTestKey(t, dir, "admin", "administrator")
	agentPath := generateTestKey(t, dir, "agent", "agent")
	issuerPath := generateTestKey(t, dir, "issuer", "local-issuer")
	registrationPath := filepath.Join(dir, "registration.json")
	statementPath := filepath.Join(dir, "statement.json")
	grantPath := filepath.Join(dir, "grant.json")
	bundlePath := filepath.Join(dir, "bundle.json")
	artifactPath := filepath.Join(dir, "artifact.txt")
	require.NoError(t, os.WriteFile(artifactPath, []byte("offline artifact\n"), 0o644))
	const audience = "https://issuer.example/apostille"
	const agentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	_, _, err := invokeCLI(t, cliNow,
		"delegate", "--admin-key", adminPath, "--agent-key", agentPath,
		"--agent-id", agentID, "--audience", audience,
		"--out", registrationPath, "--days30")
	require.NoError(t, err)
	_, _, err = invokeCLI(t, cliNow,
		"sign", "--key", agentPath, "--file", artifactPath,
		"--registration", registrationPath, "--out", statementPath)
	require.NoError(t, err)
	_, _, err = invokeCLI(t, cliNow,
		"grant", "--admin-key", adminPath, "--statement", statementPath,
		"--registration", registrationPath, "--audience", audience,
		"--visibility", "public", "--out", grantPath)
	require.NoError(t, err)
	issueOutput, _, err := invokeCLI(t, cliNow,
		"issue", "--key", issuerPath, "--issuer", audience,
		"--statement", statementPath, "--registration", registrationPath,
		"--out", bundlePath)
	require.NoError(t, err)
	require.Contains(t, issueOutput, `"issuer_status": "self_asserted_local"`)

	issuerSigner, _, err := readSigner(issuerPath)
	require.NoError(t, err)
	verifyOutput, _, err := invokeCLI(t, cliNow.Add(time.Minute),
		"verify", "--offline", "--bundle", bundlePath,
		"--issuer", audience, "--key-id", issuerSigner.KeyID(),
		"--at", cliNow.Add(time.Minute).Format(time.RFC3339Nano),
		"--artifact", artifactPath, "--require-trusted")
	require.NoError(t, err)
	var result verificationOutput
	require.NoError(t, json.Unmarshal([]byte(verifyOutput), &result))
	require.True(t, result.Valid)
	require.True(t, result.Trusted)
	require.NotNil(t, result.ArtifactMatches)
	require.True(t, *result.ArtifactMatches)
	require.Equal(t, "accepted_by_policy", result.IssuerTrust)
	require.Equal(t, "valid_at_evaluation_time", result.Freshness)
	require.Equal(t, "issuer_claimed_check_time", result.TimeBasis)

	registration, err := readRegistration(registrationPath)
	require.NoError(t, err)
	statement, err := readEnvelope(statementPath)
	require.NoError(t, err)
	grant, err := readEnvelope(grantPath)
	require.NoError(t, err)
	adminSigner, _, err := readSigner(adminPath)
	require.NoError(t, err)
	_, err = core.ValidateGrant(
		grant, statement, registration.Delegation, adminSigner.KeyID(), audience,
		cliNow.UTC().Truncate(time.Second).Add(time.Minute))
	require.NoError(t, err)

	statementBefore, err := os.ReadFile(statementPath)
	require.NoError(t, err)
	_, _, err = invokeCLI(t, cliNow,
		"sign", "--key", agentPath, "--file", artifactPath,
		"--registration", registrationPath, "--out", statementPath)
	require.Error(t, err)
	statementAfter, err := os.ReadFile(statementPath)
	require.NoError(t, err)
	require.Equal(t, statementBefore, statementAfter)
}

func TestVerifyRejectsInvalidArtifactAndUntrustedStrictMode(t *testing.T) {
	dir := t.TempDir()
	agentPath := generateTestKey(t, dir, "agent", "agent")
	issuerPath := generateTestKey(t, dir, "issuer", "issuer")
	artifactPath := filepath.Join(dir, "artifact.bin")
	wrongArtifactPath := filepath.Join(dir, "wrong.bin")
	statementPath := filepath.Join(dir, "statement.json")
	bundlePath := filepath.Join(dir, "bundle.json")
	require.NoError(t, os.WriteFile(artifactPath, []byte("expected"), 0o644))
	require.NoError(t, os.WriteFile(wrongArtifactPath, []byte("substitute"), 0o644))
	const agentID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const issuer = "urn:example:local-issuer"
	_, _, err := invokeCLI(t, cliNow,
		"sign", "--key", agentPath, "--file", artifactPath,
		"--agent-id", agentID, "--out", statementPath)
	require.NoError(t, err)
	_, _, err = invokeCLI(t, cliNow,
		"issue", "--key", issuerPath, "--issuer", issuer,
		"--statement", statementPath, "--out", bundlePath)
	require.NoError(t, err)

	output, _, err := invokeCLI(t, cliNow.Add(time.Minute),
		"verify", "--offline", "--bundle", bundlePath, "--artifact", wrongArtifactPath)
	var mismatch *exitError
	require.True(t, errors.As(err, &mismatch))
	require.Equal(t, 4, mismatch.code)
	require.Contains(t, output, `"artifact_matches": false`)
	require.Contains(t, output, `"trusted": false`)

	output, _, err = invokeCLI(t, cliNow.Add(time.Minute),
		"verify", "--offline", "--bundle", bundlePath,
		"--issuer", issuer, "--key-id", "sha256:"+strings.Repeat("0", 64),
		"--require-trusted")
	var untrusted *exitError
	require.True(t, errors.As(err, &untrusted))
	require.Equal(t, 3, untrusted.code)
	require.Contains(t, output, `"issuer_trust": "untrusted"`)
}

func testERC8004BindingForCLI(t *testing.T, issued time.Time) (core.ERC8004BindingDocument, string, *core.Signer) {
	t.Helper()
	issued = issued.UTC().Truncate(time.Second)
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
	const issuer = "https://issuer.example/apostille"
	registration, err := core.CreateRegistration(admin, agent, issuer, 4*time.Hour, issued)
	require.NoError(t, err)
	request, err := core.CreateERC8004Request(admin, registration, core.ERC8004Identity{
		ChainID: "8453", RegistryAddress: "0x1111111111111111111111111111111111111111", ERC8004AgentID: "7", OwnerAddress: "0x2222222222222222222222222222222222222222",
	}, issuer, issued)
	require.NoError(t, err)
	document, err := issuerSigner.IssueERC8004Binding(registration, request, "0x"+strings.Repeat("1", 130), core.ERC8004Observation{
		BlockNumber: "1", BlockHash: "0x" + strings.Repeat("2", 64), BlockTimestamp: issued.Format(core.TimestampLayout),
	}, issuer, issued)
	require.NoError(t, err)
	return document, issuer, issuerSigner
}

func TestVerifyERC8004Offline(t *testing.T) {
	dir := t.TempDir()
	document, issuer, signer := testERC8004BindingForCLI(t, cliNow)
	path := filepath.Join(dir, "binding.json")
	raw, err := json.Marshal(document)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o644))

	output, _, err := invokeCLI(t, cliNow.Add(time.Minute), "verify-erc8004", "--binding", path,
		"--issuer", issuer, "--key-id", signer.KeyID(), "--require-trusted")
	require.NoError(t, err)
	var result erc8004VerificationOutput
	require.NoError(t, json.Unmarshal([]byte(output), &result))
	require.True(t, result.Valid)
	require.True(t, result.Trusted)
	require.Equal(t, "within_validity", result.Freshness)
	require.Equal(t, "unknown", result.CurrentOwnership)

	output, _, err = invokeCLI(t, cliNow.Add(time.Minute), "verify-erc8004", "--binding", path,
		"--issuer", issuer, "--key-id", "sha256:"+strings.Repeat("0", 64), "--require-trusted")
	var untrusted *exitError
	require.True(t, errors.As(err, &untrusted))
	require.Equal(t, 3, untrusted.code)
	require.Contains(t, output, `"issuer_trust": "unknown"`)
}

func TestVerifyERC8004MalformedAndHistoricalExpiry(t *testing.T) {
	dir := t.TempDir()
	malformedPath := filepath.Join(dir, "malformed.json")
	require.NoError(t, os.WriteFile(malformedPath, []byte("{"), 0o644))
	output, _, err := invokeCLI(t, cliNow, "verify-erc8004", "--binding", malformedPath)
	require.Error(t, err)
	require.Contains(t, output, `"valid": false`)

	document, issuer, signer := testERC8004BindingForCLI(t, cliNow.Add(-2*time.Hour))
	expiredPath := filepath.Join(dir, "expired.json")
	raw, marshalErr := json.Marshal(document)
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(expiredPath, raw, 0o644))
	output, _, err = invokeCLI(t, cliNow, "verify-erc8004", "--binding", expiredPath,
		"--issuer", issuer, "--key-id", signer.KeyID())
	require.NoError(t, err)
	var result erc8004VerificationOutput
	require.NoError(t, json.Unmarshal([]byte(output), &result))
	require.True(t, result.Valid)
	require.False(t, result.Trusted)
	require.Equal(t, "expired", result.Freshness)
	require.Equal(t, "unknown", result.CurrentOwnership)

	_, _, err = invokeCLI(t, cliNow, "verify-erc8004", "--binding", expiredPath,
		"--issuer", issuer, "--key-id", signer.KeyID(), "--require-trusted")
	var strict *exitError
	require.True(t, errors.As(err, &strict))
	require.Equal(t, 3, strict.code)
}

func TestWrongAgentKeyAndTamperedKeyMetadataAreRejected(t *testing.T) {
	dir := t.TempDir()
	adminPath := generateTestKey(t, dir, "admin", "admin")
	agentPath := generateTestKey(t, dir, "agent", "agent")
	wrongPath := generateTestKey(t, dir, "wrong", "agent")
	registrationPath := filepath.Join(dir, "registration.json")
	artifactPath := filepath.Join(dir, "artifact.txt")
	require.NoError(t, os.WriteFile(artifactPath, []byte("artifact"), 0o644))
	_, _, err := invokeCLI(t, cliNow,
		"delegate", "--admin-key", adminPath, "--agent-key", agentPath,
		"--agent-id", "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"--audience", "https://issuer.example/apostille", "--out", registrationPath)
	require.NoError(t, err)
	_, _, err = invokeCLI(t, cliNow,
		"sign", "--key", wrongPath, "--file", artifactPath,
		"--registration", registrationPath, "--out", filepath.Join(dir, "wrong.json"))
	require.ErrorContains(t, err, "does not match registration")

	raw, err := os.ReadFile(agentPath)
	require.NoError(t, err)
	var stored keyFile
	require.NoError(t, json.Unmarshal(raw, &stored))
	stored.PublicKey = strings.Repeat("A", len(stored.PublicKey))
	tamperedPath := filepath.Join(dir, "tampered.json")
	tampered, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(tamperedPath, tampered, 0o600))
	_, _, err = invokeCLI(t, cliNow,
		"sign", "--key", tamperedPath, "--file", artifactPath,
		"--registration", registrationPath, "--out", filepath.Join(dir, "tampered-statement.json"))
	require.ErrorContains(t, err, "metadata does not match")
}
