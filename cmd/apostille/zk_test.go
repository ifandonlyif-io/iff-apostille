package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/stretchr/testify/require"
)

type zkCircuitOutput struct {
	Profile       string `json:"profile"`
	CircuitID     string `json:"circuit_id"`
	Scheme        string `json:"scheme"`
	CircuitSHA256 string `json:"circuit_sha256"`
	Constraints   int    `json:"constraints"`
	PublicInputs  int    `json:"public_inputs"`
}

func TestZKSetupRequiresDevelopment(t *testing.T) {
	dir := t.TempDir()
	setupDir := filepath.Join(dir, "setup")
	_, _, err := invokeCLI(t, cliNow, "zk-setup", "--out-dir", setupDir)
	require.ErrorContains(t, err, "requires --development")
	_, err = os.Stat(setupDir)
	require.True(t, os.IsNotExist(err))
}

func TestZKSnapshotWithRegistrationUsesDelegatedSigner(t *testing.T) {
	dir := t.TempDir()
	adminPath := generateTestKey(t, dir, "budget-admin", "administrator")
	agentPath := generateTestKey(t, dir, "budget-agent", "agent")
	registrationPath := filepath.Join(dir, "registration.json")
	_, _, err := invokeCLI(t, cliNow,
		"delegate", "--admin-key", adminPath, "--agent-key", agentPath,
		"--agent-id", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		"--audience", "https://issuer.example/apostille", "--out", registrationPath)
	require.NoError(t, err)
	amountsPath := filepath.Join(dir, "amounts.json")
	require.NoError(t, os.WriteFile(amountsPath, []byte(`{"amounts":["125"]}`), 0o600))
	snapshotDir := filepath.Join(dir, "delegated-snapshot")
	_, _, err = invokeCLI(t, cliNow,
		"zk-snapshot", "--amounts", amountsPath, "--key", agentPath,
		"--registration", registrationPath, "--scope", "department-budget", "--currency", "USD",
		"--period-start", "2025-06-15T15:06:40Z", "--period-end", "2025-06-15T16:06:40Z", "--out-dir", snapshotDir)
	require.NoError(t, err)

	sourceBefore, err := os.ReadFile(filepath.Join(snapshotDir, "source-bundle.json"))
	require.NoError(t, err)
	var source core.Bundle
	require.NoError(t, core.StrictJSON(sourceBefore, &source))
	require.NotNil(t, source.Delegation)
	require.NotNil(t, source.Acceptance)
	_, err = core.VerifyBundle(source, core.VerifyOptions{Now: cliNow})
	require.NoError(t, err)

	_, _, err = invokeCLI(t, cliNow,
		"zk-snapshot", "--amounts", amountsPath, "--key", agentPath,
		"--registration", registrationPath, "--scope", "department-budget", "--currency", "USD",
		"--period-start", "2025-06-15T15:06:40Z", "--period-end", "2025-06-15T16:06:40Z", "--out-dir", snapshotDir)
	require.Error(t, err)
	sourceAfter, err := os.ReadFile(filepath.Join(snapshotDir, "source-bundle.json"))
	require.NoError(t, err)
	require.Equal(t, sourceBefore, sourceAfter)

	_, _, err = invokeCLI(t, cliNow,
		"zk-snapshot", "--amounts", amountsPath, "--key", agentPath,
		"--registration", registrationPath, "--scope", "department-budget", "--currency", "USD",
		"--period-start", "1750000000", "--period-end", "2025-06-15T16:06:40Z", "--out-dir", filepath.Join(dir, "bad-period"))
	require.ErrorContains(t, err, "period start")
}

func TestZKCLIFullLocalPipelineAndPrivateInputProtection(t *testing.T) {
	dir := t.TempDir()
	circuitOutput, _, err := invokeCLI(t, cliNow, "zk-circuit")
	require.NoError(t, err)
	var circuit zkCircuitOutput
	require.NoError(t, json.Unmarshal([]byte(circuitOutput), &circuit))
	require.NotEmpty(t, circuit.Profile)
	require.NotEmpty(t, circuit.CircuitID)
	require.NotEmpty(t, circuit.Scheme)
	require.Equal(t, 9867, circuit.Constraints)
	require.Equal(t, 9, circuit.PublicInputs)

	setupDir := filepath.Join(dir, "setup")
	setupOutput, _, err := invokeCLI(t, cliNow, "zk-setup", "--development", "--out-dir", setupDir)
	require.NoError(t, err)
	require.NotContains(t, setupOutput, "proving_key")
	require.NotContains(t, setupOutput, "verifying_key.bin")
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(setupDir)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
		for _, name := range []string{"proving-key.bin", "verifying-key.bin", "parameters.json"} {
			info, statErr = os.Stat(filepath.Join(setupDir, name))
			require.NoError(t, statErr)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}
	}
	var parameters zkParametersFile
	parametersRaw, err := os.ReadFile(filepath.Join(setupDir, "parameters.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(parametersRaw, &parameters))
	require.NotEmpty(t, parameters.VerifyingKeySHA256)
	require.Equal(t, parameters.CircuitSHA256, circuit.CircuitSHA256)

	keyPath := generateTestKey(t, dir, "budget-agent", "budget-agent")
	amountsPath := filepath.Join(dir, "amounts.json")
	const amountsJSON = `{"amounts":["125","200"]}`
	require.NoError(t, os.WriteFile(amountsPath, []byte(amountsJSON), 0o600))
	snapshotDir := filepath.Join(dir, "snapshot")
	snapshotOutput, _, err := invokeCLI(t, cliNow,
		"zk-snapshot", "--amounts", amountsPath, "--key", keyPath,
		"--agent-id", "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		"--scope", "cross-department-budget", "--currency", "USD",
		"--period-start", "2025-06-15T15:06:40Z", "--period-end", "2025-06-15T16:06:40Z", "--out-dir", snapshotDir)
	require.NoError(t, err)
	require.NotContains(t, snapshotOutput, "amounts")
	require.NotContains(t, snapshotOutput, "blinding")
	if runtime.GOOS != "windows" {
		for _, name := range []string{"snapshot.json", "private.json", "source-bundle.json"} {
			info, statErr := os.Stat(filepath.Join(snapshotDir, name))
			require.NoError(t, statErr)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}
	}

	requestPath := filepath.Join(dir, "request.json")
	_, _, err = invokeCLI(t, cliNow,
		"zk-request", "--snapshot", filepath.Join(snapshotDir, "snapshot.json"),
		"--policy-id", "department-cap", "--audience", "https://verifier.example/zk",
		"--limit", "500", "--out", requestPath)
	require.NoError(t, err)
	requestBefore, err := os.ReadFile(requestPath)
	require.NoError(t, err)
	_, _, err = invokeCLI(t, cliNow,
		"zk-request", "--snapshot", filepath.Join(snapshotDir, "snapshot.json"),
		"--policy-id", "department-cap", "--audience", "https://verifier.example/zk",
		"--limit", "500", "--out", requestPath)
	require.Error(t, err)
	requestAfter, err := os.ReadFile(requestPath)
	require.NoError(t, err)
	require.Equal(t, requestBefore, requestAfter)

	proofPath := filepath.Join(dir, "proof.json")
	_, _, err = invokeCLI(t, cliNow,
		"zk-prove", "--private", filepath.Join(snapshotDir, "private.json"),
		"--source-bundle", filepath.Join(snapshotDir, "source-bundle.json"),
		"--request", requestPath,
		"--proving-key", filepath.Join(setupDir, "proving-key.bin"),
		"--verifying-key", filepath.Join(setupDir, "verifying-key.bin"),
		"--vk-sha256", parameters.VerifyingKeySHA256, "--out", proofPath)
	require.NoError(t, err)

	signer, _, err := readSigner(keyPath)
	require.NoError(t, err)
	verifyOutput, _, err := invokeCLI(t, cliNow,
		"zk-verify", "--offline", "--proof", proofPath, "--request", requestPath,
		"--verifying-key", filepath.Join(setupDir, "verifying-key.bin"),
		"--vk-sha256", parameters.VerifyingKeySHA256, "--source-key-id", signer.KeyID())
	require.NoError(t, err)
	require.NotContains(t, verifyOutput, "blinding")
	var verification map[string]any
	require.NoError(t, json.Unmarshal([]byte(verifyOutput), &verification))
	require.Equal(t, true, verification["valid"])
	require.Equal(t, cliNow.UTC().Truncate(time.Second).Format(time.RFC3339Nano), verification["evaluated_at"])
	// Historical --at must drive both verification and its recorded time, even
	// if the process clock is now well beyond the receiver request's expiry.
	historical := cliNow.Add(time.Minute).In(time.FixedZone("receiver", 8*60*60))
	verifyOutput, _, err = invokeCLI(t, cliNow.Add(24*time.Hour),
		"zk-verify", "--offline", "--proof", proofPath, "--request", requestPath,
		"--verifying-key", filepath.Join(setupDir, "verifying-key.bin"),
		"--vk-sha256", parameters.VerifyingKeySHA256, "--source-key-id", signer.KeyID(),
		"--at", historical.Add(1234*time.Nanosecond).Format(time.RFC3339Nano))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(verifyOutput), &verification))
	require.Equal(t, true, verification["valid"])
	require.Equal(t, historical.UTC().Truncate(time.Second).Format(time.RFC3339Nano), verification["evaluated_at"])
	otherKeyPath := generateTestKey(t, dir, "other-budget-agent", "budget-agent")
	otherSigner, _, err := readSigner(otherKeyPath)
	require.NoError(t, err)
	failure, _, err := invokeCLI(t, cliNow,
		"zk-verify", "--offline", "--proof", proofPath, "--request", requestPath,
		"--verifying-key", filepath.Join(setupDir, "verifying-key.bin"),
		"--vk-sha256", parameters.VerifyingKeySHA256, "--source-key-id", otherSigner.KeyID())
	require.Error(t, err)
	requireZKVerificationFailure(t, failure, cliNow.UTC().Truncate(time.Second))

	wrongRequestPath := filepath.Join(dir, "wrong-request.json")
	_, _, err = invokeCLI(t, cliNow,
		"zk-request", "--snapshot", filepath.Join(snapshotDir, "snapshot.json"),
		"--policy-id", "other-policy", "--audience", "https://verifier.example/zk",
		"--limit", "500", "--out", wrongRequestPath)
	require.NoError(t, err)
	evaluation := cliNow.UTC().Truncate(time.Second).Add(time.Minute)
	failure, _, err = invokeCLI(t, cliNow,
		"zk-verify", "--offline", "--proof", proofPath, "--request", wrongRequestPath,
		"--verifying-key", filepath.Join(setupDir, "verifying-key.bin"),
		"--vk-sha256", parameters.VerifyingKeySHA256, "--source-key-id", signer.KeyID(),
		"--at", evaluation.Format(time.RFC3339))
	require.Error(t, err)
	requireZKVerificationFailure(t, failure, evaluation)

	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(filepath.Join(snapshotDir, "private.json"), 0o644))
		_, _, err = invokeCLI(t, cliNow,
			"zk-prove", "--private", filepath.Join(snapshotDir, "private.json"),
			"--source-bundle", filepath.Join(snapshotDir, "source-bundle.json"),
			"--request", requestPath,
			"--proving-key", filepath.Join(setupDir, "proving-key.bin"),
			"--verifying-key", filepath.Join(setupDir, "verifying-key.bin"),
			"--vk-sha256", parameters.VerifyingKeySHA256, "--out", filepath.Join(dir, "should-not-exist.json"))
		require.ErrorContains(t, err, "private snapshot")
	}
}

func requireZKVerificationFailure(t *testing.T, output string, evaluatedAt time.Time) {
	t.Helper()
	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &result))
	require.Equal(t, false, result["valid"])
	require.Equal(t, "verification_failed", result["error"])
	require.Equal(t, evaluatedAt.UTC().Format(time.RFC3339Nano), result["evaluated_at"])
}
