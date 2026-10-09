package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/ifandonlyif-io/iff-apostille/apostille/zkbudget"
	"github.com/stretchr/testify/require"
)

const (
	flowAudience = "https://issuer.example/apostille"
	flowAgentID  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

type flowFiles struct {
	admin, agent, issuer                          string
	registration, statement, grant, bundle, input string
}

func generateKeyWith(t *testing.T, dir, name, algorithm string) string {
	t.Helper()
	path := filepath.Join(dir, name+".json")
	stdout, _, err := invokeCLI(t, cliNow, "keygen", "--out", path, "--role", name, "--algorithm", algorithm)
	require.NoError(t, err)
	require.NotContains(t, stdout, "seed")
	return path
}

func algorithmForProtocol(selector string) string {
	if protocol, err := parseProtocol(selector); err == nil && protocol == core.Protocol03 {
		return "ml-dsa-65"
	}
	return "ed25519"
}

// runFlow runs delegate, sign, grant and issue for one protocol selector and
// returns the files it wrote.
func runFlow(t *testing.T, protocol string) flowFiles {
	t.Helper()
	dir := t.TempDir()
	algorithm := algorithmForProtocol(protocol)
	f := flowFiles{
		admin:        generateKeyWith(t, dir, "admin", algorithm),
		agent:        generateKeyWith(t, dir, "agent", algorithm),
		issuer:       generateKeyWith(t, dir, "issuer", algorithm),
		registration: filepath.Join(dir, "registration.json"),
		statement:    filepath.Join(dir, "statement.json"),
		grant:        filepath.Join(dir, "grant.json"),
		bundle:       filepath.Join(dir, "bundle.json"),
		input:        filepath.Join(dir, "artifact.txt"),
	}
	require.NoError(t, os.WriteFile(f.input, []byte("versioned artifact\n"), 0o644))
	for _, step := range [][]string{
		{"delegate", "--admin-key", f.admin, "--agent-key", f.agent, "--agent-id", flowAgentID,
			"--audience", flowAudience, "--out", f.registration, "--protocol", protocol},
		{"sign", "--key", f.agent, "--file", f.input, "--registration", f.registration,
			"--out", f.statement, "--protocol", protocol},
		{"grant", "--admin-key", f.admin, "--statement", f.statement, "--registration", f.registration,
			"--audience", flowAudience, "--visibility", "private", "--out", f.grant, "--protocol", protocol},
		{"issue", "--key", f.issuer, "--issuer", flowAudience, "--statement", f.statement,
			"--registration", f.registration, "--out", f.bundle, "--protocol", protocol},
	} {
		_, _, err := invokeCLI(t, cliNow, step...)
		require.NoError(t, err, step[0])
	}
	return f
}

func TestKeygenAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		protocol  string
		algorithm string
	}{
		{"default", nil, core.Protocol, core.Algorithm},
		{"ed25519", []string{"--algorithm", "ed25519"}, core.Protocol, core.Algorithm},
		{"ml-dsa-65", []string{"--algorithm", "ml-dsa-65"}, core.Protocol03, core.Algorithm03},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.json")
			stdout, _, err := invokeCLI(t, cliNow, append([]string{"keygen", "--out", path, "--role", "r"}, tc.args...)...)
			require.NoError(t, err)
			if runtime.GOOS != "windows" {
				info, statErr := os.Stat(path)
				require.NoError(t, statErr)
				require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
			}
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			signer, stored, err := core.ParseKeyFile(raw)
			require.NoError(t, err)
			require.Equal(t, tc.protocol, stored.Protocol)
			require.Equal(t, tc.algorithm, signer.Algorithm())
			require.Equal(t, "r", stored.Role)
			require.NotContains(t, stdout, stored.Seed)
			require.NotContains(t, stdout, "seed")
			var printed struct {
				KeyID     string `json:"key_id"`
				PublicKey string `json:"public_key"`
				Role      string `json:"role"`
			}
			require.NoError(t, json.Unmarshal([]byte(stdout), &printed))
			require.Equal(t, signer.KeyID(), printed.KeyID)
			require.Equal(t, signer.PublicKey(), printed.PublicKey)

			_, _, err = invokeCLI(t, cliNow, append([]string{"keygen", "--out", path}, tc.args...)...)
			require.Error(t, err)
			after, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			require.Equal(t, raw, after)
		})
	}
	_, _, err := invokeCLI(t, cliNow, "keygen", "--out", filepath.Join(t.TempDir(), "k.json"), "--algorithm", "rsa")
	require.ErrorContains(t, err, "algorithm must be ed25519 or ml-dsa-65")
}

func TestFlowsAtEveryProtocol(t *testing.T) {
	for _, tc := range []struct {
		selector string
		protocol string
	}{
		{"0.1", core.Protocol},
		{"0.2", core.Protocol02},
		{"0.3", core.Protocol03},
		{core.Protocol03, core.Protocol03},
	} {
		t.Run(tc.selector, func(t *testing.T) {
			f := runFlow(t, tc.selector)
			issuerSigner, _, err := readSigner(f.issuer)
			require.NoError(t, err)
			registration, err := readRegistration(f.registration)
			require.NoError(t, err)
			statement, err := readEnvelope(f.statement)
			require.NoError(t, err)
			grant, err := readEnvelope(f.grant)
			require.NoError(t, err)
			adminSigner, _, err := readSigner(f.admin)
			require.NoError(t, err)
			for _, envelope := range []core.Envelope{registration.Delegation, registration.Acceptance, statement, grant} {
				require.Equal(t, tc.protocol, envelope.Protocol)
				require.Equal(t, algorithmFor(tc.protocol), envelope.Signature.Algorithm)
			}
			_, err = core.ValidateGrant(grant, statement, registration.Delegation, adminSigner.KeyID(),
				flowAudience, cliNow.UTC().Truncate(time.Second).Add(time.Minute))
			require.NoError(t, err)

			at := cliNow.Add(time.Minute).Format(time.RFC3339)
			output, _, err := invokeCLI(t, cliNow.Add(time.Minute),
				"verify", "--offline", "--bundle", f.bundle, "--issuer", flowAudience,
				"--key-id", issuerSigner.KeyID(), "--at", at, "--artifact", f.input, "--require-trusted")
			require.NoError(t, err)
			var result verificationOutput
			require.NoError(t, json.Unmarshal([]byte(output), &result))
			require.True(t, result.Valid)
			require.True(t, result.Trusted)
			require.Equal(t, tc.protocol, result.Protocol)
			require.Contains(t, output, `"protocol": "`+tc.protocol+`"`)
			require.Equal(t, "valid", result.ArtifactIntegrity)

			// An explicit accept list naming the bundle's version still verifies.
			_, _, err = invokeCLI(t, cliNow.Add(time.Minute), "verify", "--offline", "--bundle", f.bundle,
				"--at", at, "--accept-protocol", tc.selector, "--accept-protocol", "0.2")
			require.NoError(t, err)

			// Omitting --protocol on issue follows the statement; a conflicting one is refused.
			other := "0.1"
			if tc.protocol == core.Protocol {
				other = "0.3"
			}
			_, _, err = invokeCLI(t, cliNow, "issue", "--key", f.issuer, "--issuer", flowAudience,
				"--statement", f.statement, "--registration", f.registration,
				"--out", filepath.Join(filepath.Dir(f.bundle), "other.json"), "--protocol", other)
			require.ErrorContains(t, err, "versions must not mix")
		})
	}
}

func TestIssueFollowsStatementProtocolWithoutFlag(t *testing.T) {
	f := runFlow(t, "0.3")
	out := filepath.Join(filepath.Dir(f.bundle), "implicit.json")
	_, _, err := invokeCLI(t, cliNow, "issue", "--key", f.issuer, "--issuer", flowAudience,
		"--statement", f.statement, "--registration", f.registration, "--out", out)
	require.NoError(t, err)
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var bundle core.Bundle
	require.NoError(t, core.StrictJSON(raw, &bundle))
	require.Equal(t, core.Protocol03, bundle.Protocol)
	require.Equal(t, core.Protocol03, bundle.Certificate.Protocol)
}

func TestDefaultProtocolIsCore01(t *testing.T) {
	dir := t.TempDir()
	adminPath := generateTestKey(t, dir, "admin", "administrator")
	agentPath := generateTestKey(t, dir, "agent", "agent")
	registrationPath := filepath.Join(dir, "registration.json")
	_, _, err := invokeCLI(t, cliNow, "delegate", "--admin-key", adminPath, "--agent-key", agentPath,
		"--audience", flowAudience, "--out", registrationPath)
	require.NoError(t, err)
	registration, err := readRegistration(registrationPath)
	require.NoError(t, err)
	require.Equal(t, core.Protocol, registration.Delegation.Protocol)
}

func TestAcceptProtocolNarrowing(t *testing.T) {
	f01 := runFlow(t, "0.1")
	f03 := runFlow(t, "0.3")
	at := cliNow.Add(time.Minute).Format(time.RFC3339)

	output, _, err := invokeCLI(t, cliNow, "verify", "--offline", "--bundle", f01.bundle, "--at", at, "--accept-protocol", "0.3")
	require.ErrorContains(t, err, "not accepted by the receiver's policy")
	require.Contains(t, output, `"valid": false`)
	_, _, err = invokeCLI(t, cliNow, "verify", "--offline", "--bundle", f03.bundle, "--at", at, "--accept-protocol", "0.1", "--accept-protocol", "0.2")
	require.ErrorContains(t, err, "not accepted by the receiver's policy")
	_, _, err = invokeCLI(t, cliNow, "verify", "--offline", "--bundle", f01.bundle, "--at", at, "--accept-protocol", "0.1")
	require.NoError(t, err)
	_, _, err = invokeCLI(t, cliNow, "verify", "--offline", "--bundle", f03.bundle, "--at", at, "--accept-protocol", core.Protocol03)
	require.NoError(t, err)

	_, _, err = invokeCLI(t, cliNow, "verify", "--offline", "--bundle", f01.bundle, "--accept-protocol", "0.9")
	require.ErrorContains(t, err, "unsupported protocol")
}

func TestAlgorithmProtocolMismatchIsRefusedBeforeSigning(t *testing.T) {
	dir := t.TempDir()
	edAdmin := generateKeyWith(t, dir, "ed-admin", "ed25519")
	edAgent := generateKeyWith(t, dir, "ed-agent", "ed25519")
	mlAdmin := generateKeyWith(t, dir, "ml-admin", "ml-dsa-65")
	mlAgent := generateKeyWith(t, dir, "ml-agent", "ml-dsa-65")
	artifact := filepath.Join(dir, "artifact.txt")
	require.NoError(t, os.WriteFile(artifact, []byte("x"), 0o644))
	f01 := runFlow(t, "0.1")
	f03 := runFlow(t, "0.3")
	out := func(name string) string { return filepath.Join(dir, name) }

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"delegate 0.3 with Ed25519 admin", []string{"delegate", "--admin-key", edAdmin, "--agent-key", mlAgent, "--audience", flowAudience, "--out", out("a"), "--protocol", "0.3"}, "admin key: Core 0.3 needs an ML-DSA-65 key file, but the key file is Ed25519"},
		{"delegate 0.3 with Ed25519 agent", []string{"delegate", "--admin-key", mlAdmin, "--agent-key", edAgent, "--audience", flowAudience, "--out", out("b"), "--protocol", "0.3"}, "agent key: Core 0.3 needs an ML-DSA-65 key file"},
		{"delegate 0.1 with ML-DSA admin", []string{"delegate", "--admin-key", mlAdmin, "--agent-key", edAgent, "--audience", flowAudience, "--out", out("c")}, "admin key: Core 0.1 needs an Ed25519 key file, but the key file is ML-DSA-65"},
		{"delegate 0.2 with ML-DSA agent", []string{"delegate", "--admin-key", edAdmin, "--agent-key", mlAgent, "--audience", flowAudience, "--out", out("d"), "--protocol", "0.2"}, "agent key: Core 0.2 needs an Ed25519 key file"},
		{"sign 0.3 with Ed25519 key", []string{"sign", "--key", edAgent, "--file", artifact, "--agent-id", flowAgentID, "--out", out("e"), "--protocol", "0.3"}, "Core 0.3 needs an ML-DSA-65 key file"},
		{"sign 0.2 with ML-DSA key", []string{"sign", "--key", mlAgent, "--file", artifact, "--agent-id", flowAgentID, "--out", out("f"), "--protocol", "0.2"}, "Core 0.2 needs an Ed25519 key file"},
		{"grant 0.3 with Ed25519 key", []string{"grant", "--admin-key", edAdmin, "--statement", f03.statement, "--registration", f03.registration, "--audience", flowAudience, "--visibility", "private", "--out", out("g"), "--protocol", "0.3"}, "admin key: Core 0.3 needs an ML-DSA-65 key file"},
		{"grant 0.1 with ML-DSA key", []string{"grant", "--admin-key", mlAdmin, "--statement", f01.statement, "--registration", f01.registration, "--audience", flowAudience, "--visibility", "private", "--out", out("h")}, "admin key: Core 0.1 needs an Ed25519 key file"},
		{"issue 0.3 statement with Ed25519 issuer", []string{"issue", "--key", f01.issuer, "--issuer", flowAudience, "--statement", f03.statement, "--registration", f03.registration, "--out", out("i")}, "issuer key: Core 0.3 needs an ML-DSA-65 key file, but the key file is Ed25519"},
		{"issue 0.1 statement with ML-DSA issuer", []string{"issue", "--key", f03.issuer, "--issuer", flowAudience, "--statement", f01.statement, "--registration", f01.registration, "--out", out("j")}, "issuer key: Core 0.1 needs an Ed25519 key file, but the key file is ML-DSA-65"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := invokeCLI(t, cliNow, tc.args...)
			require.ErrorContains(t, err, tc.want)
			for i, arg := range tc.args {
				if arg == "--out" {
					_, statErr := os.Stat(tc.args[i+1])
					require.True(t, os.IsNotExist(statErr), "no output file on refusal")
				}
			}
		})
	}
}

func TestVersionsMustNotMix(t *testing.T) {
	dir := t.TempDir()
	f02 := runFlow(t, "0.2")
	f03 := runFlow(t, "0.3")
	artifact := filepath.Join(dir, "artifact.txt")
	require.NoError(t, os.WriteFile(artifact, []byte("x"), 0o644))

	// Default 0.1 signing against a 0.2 registration, and 0.3 against a 0.2 one.
	_, _, err := invokeCLI(t, cliNow, "sign", "--key", f02.agent, "--file", artifact,
		"--registration", f02.registration, "--out", filepath.Join(dir, "s1.json"))
	require.ErrorContains(t, err, "registration is Core 0.2 but the command selects Core 0.1; versions must not mix")
	_, _, err = invokeCLI(t, cliNow, "sign", "--key", f03.agent, "--file", artifact,
		"--registration", f02.registration, "--out", filepath.Join(dir, "s2.json"), "--protocol", "0.3")
	require.ErrorContains(t, err, "registration is Core 0.2 but the command selects Core 0.3")

	// A 0.3 grant over a 0.2 statement, and a 0.2 grant over a 0.3 registration.
	_, _, err = invokeCLI(t, cliNow, "grant", "--admin-key", f03.admin, "--statement", f02.statement,
		"--registration", f03.registration, "--audience", flowAudience, "--visibility", "private",
		"--out", filepath.Join(dir, "g1.json"), "--protocol", "0.3")
	require.ErrorContains(t, err, "statement is Core 0.2 but the command selects Core 0.3; versions must not mix")
	_, _, err = invokeCLI(t, cliNow, "grant", "--admin-key", f02.admin, "--statement", f02.statement,
		"--registration", f03.registration, "--audience", flowAudience, "--visibility", "private",
		"--out", filepath.Join(dir, "g2.json"), "--protocol", "0.2")
	require.ErrorContains(t, err, "registration is Core 0.3 but the command selects Core 0.2")

	// A 0.3 statement bound to a 0.2 registration cannot be issued.
	_, _, err = invokeCLI(t, cliNow, "issue", "--key", f03.issuer, "--issuer", flowAudience,
		"--statement", f03.statement, "--registration", f02.registration, "--out", filepath.Join(dir, "i1.json"))
	require.ErrorContains(t, err, "local issuance")
}

func TestPublishedCore03BundleVerifiesWithPins(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "apostille", "core-0.3.json"))
	require.NoError(t, err)
	var fixture struct {
		Protocol       string          `json:"protocol"`
		EvaluationTime string          `json:"evaluation_time"`
		Issuer         string          `json:"issuer"`
		IssuerKeyID    string          `json:"issuer_key_id"`
		Artifact       string          `json:"artifact"`
		Bundle         json.RawMessage `json:"bundle"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	artifactPath := filepath.Join(dir, "artifact.txt")
	require.NoError(t, os.WriteFile(bundlePath, fixture.Bundle, 0o644))
	require.NoError(t, os.WriteFile(artifactPath, []byte(fixture.Artifact), 0o644))

	output, _, err := invokeCLI(t, cliNow, "verify", "--offline", "--bundle", bundlePath,
		"--issuer", fixture.Issuer, "--key-id", fixture.IssuerKeyID, "--at", fixture.EvaluationTime,
		"--artifact", artifactPath, "--require-trusted", "--accept-protocol", "0.3")
	require.NoError(t, err)
	var result verificationOutput
	require.NoError(t, json.Unmarshal([]byte(output), &result))
	require.Equal(t, fixture.Protocol, result.Protocol)
	require.True(t, result.Trusted)
	require.NotNil(t, result.ArtifactMatches)
	require.True(t, *result.ArtifactMatches)

	_, _, err = invokeCLI(t, cliNow, "verify", "--offline", "--bundle", bundlePath,
		"--at", fixture.EvaluationTime, "--accept-protocol", "0.1", "--accept-protocol", "0.2")
	require.ErrorContains(t, err, "not accepted")
}

func TestLegacyExpandedAndWrongFormKeyFilesAreRefused(t *testing.T) {
	dir := t.TempDir()
	path := generateKeyWith(t, dir, "key", "ed25519")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var stored core.KeyFile
	require.NoError(t, json.Unmarshal(raw, &stored))
	seed, err := base64.RawURLEncoding.DecodeString(stored.Seed)
	require.NoError(t, err)

	for name, badSeed := range map[string]string{
		"64-byte expanded": base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed)),
		"standard alphabet": strings.NewReplacer("-", "+", "_", "/").Replace(
			base64.StdEncoding.EncodeToString(seed)),
	} {
		t.Run(name, func(t *testing.T) {
			bad := stored
			bad.Seed = badSeed
			encoded, err := json.Marshal(bad)
			require.NoError(t, err)
			badPath := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
			require.NoError(t, os.WriteFile(badPath, encoded, 0o600))
			_, _, err = invokeCLI(t, cliNow, "sign", "--key", badPath, "--file", path,
				"--agent-id", flowAgentID, "--out", filepath.Join(dir, "never.json"))
			require.ErrorContains(t, err, "parse private key: Ed25519 seed must be 43 canonical base64url characters")
		})
	}
}

func TestCore01OnlyProfilesRefuseNewerCore(t *testing.T) {
	dir := t.TempDir()
	const wantSuffix = "profile covers Core 0.1 only"

	// ERC-8004: a binding document that carries a Core 0.2 or 0.3 registration.
	document, issuer, _ := testERC8004BindingForCLI(t, cliNow)
	for _, protocol := range []string{core.Protocol02, core.Protocol03} {
		algorithm := "ed25519"
		if protocol == core.Protocol03 {
			algorithm = "ml-dsa-65"
		}
		adminPath := generateKeyWith(t, dir, "e-admin-"+algorithm, algorithm)
		agentPath := generateKeyWith(t, dir, "e-agent-"+algorithm, algorithm)
		admin, _, err := readSigner(adminPath)
		require.NoError(t, err)
		agent, _, err := readSigner(agentPath)
		require.NoError(t, err)
		registration, err := core.CreateRegistrationFor(protocol, admin, agent, issuer, time.Hour, cliNow.UTC())
		require.NoError(t, err)
		mixed := document
		mixed.Delegation, mixed.Acceptance = registration.Delegation, registration.Acceptance
		raw, err := json.Marshal(mixed)
		require.NoError(t, err)
		bindingPath := filepath.Join(dir, "binding-"+algorithm+".json")
		require.NoError(t, os.WriteFile(bindingPath, raw, 0o644))
		output, _, err := invokeCLI(t, cliNow, "verify-erc8004", "--binding", bindingPath)
		require.ErrorContains(t, err, "binding delegation is Core "+protocol[len(protocol)-3:]+": the ERC-8004 binding "+wantSuffix)
		require.Empty(t, output)
	}

	// ZK: a Core 0.3 key, a Core 0.2 registration, and Core 0.3 source bundles.
	mlKey := generateKeyWith(t, dir, "z-ml", "ml-dsa-65")
	edAdmin := generateKeyWith(t, dir, "z-admin", "ed25519")
	edAgent := generateKeyWith(t, dir, "z-agent", "ed25519")
	amounts := filepath.Join(dir, "amounts.json")
	require.NoError(t, os.WriteFile(amounts, []byte(`{"amounts":["1"]}`), 0o600))
	snapshotArgs := func(key, outDir string, extra ...string) []string {
		return append([]string{"zk-snapshot", "--amounts", amounts, "--key", key, "--scope", "s", "--currency", "USD",
			"--period-start", "2025-06-15T15:06:40Z", "--period-end", "2025-06-15T16:06:40Z", "--out-dir", outDir}, extra...)
	}
	_, _, err := invokeCLI(t, cliNow, snapshotArgs(mlKey, filepath.Join(dir, "z1"), "--agent-id", flowAgentID)...)
	require.ErrorContains(t, err, "signer key is ML-DSA-65: the ZK budget "+wantSuffix)
	_, err = os.Stat(filepath.Join(dir, "z1"))
	require.True(t, os.IsNotExist(err))

	reg02 := filepath.Join(dir, "reg02.json")
	_, _, err = invokeCLI(t, cliNow, "delegate", "--admin-key", edAdmin, "--agent-key", edAgent,
		"--audience", flowAudience, "--out", reg02, "--protocol", "0.2")
	require.NoError(t, err)
	_, _, err = invokeCLI(t, cliNow, snapshotArgs(edAgent, filepath.Join(dir, "z2"), "--registration", reg02)...)
	require.ErrorContains(t, err, "registration is Core 0.2: the ZK budget "+wantSuffix)

	fixtureRaw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "apostille", "core-0.3.json"))
	require.NoError(t, err)
	var fixture struct {
		Bundle core.Bundle `json:"bundle"`
	}
	require.NoError(t, json.Unmarshal(fixtureRaw, &fixture))
	sourcePath := filepath.Join(dir, "source03.json")
	sourceRaw, err := json.Marshal(fixture.Bundle)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sourcePath, sourceRaw, 0o600))
	privatePath := filepath.Join(dir, "private.json")
	require.NoError(t, os.WriteFile(privatePath, []byte(`{}`), 0o600))
	requestPath := filepath.Join(dir, "request.json")
	require.NoError(t, os.WriteFile(requestPath, []byte(`{}`), 0o600))
	keyBin := filepath.Join(dir, "key.bin")
	require.NoError(t, os.WriteFile(keyBin, []byte("k"), 0o600))
	_, _, err = invokeCLI(t, cliNow, "zk-prove", "--private", privatePath, "--source-bundle", sourcePath,
		"--request", requestPath, "--proving-key", keyBin, "--verifying-key", keyBin,
		"--vk-sha256", strings.Repeat("0", 64), "--out", filepath.Join(dir, "proof.json"))
	require.ErrorContains(t, err, "source bundle is Core 0.3: the ZK budget "+wantSuffix)

	proofRaw, err := json.Marshal(zkbudget.Document{SourceBundle: fixture.Bundle})
	require.NoError(t, err)
	proofPath := filepath.Join(dir, "proof03.json")
	require.NoError(t, os.WriteFile(proofPath, proofRaw, 0o644))
	_, _, err = invokeCLI(t, cliNow, "zk-verify", "--offline", "--proof", proofPath, "--request", requestPath,
		"--verifying-key", keyBin, "--vk-sha256", strings.Repeat("0", 64), "--source-key-id", "sha256:"+strings.Repeat("0", 64))
	require.ErrorContains(t, err, "proof source bundle is Core 0.3: the ZK budget "+wantSuffix)
}
