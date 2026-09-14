package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/ifandonlyif-io/iff-apostille/apostille/zkbudget"
)

const zkPrivateFileMode = 0o600

type zkAmountsInput struct {
	Amounts []string `json:"amounts"`
}

// zkParametersFile deliberately excludes proving-key bytes. The binary key
// files are local setup material; this file only records the public pins that
// an operator must carry into an independently configured verifier.
type zkParametersFile struct {
	Profile            string `json:"profile"`
	CircuitID          string `json:"circuit_id"`
	VerifyingKeySHA256 string `json:"verifying_key_sha256"`
	CircuitSHA256      string `json:"circuit_sha256"`
}

func (a application) zkSetup(ctx context.Context, args []string) error {
	flags := a.flags("zk-setup")
	development := flags.Bool("development", false, "acknowledge experimental single-party trusted setup")
	outDir := flags.String("out-dir", "", "new directory for local setup material")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireContext(ctx); err != nil {
		return err
	}
	if !*development {
		return errors.New("zk-setup requires --development for the experimental single-party trusted setup")
	}
	if err := makeNewPrivateDir(*outDir); err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(*outDir)
		}
	}()

	parameters, err := zkbudget.Setup()
	if err != nil {
		return errors.New("zk setup failed")
	}
	if len(parameters.ProvingKey) == 0 || len(parameters.ProvingKey) > zkbudget.MaxParametersBytes ||
		len(parameters.VerifyingKey) == 0 || len(parameters.VerifyingKey) > zkbudget.MaxParametersBytes {
		return errors.New("zk setup returned invalid parameter sizes")
	}
	if err := writeBytesExclusive(filepath.Join(*outDir, "proving-key.bin"), parameters.ProvingKey, zkPrivateFileMode); err != nil {
		return err
	}
	if err := writeBytesExclusive(filepath.Join(*outDir, "verifying-key.bin"), parameters.VerifyingKey, zkPrivateFileMode); err != nil {
		return err
	}
	public := zkParametersFile{
		Profile: zkbudget.Profile, CircuitID: zkbudget.CircuitID,
		VerifyingKeySHA256: parameters.VerifyingKeySHA256, CircuitSHA256: parameters.CircuitSHA256,
	}
	if err := writeJSONExclusive(filepath.Join(*outDir, "parameters.json"), public, zkPrivateFileMode); err != nil {
		return err
	}
	keep = true
	return writeJSON(a.stdout, public)
}

// zkCircuit reports the fixed circuit metadata after locally compiling the
// circuit. It does not create setup material or perform a trusted setup.
func (a application) zkCircuit(ctx context.Context, args []string) error {
	flags := a.flags("zk-circuit")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireContext(ctx); err != nil {
		return err
	}
	info, err := zkbudget.InspectCircuit()
	if err != nil {
		return errors.New("circuit inspection failed")
	}
	return writeJSON(a.stdout, info)
}

func (a application) zkSnapshot(ctx context.Context, args []string) error {
	flags := a.flags("zk-snapshot")
	amountsPath := flags.String("amounts", "", "private amount JSON file")
	keyPath := flags.String("key", "", "existing Apostille signer key")
	agentID := flags.String("agent-id", "", "producer-only agent UUID")
	registrationPath := flags.String("registration", "", "agent registration JSON file")
	scope := flags.String("scope", "", "public budget scope")
	currency := flags.String("currency", "", "three-letter public currency")
	periodStart := flags.String("period-start", "", "UTC period start in RFC3339 whole-second form")
	periodEnd := flags.String("period-end", "", "UTC period end in RFC3339 whole-second form")
	outDir := flags.String("out-dir", "", "new directory for the private snapshot and signed source")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireContext(ctx); err != nil {
		return err
	}
	if *amountsPath == "" || *keyPath == "" || *scope == "" || *currency == "" || *periodStart == "" || *periodEnd == "" || *outDir == "" {
		return errors.New("zk-snapshot requires --amounts, --key, --scope, --currency, --period-start, --period-end, and --out-dir")
	}
	if (*registrationPath == "") == (*agentID == "") {
		return errors.New("zk-snapshot requires exactly one of --registration or --agent-id")
	}
	amountsRaw, err := readPrivateInput(*amountsPath, core.MaxInputBytes)
	if err != nil {
		return errors.New("amounts input is unavailable or does not meet private-file requirements")
	}
	var amounts zkAmountsInput
	if err := core.StrictJSON(amountsRaw, &amounts); err != nil {
		return errors.New("amounts input is invalid")
	}
	signer, _, err := readSigner(*keyPath)
	if err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	var registration *core.AgentRegistration
	if *registrationPath != "" {
		value, err := readRegistration(*registrationPath)
		if err != nil {
			return err
		}
		delegation, err := core.VerifyRegistration(value, "", a.utcNow())
		if err != nil {
			return errors.New("registration is invalid")
		}
		if delegation.AgentKeyID != signer.KeyID() || delegation.AgentPublicKey != signer.PublicKey() {
			return errors.New("signer key does not match registration")
		}
		registration = &value
	} else if !core.ValidID(*agentID) {
		return errors.New("agent ID must be a canonical UUID v4")
	}
	if _, err := core.Timestamp(*periodStart); err != nil {
		return errors.New("period start must be a UTC RFC3339 whole-second timestamp")
	}
	if _, err := core.Timestamp(*periodEnd); err != nil {
		return errors.New("period end must be a UTC RFC3339 whole-second timestamp")
	}

	private, err := zkbudget.NewSnapshot(amounts.Amounts, zkbudget.SnapshotOptions{
		Scope: *scope, Currency: *currency,
		PeriodStart: *periodStart, PeriodEnd: *periodEnd,
	})
	if err != nil {
		return errors.New("snapshot inputs are invalid")
	}
	source, err := zkbudget.SignSnapshot(private.Snapshot, signer, registration, *agentID, a.utcNow())
	if err != nil {
		return errors.New("snapshot signing failed")
	}
	snapshotRaw, err := zkbudget.SnapshotBytes(private.Snapshot)
	if err != nil {
		return errors.New("snapshot encoding failed")
	}
	digest, err := zkbudget.SnapshotDigest(private.Snapshot)
	if err != nil {
		return errors.New("snapshot digest failed")
	}
	if err := makeNewPrivateDir(*outDir); err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(*outDir)
		}
	}()
	if err := writeBytesExclusive(filepath.Join(*outDir, "snapshot.json"), snapshotRaw, zkPrivateFileMode); err != nil {
		return err
	}
	if err := writeJSONExclusive(filepath.Join(*outDir, "private.json"), private, zkPrivateFileMode); err != nil {
		return err
	}
	if err := writeJSONExclusive(filepath.Join(*outDir, "source-bundle.json"), source, zkPrivateFileMode); err != nil {
		return err
	}
	keep = true
	return writeJSON(a.stdout, struct {
		SnapshotSHA256 string `json:"snapshot_sha256"`
		SourceKeyID    string `json:"source_key_id"`
	}{digest, source.Statement.Signature.KeyID})
}

func (a application) zkRequest(ctx context.Context, args []string) error {
	flags := a.flags("zk-request")
	snapshotPath := flags.String("snapshot", "", "public snapshot JSON file")
	policyID := flags.String("policy-id", "", "exact public policy identifier")
	audience := flags.String("audience", "", "exact verifier audience URI")
	limit := flags.String("limit", "", "nonnegative decimal minor-unit limit")
	out := flags.String("out", "", "new request JSON file")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireContext(ctx); err != nil {
		return err
	}
	if *snapshotPath == "" || *policyID == "" || *audience == "" || *limit == "" || *out == "" {
		return errors.New("zk-request requires --snapshot, --policy-id, --audience, --limit, and --out")
	}
	var snapshot zkbudget.Snapshot
	if err := readStrictJSON(*snapshotPath, core.MaxInputBytes, &snapshot); err != nil {
		return errors.New("snapshot input is invalid")
	}
	request, err := zkbudget.NewRequest(snapshot, *policyID, *audience, *limit, a.utcNow())
	if err != nil {
		return errors.New("request inputs are invalid")
	}
	return writeJSONExclusive(*out, request, zkPrivateFileMode)
}

func (a application) zkProve(ctx context.Context, args []string) error {
	flags := a.flags("zk-prove")
	privatePath := flags.String("private", "", "private snapshot JSON file")
	sourcePath := flags.String("source-bundle", "", "signed source bundle JSON file")
	requestPath := flags.String("request", "", "exact verifier request JSON file")
	provingKeyPath := flags.String("proving-key", "", "local proving key file")
	verifyingKeyPath := flags.String("verifying-key", "", "local verifying key file")
	vkHash := flags.String("vk-sha256", "", "externally supplied verifying-key SHA-256 pin")
	out := flags.String("out", "", "new proof JSON file")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireContext(ctx); err != nil {
		return err
	}
	if *privatePath == "" || *sourcePath == "" || *requestPath == "" || *provingKeyPath == "" || *verifyingKeyPath == "" || *vkHash == "" || *out == "" {
		return errors.New("zk-prove requires --private, --source-bundle, --request, --proving-key, --verifying-key, --vk-sha256, and --out")
	}
	var private zkbudget.PrivateSnapshot
	if err := readPrivateStrictJSON(*privatePath, core.MaxInputBytes, &private); err != nil {
		return errors.New("private snapshot is unavailable or invalid")
	}
	var source core.Bundle
	if err := readStrictJSON(*sourcePath, core.MaxInputBytes, &source); err != nil {
		return errors.New("source bundle is invalid")
	}
	var request zkbudget.Request
	if err := readStrictJSON(*requestPath, core.MaxInputBytes, &request); err != nil {
		return errors.New("request is invalid")
	}
	provingKey, err := readBoundedRegular(*provingKeyPath, zkbudget.MaxParametersBytes)
	if err != nil {
		return errors.New("proving key is unavailable or invalid")
	}
	verifyingKey, err := readBoundedRegular(*verifyingKeyPath, zkbudget.MaxParametersBytes)
	if err != nil {
		return errors.New("verifying key is unavailable or invalid")
	}
	prover, err := zkbudget.NewProver(provingKey, verifyingKey, *vkHash)
	if err != nil {
		return errors.New("prover parameters are invalid")
	}
	document, err := prover.Prove(private, source, request, a.utcNow())
	if err != nil {
		return errors.New("proof generation failed")
	}
	return writeJSONExclusive(*out, document, zkPrivateFileMode)
}

func (a application) zkVerify(ctx context.Context, args []string) error {
	flags := a.flags("zk-verify")
	offline := flags.Bool("offline", false, "confirm verification uses local files only")
	proofPath := flags.String("proof", "", "proof JSON file")
	requestPath := flags.String("request", "", "independently selected request JSON file")
	verifyingKeyPath := flags.String("verifying-key", "", "independently selected verifying key file")
	vkHash := flags.String("vk-sha256", "", "independent verifying-key SHA-256 pin")
	sourceKeyID := flags.String("source-key-id", "", "independent source signing key fingerprint")
	issuer := flags.String("issuer", "", "optional exact certificate issuer")
	issuerKeyID := flags.String("issuer-key-id", "", "optional exact certificate key fingerprint")
	at := flags.String("at", "", "evaluation time in RFC3339")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireContext(ctx); err != nil {
		return err
	}
	if !*offline || *proofPath == "" || *requestPath == "" || *verifyingKeyPath == "" || *vkHash == "" || *sourceKeyID == "" {
		return errors.New("zk-verify requires --offline, --proof, --request, --verifying-key, --vk-sha256, and --source-key-id")
	}
	if (*issuer == "") != (*issuerKeyID == "") {
		return errors.New("issuer policy requires both --issuer and --issuer-key-id")
	}
	if *issuer != "" && !core.ValidIssuer(*issuer) {
		return errors.New("issuer must be an exact HTTPS or URN issuer identifier")
	}
	now := a.utcNow()
	if *at != "" {
		parsed, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return fmt.Errorf("invalid --at RFC3339 time: %w", err)
		}
		now = parsed.UTC().Truncate(time.Second)
	}
	var request zkbudget.Request
	if err := readStrictJSON(*requestPath, core.MaxInputBytes, &request); err != nil {
		return errors.New("request is invalid")
	}
	verifyingKey, err := readBoundedRegular(*verifyingKeyPath, zkbudget.MaxParametersBytes)
	if err != nil {
		return errors.New("verifying key is unavailable or invalid")
	}
	proof, err := readBoundedRegular(*proofPath, core.MaxInputBytes)
	if err != nil {
		return errors.New("proof is unavailable or invalid")
	}
	verifier, err := zkbudget.NewVerifier(verifyingKey, *vkHash)
	if err != nil {
		return errors.New("verifier parameters are invalid")
	}
	verification, err := verifier.VerifyJSON(proof, zkbudget.VerifyOptions{
		ExpectedRequest: request, TrustedSourceKeyIDs: []string{*sourceKeyID}, Now: now,
		SourceIssuer: *issuer, SourceIssuerKeyIDs: optionalString(*issuerKeyID),
	})
	if err != nil {
		_ = writeJSON(a.stdout, struct {
			Valid       bool   `json:"valid"`
			Error       string `json:"error"`
			EvaluatedAt string `json:"evaluated_at"`
		}{false, "verification_failed", now.UTC().Format(time.RFC3339Nano)})
		return errors.New("verification failed")
	}
	return writeJSON(a.stdout, struct {
		zkbudget.Verification
		Valid bool `json:"valid"`
	}{verification, true})
}

func optionalString(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func makeNewPrivateDir(path string) error {
	if path == "" {
		return errors.New("output directory is required")
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create output directory %q: %w", path, err)
	}
	return nil
}

func writeBytesExclusive(path string, raw []byte, mode os.FileMode) error {
	if path == "" || len(raw) == 0 {
		return errors.New("output path and content are required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create output %q: %w", path, err)
	}
	written := false
	defer func() {
		_ = file.Close()
		if !written {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	written = true
	return nil
}

func readPrivateInput(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("private input path must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private input file permissions expose it to group or other users")
	}
	return readBoundedRegular(path, limit)
}

func readStrictJSON(path string, limit int64, value any) error {
	raw, err := readBoundedRegular(path, limit)
	if err != nil {
		return err
	}
	return core.StrictJSON(raw, value)
}

func readPrivateStrictJSON(path string, limit int64, value any) error {
	raw, err := readPrivateInput(path, limit)
	if err != nil {
		return err
	}
	return core.StrictJSON(raw, value)
}
