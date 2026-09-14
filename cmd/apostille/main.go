// apostille is a local-only CLI for the issuer-neutral Apostille 0.1 draft.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
)

const maxKeyFileBytes = 4 << 10

type application struct {
	stdout io.Writer
	stderr io.Writer
	now    func() time.Time
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

type keyFile struct {
	Protocol  string `json:"protocol"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Seed      string `json:"seed"`
	Role      string `json:"role,omitempty"`
}

func main() {
	app := application{stdout: os.Stdout, stderr: os.Stderr, now: time.Now}
	if err := app.run(context.Background(), os.Args[1:]); err != nil {
		code := 2
		var coded *exitError
		if errors.As(err, &coded) {
			code = coded.code
		}
		fmt.Fprintln(os.Stderr, "apostille:", err)
		os.Exit(code)
	}
}

func (a application) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("command required: keygen, delegate, sign, grant, issue, verify, verify-erc8004, zk-setup, zk-circuit, zk-snapshot, zk-request, zk-prove, or zk-verify")
	}
	switch args[0] {
	case "keygen":
		return a.keygen(ctx, args[1:])
	case "delegate":
		return a.delegate(ctx, args[1:])
	case "sign":
		return a.sign(ctx, args[1:])
	case "grant":
		return a.grant(ctx, args[1:])
	case "issue":
		return a.issue(ctx, args[1:])
	case "verify":
		return a.verify(ctx, args[1:])
	case "verify-erc8004":
		return a.verifyERC8004(ctx, args[1:])
	case "zk-setup":
		return a.zkSetup(ctx, args[1:])
	case "zk-circuit":
		return a.zkCircuit(ctx, args[1:])
	case "zk-snapshot":
		return a.zkSnapshot(ctx, args[1:])
	case "zk-request":
		return a.zkRequest(ctx, args[1:])
	case "zk-prove":
		return a.zkProve(ctx, args[1:])
	case "zk-verify":
		return a.zkVerify(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func (a application) keygen(ctx context.Context, args []string) error {
	flags := a.flags("keygen")
	out := flags.String("out", "", "new private key JSON file")
	role := flags.String("role", "", "optional local key role label")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireContext(ctx); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen requires --out")
	}
	if len(*role) > 64 || strings.TrimSpace(*role) != *role || strings.ContainsAny(*role, "\r\n\x00") {
		return errors.New("role must be a trimmed label of at most 64 characters")
	}
	seed, publicKey, err := core.GenerateKey()
	if err != nil {
		return err
	}
	signer, err := core.NewSigner(seed)
	if err != nil {
		return err
	}
	key := keyFile{
		Protocol: core.Protocol, KeyID: signer.KeyID(), PublicKey: publicKey,
		Seed: seed, Role: *role,
	}
	if err := writeJSONExclusive(*out, key, 0o600); err != nil {
		return err
	}
	return writeJSON(a.stdout, struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
		Role      string `json:"role,omitempty"`
	}{key.KeyID, key.PublicKey, key.Role})
}

func (a application) delegate(ctx context.Context, args []string) error {
	flags := a.flags("delegate")
	adminPath := flags.String("admin-key", "", "administrator private key file")
	agentPath := flags.String("agent-key", "", "agent private key file")
	agentID := flags.String("agent-id", "", "agent UUID; generated when omitted")
	audience := flags.String("audience", "", "exact service issuer URI")
	out := flags.String("out", "", "new registration JSON file")
	days30 := flags.Bool("days30", false, "make delegation valid for 30 days instead of 24 hours")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *adminPath == "" || *agentPath == "" || *audience == "" || *out == "" {
		return errors.New("delegate requires --admin-key, --agent-key, --audience, and --out")
	}
	if !core.ValidIssuer(*audience) {
		return errors.New("audience must be an exact HTTPS or URN issuer identifier")
	}
	admin, _, err := readSigner(*adminPath)
	if err != nil {
		return fmt.Errorf("admin key: %w", err)
	}
	agent, _, err := readSigner(*agentPath)
	if err != nil {
		return fmt.Errorf("agent key: %w", err)
	}
	if *agentID == "" {
		*agentID, err = core.NewID()
		if err != nil {
			return err
		}
	}
	if !core.ValidID(*agentID) {
		return errors.New("agent ID must be a canonical UUID v4")
	}
	now := a.utcNow()
	validFor := 24 * time.Hour
	if *days30 {
		validFor = 30 * 24 * time.Hour
	}
	delegation := core.Delegation{
		Header:  core.NewHeader(core.KindDelegation, core.KeyIdentity(admin.KeyID()), admin, now),
		AgentID: *agentID, AgentKeyID: agent.KeyID(), AgentPublicKey: agent.PublicKey(),
		ServiceAudience: *audience, NotBefore: now.Format(core.TimestampLayout),
		ExpiresAt: now.Add(validFor).Format(core.TimestampLayout),
		Scopes:    []string{"sign_origin_statement"},
	}
	signedDelegation, err := admin.Sign(core.KindDelegation, delegation)
	if err != nil {
		return fmt.Errorf("sign delegation: %w", err)
	}
	delegationHash, err := core.EnvelopeDigest(signedDelegation)
	if err != nil {
		return err
	}
	acceptance := core.Acceptance{
		Header:  core.NewHeader(core.KindAcceptance, core.KeyIdentity(agent.KeyID()), agent, now),
		AgentID: *agentID, DelegationSHA256: delegationHash,
	}
	signedAcceptance, err := agent.Sign(core.KindAcceptance, acceptance)
	if err != nil {
		return fmt.Errorf("sign acceptance: %w", err)
	}
	registration := core.AgentRegistration{
		Delegation: signedDelegation, Acceptance: signedAcceptance,
	}
	if _, err := core.VerifyRegistration(registration, *audience, now); err != nil {
		return fmt.Errorf("self-check registration: %w", err)
	}
	if err := writeJSONExclusive(*out, registration, 0o644); err != nil {
		return err
	}
	return writeJSON(a.stdout, struct {
		AgentID   string `json:"agent_id"`
		AdminKey  string `json:"admin_key_id"`
		AgentKey  string `json:"agent_key_id"`
		ExpiresAt string `json:"expires_at"`
	}{*agentID, admin.KeyID(), agent.KeyID(), delegation.ExpiresAt})
}

func (a application) sign(ctx context.Context, args []string) error {
	flags := a.flags("sign")
	keyPath := flags.String("key", "", "agent private key file")
	filePath := flags.String("file", "", "original artifact file")
	out := flags.String("out", "", "new signed statement JSON file")
	registrationPath := flags.String("registration", "", "agent registration JSON file")
	agentID := flags.String("agent-id", "", "agent UUID for producer-only statements")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *keyPath == "" || *filePath == "" || *out == "" {
		return errors.New("sign requires --key, --file, and --out")
	}
	if (*registrationPath == "") == (*agentID == "") {
		return errors.New("sign requires exactly one of --registration or --agent-id")
	}
	agent, _, err := readSigner(*keyPath)
	if err != nil {
		return fmt.Errorf("agent key: %w", err)
	}
	now := a.utcNow()
	delegationHash := ""
	if *registrationPath != "" {
		registration, err := readRegistration(*registrationPath)
		if err != nil {
			return err
		}
		delegation, err := core.VerifyRegistration(registration, "", now)
		if err != nil {
			return fmt.Errorf("registration: %w", err)
		}
		if delegation.AgentKeyID != agent.KeyID() || delegation.AgentPublicKey != agent.PublicKey() {
			return errors.New("agent key does not match registration")
		}
		*agentID = delegation.AgentID
		delegationHash, err = core.EnvelopeDigest(registration.Delegation)
		if err != nil {
			return err
		}
	} else if !core.ValidID(*agentID) {
		return errors.New("agent ID must be a canonical UUID v4")
	}
	artifactHash, artifactSize, err := hashFile(ctx, *filePath)
	if err != nil {
		return err
	}
	nonce, err := core.NewID()
	if err != nil {
		return err
	}
	statement := core.Statement{
		Header:  core.NewHeader(core.KindStatement, core.KeyIdentity(agent.KeyID()), agent, now),
		AgentID: *agentID, DelegationSHA256: delegationHash,
		ArtifactSHA256: artifactHash, ArtifactSize: strconv.FormatInt(artifactSize, 10),
		ArtifactMediaType: artifactMediaType(*filePath), Nonce: nonce,
	}
	signed, err := agent.Sign(core.KindStatement, statement)
	if err != nil {
		return fmt.Errorf("sign statement: %w", err)
	}
	if err := writeJSONExclusive(*out, signed, 0o644); err != nil {
		return err
	}
	return writeJSON(a.stdout, struct {
		AgentID       string `json:"agent_id"`
		ArtifactHash  string `json:"artifact_sha256"`
		ArtifactSize  string `json:"artifact_size"`
		StatementPath string `json:"statement"`
	}{*agentID, artifactHash, statement.ArtifactSize, *out})
}

func (a application) grant(ctx context.Context, args []string) error {
	flags := a.flags("grant")
	adminPath := flags.String("admin-key", "", "administrator private key file")
	statementPath := flags.String("statement", "", "signed statement JSON file")
	registrationPath := flags.String("registration", "", "agent registration JSON file")
	audience := flags.String("audience", "", "exact service issuer URI")
	visibility := flags.String("visibility", "", "private or public")
	out := flags.String("out", "", "new publication grant JSON file")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *adminPath == "" || *statementPath == "" || *registrationPath == "" ||
		*audience == "" || *visibility == "" || *out == "" {
		return errors.New("grant requires --admin-key, --statement, --registration, --audience, --visibility, and --out")
	}
	if *visibility != "private" && *visibility != "public" {
		return errors.New("visibility must be private or public")
	}
	if !core.ValidIssuer(*audience) {
		return errors.New("audience must be an exact HTTPS or URN issuer identifier")
	}
	admin, _, err := readSigner(*adminPath)
	if err != nil {
		return fmt.Errorf("admin key: %w", err)
	}
	statement, err := readEnvelope(*statementPath)
	if err != nil {
		return fmt.Errorf("statement: %w", err)
	}
	registration, err := readRegistration(*registrationPath)
	if err != nil {
		return err
	}
	now := a.utcNow()
	delegation, err := core.VerifyRegistration(registration, *audience, now)
	if err != nil {
		return fmt.Errorf("registration: %w", err)
	}
	if delegation.IssuerKeyID != admin.KeyID() || registration.Delegation.Signature.PublicKey != admin.PublicKey() {
		return errors.New("admin key does not match registration")
	}
	if _, err := core.VerifyBundle(core.Bundle{
		Protocol: core.Protocol, Statement: statement,
		Delegation: &registration.Delegation, Acceptance: &registration.Acceptance,
	}, core.VerifyOptions{}); err != nil {
		return fmt.Errorf("statement registration binding: %w", err)
	}
	statementHash, err := core.EnvelopeDigest(statement)
	if err != nil {
		return err
	}
	delegationHash, err := core.EnvelopeDigest(registration.Delegation)
	if err != nil {
		return err
	}
	nonce, err := core.NewID()
	if err != nil {
		return err
	}
	grant := core.PublicationGrant{
		Header:          core.NewHeader(core.KindGrant, core.KeyIdentity(admin.KeyID()), admin, now),
		StatementSHA256: statementHash, DelegationSHA256: delegationHash,
		ServiceAudience: *audience, Visibility: *visibility,
		Purpose: "issue_origin_certificate", ExpiresAt: now.Add(5 * time.Minute).Format(core.TimestampLayout),
		Nonce: nonce,
	}
	signed, err := admin.Sign(core.KindGrant, grant)
	if err != nil {
		return fmt.Errorf("sign publication grant: %w", err)
	}
	if _, err := core.ValidateGrant(
		signed, statement, registration.Delegation, admin.KeyID(), *audience, now,
	); err != nil {
		return fmt.Errorf("self-check publication grant: %w", err)
	}
	if err := writeJSONExclusive(*out, signed, 0o644); err != nil {
		return err
	}
	return writeJSON(a.stdout, struct {
		Nonce      string `json:"nonce"`
		Visibility string `json:"visibility"`
		ExpiresAt  string `json:"expires_at"`
	}{nonce, *visibility, grant.ExpiresAt})
}

func (a application) issue(ctx context.Context, args []string) error {
	flags := a.flags("issue")
	keyPath := flags.String("key", "", "local issuer private key file")
	issuer := flags.String("issuer", "", "self-selected issuer URI")
	statementPath := flags.String("statement", "", "signed statement JSON file")
	registrationPath := flags.String("registration", "", "optional agent registration JSON file")
	out := flags.String("out", "", "new certificate bundle JSON file")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *keyPath == "" || *issuer == "" || *statementPath == "" || *out == "" {
		return errors.New("issue requires --key, --issuer, --statement, and --out")
	}
	issuerSigner, _, err := readSigner(*keyPath)
	if err != nil {
		return fmt.Errorf("issuer key: %w", err)
	}
	statement, err := readEnvelope(*statementPath)
	if err != nil {
		return fmt.Errorf("statement: %w", err)
	}
	bundle := core.Bundle{Protocol: core.Protocol, Statement: statement}
	if *registrationPath != "" {
		registration, err := readRegistration(*registrationPath)
		if err != nil {
			return err
		}
		bundle.Delegation = &registration.Delegation
		bundle.Acceptance = &registration.Acceptance
	}
	now := a.utcNow()
	bundle, err = core.Issue(bundle, issuerSigner, *issuer, now)
	if err != nil {
		return fmt.Errorf("local issuance: %w", err)
	}
	var certificate core.Certificate
	if err := core.DecodePayload(*bundle.Certificate, core.KindCertificate, &certificate); err != nil {
		return fmt.Errorf("self-check certificate: %w", err)
	}
	if err := writeJSONExclusive(*out, bundle, 0o644); err != nil {
		return err
	}
	return writeJSON(a.stdout, struct {
		CertificateID string `json:"certificate_id"`
		Issuer        string `json:"issuer"`
		IssuerKeyID   string `json:"issuer_key_id"`
		IssuerStatus  string `json:"issuer_status"`
	}{certificate.CertificateID, *issuer, issuerSigner.KeyID(), "self_asserted_local"})
}

func (a application) verify(ctx context.Context, args []string) error {
	flags := a.flags("verify")
	offline := flags.Bool("offline", false, "confirm that verification must use local files only")
	bundlePath := flags.String("bundle", "", "certificate bundle JSON file")
	issuer := flags.String("issuer", "", "exact trusted issuer URI")
	keyID := flags.String("key-id", "", "exact trusted issuer key fingerprint")
	at := flags.String("at", "", "evaluation time in RFC3339; defaults to current time")
	artifactPath := flags.String("artifact", "", "optional original artifact to compare")
	requireTrusted := flags.Bool("require-trusted", false, "fail unless both issuer and key ID match")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if !*offline || *bundlePath == "" {
		return errors.New("verify requires --offline and --bundle")
	}
	if *requireTrusted && (*issuer == "" || *keyID == "") {
		return errors.New("--require-trusted requires both --issuer and --key-id")
	}
	now := a.utcNow()
	if *at != "" {
		parsed, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return fmt.Errorf("invalid --at RFC3339 time: %w", err)
		}
		now = parsed.UTC().Truncate(time.Second)
	}
	raw, err := readBoundedRegular(*bundlePath, core.MaxInputBytes)
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	trustedKeys := []string(nil)
	if *keyID != "" {
		trustedKeys = []string{*keyID}
	}
	verification, err := core.Verify(raw, core.VerifyOptions{
		ExpectedIssuer: *issuer, TrustedKeyIDs: trustedKeys, Now: now,
	})
	if err != nil {
		_ = writeJSON(a.stdout, struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}{false, "verification_failed"})
		return fmt.Errorf("verify bundle: %w", err)
	}
	output := verificationOutput{
		Verification: verification,
		Valid:        true,
		Trusted:      verification.IssuerTrust == "accepted_by_policy",
	}
	artifactMismatch := false
	if *artifactPath != "" {
		hash, size, err := hashFile(ctx, *artifactPath)
		if err != nil {
			return err
		}
		matches := verification.Statement.ArtifactSHA256 == hash &&
			verification.Statement.ArtifactSize == strconv.FormatInt(size, 10)
		output.ArtifactMatches = &matches
		artifactMismatch = !matches
	}
	if err := writeJSON(a.stdout, output); err != nil {
		return err
	}
	if artifactMismatch {
		return &exitError{code: 4, err: errors.New("artifact does not match signed statement")}
	}
	if *requireTrusted && !output.Trusted {
		return &exitError{code: 3, err: errors.New("issuer trust policy did not match")}
	}
	return nil
}

// verifyERC8004 verifies the detached binding profile using only a local JSON
// document. It intentionally does not query an RPC, key directory, or server.
func (a application) verifyERC8004(ctx context.Context, args []string) error {
	flags := a.flags("verify-erc8004")
	bindingPath := flags.String("binding", "", "detached ERC-8004 binding JSON file")
	issuer := flags.String("issuer", "", "exact trusted issuer URI")
	keyID := flags.String("key-id", "", "exact trusted issuer key fingerprint")
	at := flags.String("at", "", "evaluation time in RFC3339; defaults to current time")
	requireTrusted := flags.Bool("require-trusted", false, "fail unless issuer/key pin matches and binding is within validity")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireContext(ctx); err != nil {
		return err
	}
	if *bindingPath == "" {
		return errors.New("verify-erc8004 requires --binding")
	}
	if *requireTrusted && (*issuer == "" || *keyID == "") {
		return errors.New("--require-trusted requires both --issuer and --key-id")
	}
	now := a.utcNow()
	if *at != "" {
		parsed, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return fmt.Errorf("invalid --at RFC3339 time: %w", err)
		}
		now = parsed.UTC().Truncate(time.Second)
	}
	raw, err := readBoundedRegular(*bindingPath, core.MaxInputBytes)
	if err != nil {
		return fmt.Errorf("binding: %w", err)
	}
	var document core.ERC8004BindingDocument
	if err := core.StrictJSON(raw, &document); err != nil {
		_ = writeJSON(a.stdout, struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}{false, "verification_failed"})
		return fmt.Errorf("verify ERC-8004 binding: %w", err)
	}
	trustedKeys := []string(nil)
	if *keyID != "" {
		trustedKeys = []string{*keyID}
	}
	verification, err := core.VerifyERC8004Binding(document, core.VerifyOptions{
		ExpectedIssuer: *issuer, TrustedKeyIDs: trustedKeys, Now: now,
	})
	if err != nil {
		_ = writeJSON(a.stdout, struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}{false, "verification_failed"})
		return fmt.Errorf("verify ERC-8004 binding: %w", err)
	}
	output := erc8004VerificationOutput{
		ERC8004Verification: verification,
		Valid:               true,
		Trusted:             verification.IssuerTrust == "pinned" && verification.Freshness == "within_validity",
	}
	if err := writeJSON(a.stdout, output); err != nil {
		return err
	}
	if *requireTrusted && !output.Trusted {
		return &exitError{code: 3, err: errors.New("issuer trust policy did not match or binding is outside validity")}
	}
	return nil
}

type verificationOutput struct {
	core.Verification
	Valid           bool  `json:"valid"`
	Trusted         bool  `json:"trusted"`
	ArtifactMatches *bool `json:"artifact_matches,omitempty"`
}

type erc8004VerificationOutput struct {
	core.ERC8004Verification
	Valid   bool `json:"valid"`
	Trusted bool `json:"trusted"`
}

func (a application) flags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	return flags
}

func (a application) utcNow() time.Time {
	if a.now == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return a.now().UTC().Truncate(time.Second)
}

func parseFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return nil
}

func requireContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func readSigner(path string) (*core.Signer, keyFile, error) {
	raw, err := readPrivateKeyFile(path)
	if err != nil {
		return nil, keyFile{}, err
	}
	var stored keyFile
	if err := core.StrictJSON(raw, &stored); err != nil {
		return nil, keyFile{}, fmt.Errorf("parse private key: %w", err)
	}
	if stored.Protocol != core.Protocol {
		return nil, keyFile{}, errors.New("private key uses an unsupported protocol")
	}
	if len(stored.Role) > 64 || strings.ContainsAny(stored.Role, "\r\n\x00") {
		return nil, keyFile{}, errors.New("private key role label is invalid")
	}
	signer, err := core.NewSigner(stored.Seed)
	if err != nil {
		return nil, keyFile{}, err
	}
	if signer.KeyID() != stored.KeyID || signer.PublicKey() != stored.PublicKey {
		return nil, keyFile{}, errors.New("private key metadata does not match its seed")
	}
	return signer, stored, nil
}

func readPrivateKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("private key path must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key file permissions %04o expose it to group or other users", info.Mode().Perm())
	}
	return readBoundedRegular(path, maxKeyFileBytes)
}

func readRegistration(path string) (core.AgentRegistration, error) {
	raw, err := readBoundedRegular(path, core.MaxInputBytes)
	if err != nil {
		return core.AgentRegistration{}, fmt.Errorf("registration: %w", err)
	}
	var registration core.AgentRegistration
	if err := core.StrictJSON(raw, &registration); err != nil {
		return core.AgentRegistration{}, fmt.Errorf("registration: %w", err)
	}
	return registration, nil
}

func readEnvelope(path string) (core.Envelope, error) {
	raw, err := readBoundedRegular(path, core.MaxInputBytes)
	if err != nil {
		return core.Envelope{}, err
	}
	var envelope core.Envelope
	if err := core.StrictJSON(raw, &envelope); err != nil {
		return core.Envelope{}, err
	}
	if _, err := core.VerifyEnvelope(envelope); err != nil {
		return core.Envelope{}, err
	}
	return envelope, nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input path must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("input must contain 1-%d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || int64(len(raw)) > limit {
		return nil, fmt.Errorf("input must contain 1-%d bytes", limit)
	}
	return raw, nil
}

func hashFile(ctx context.Context, path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, fmt.Errorf("artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", 0, errors.New("artifact path must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("artifact: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var size int64
	for {
		if err := requireContext(ctx); err != nil {
			return "", 0, err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			written, writeErr := hash.Write(buffer[:read])
			if writeErr != nil {
				return "", 0, writeErr
			}
			if written != read {
				return "", 0, io.ErrShortWrite
			}
			size += int64(read)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", 0, readErr
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func artifactMediaType(path string) string {
	mediaType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if mediaType == "" || len(mediaType) > 128 || strings.ContainsAny(mediaType, "\r\n\x00") {
		return "application/octet-stream"
	}
	return mediaType
}

func writeJSONExclusive(path string, value any, mode os.FileMode) error {
	if path == "" {
		return errors.New("output path is required")
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
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

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
