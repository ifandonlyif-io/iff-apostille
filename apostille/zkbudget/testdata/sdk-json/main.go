// Exercise the SDK in a normal executable: gnark disables its default logger
// inside go test binaries, which would otherwise hide stdout regressions.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/ifandonlyif-io/iff-apostille/apostille/zkbudget"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--circuit" {
		info, err := zkbudget.InspectCircuit()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(info)
	}
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	seed, _, err := core.GenerateKey()
	if err != nil {
		return err
	}
	signer, err := core.NewSigner(seed)
	if err != nil {
		return err
	}
	private, err := zkbudget.NewSnapshot([]string{"100"}, zkbudget.SnapshotOptions{
		Scope: "sdk-json-test", Currency: "USD", PeriodStart: "2026-09-01T00:00:00Z", PeriodEnd: "2026-09-14T00:00:00Z",
	})
	if err != nil {
		return err
	}
	source, err := zkbudget.SignSnapshot(private.Snapshot, signer, nil, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now)
	if err != nil {
		return err
	}
	request, err := zkbudget.NewRequest(private.Snapshot, "test-policy", "urn:example:audit", "100", now)
	if err != nil {
		return err
	}
	parameters, err := zkbudget.Setup()
	if err != nil {
		return err
	}
	prover, err := zkbudget.NewProver(parameters.ProvingKey, parameters.VerifyingKey, parameters.VerifyingKeySHA256)
	if err != nil {
		return err
	}
	document, err := prover.Prove(private, source, request, now)
	if err != nil {
		return err
	}
	verifier, err := zkbudget.NewVerifier(parameters.VerifyingKey, parameters.VerifyingKeySHA256)
	if err != nil {
		return err
	}
	result, err := verifier.Verify(document, zkbudget.VerifyOptions{
		ExpectedRequest: request, TrustedSourceKeyIDs: []string{signer.KeyID()}, Now: now,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
