package zkbudget

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"testing"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/stretchr/testify/require"
)

func TestSDKProcessWritesOnlyJSON(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", "./testdata/sdk-json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), "SDK executable: %s", stderr.String())
	var result Verification
	decoder := json.NewDecoder(&stdout)
	require.NoError(t, decoder.Decode(&result), "stdout must start with the SDK JSON result")
	require.Equal(t, "valid", result.ProofIntegrity)
	require.ErrorIs(t, decoder.Decode(new(any)), io.EOF, "stdout must contain only one JSON value")
	require.Empty(t, stderr.String(), "no default process logging on stderr either")
}

func TestCircuitFingerprintReproducesOutsideProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "go", "run", "./testdata/sdk-json", "--circuit").Output()
	require.NoError(t, err)
	var remote CircuitInfo
	require.NoError(t, json.Unmarshal(raw, &remote))
	local, err := InspectCircuit()
	require.NoError(t, err)
	require.Equal(t, local, remote, "same scheme/circuit must reproduce across compilations")
	ccs, err := compile()
	require.NoError(t, err)
	encoded, err := serialize(ccs)
	require.NoError(t, err)
	require.Equal(t, core.Hash(encoded), local.CircuitSHA256)
	require.Equal(t, ccs.GetNbConstraints(), local.Constraints)
	require.Equal(t, 9, local.PublicInputs)
}

func TestCircuitConstraintBudget(t *testing.T) {
	ccs, err := compile()
	require.NoError(t, err)
	// Keep the fixed profile below 10k constraints; a second hash of its public
	// inputs added 2,998 constraints without adding a private witness relation.
	require.LessOrEqual(t, ccs.GetNbConstraints(), 10000)
	t.Logf("budget circuit: %d constraints", ccs.GetNbConstraints())
}
