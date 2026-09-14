package zkbudget

import (
	"encoding/binary"
	"testing"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/stretchr/testify/require"
)

func TestParameterDecodingBoundsBeforeAllocation(t *testing.T) {
	p, err := testSetup()
	require.NoError(t, err)
	// K vector count follows six fixed points; its points precede the two
	// forbidden commitment-vector counts. v2 has nine public inputs plus ONE.
	for _, offset := range []int{432, 436 + 48*(publicInputs+1), 440 + 48*(publicInputs+1)} {
		bad := append([]byte(nil), p.VerifyingKey...)
		binary.BigEndian.PutUint32(bad[offset:offset+4], ^uint32(0))
		// Supply the malformed file's actual hash, so rejection must be due to
		// structural bounds, not merely the independent hash gate.
		_, err := NewVerifier(bad, core.Hash(bad))
		require.Error(t, err)
	}
	bad := append([]byte(nil), p.ProvingKey...)
	binary.BigEndian.PutUint64(bad[:8], uint64(1)<<60)
	_, err = NewProver(bad, p.VerifyingKey, p.VerifyingKeySHA256)
	require.ErrorContains(t, err, "domain size")
	bad = append([]byte(nil), p.ProvingKey...)
	// Fixed domain (169 bytes) and three compressed G1 points precede A.
	binary.BigEndian.PutUint32(bad[313:317], ^uint32(0))
	_, err = NewProver(bad, p.VerifyingKey, p.VerifyingKeySHA256)
	require.Error(t, err)
	for _, raw := range [][]byte{p.ProvingKey[:1], p.ProvingKey[:168], p.ProvingKey[:500], append(append([]byte(nil), p.ProvingKey...), 0)} {
		_, err := NewProver(raw, p.VerifyingKey, p.VerifyingKeySHA256)
		require.Error(t, err)
	}
	bad = append([]byte(nil), p.VerifyingKey...)
	bad[0] &= 0x7f
	_, err = NewVerifier(bad, core.Hash(bad))
	require.Error(t, err, "uncompressed points cannot shift encoded counts")
}

func TestVerifierRejectsLegacyTenPublicInputLayout(t *testing.T) {
	p, err := testSetup()
	require.NoError(t, err)
	// v1 had an extra Binding input. Insert an otherwise valid compressed K
	// point and adjust its count to reproduce the legacy layout before decode.
	end := 436 + 48*(publicInputs+1)
	legacy := append([]byte(nil), p.VerifyingKey[:end]...)
	legacy = append(legacy, p.VerifyingKey[436:484]...)
	legacy = append(legacy, p.VerifyingKey[end:]...)
	binary.BigEndian.PutUint32(legacy[432:436], 11)
	_, err = NewVerifier(legacy, core.Hash(legacy))
	require.ErrorContains(t, err, "invalid trusted verification key layout")
}
