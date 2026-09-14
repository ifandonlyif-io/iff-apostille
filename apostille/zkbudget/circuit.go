// Package zkbudget implements an experimental, detached Apostille budget proof.
// All operations are local. It proves a predicate over a signed commitment, not
// the truth or completeness of the upstream accounting system.
package zkbudget

import (
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// This is a fixed circuit: modifying any constraint requires a new CircuitID,
// new setup and independently distributed verifier pins.
type budgetCircuit struct {
	Commitment frontend.Variable `gnark:",public"`
	Limit      frontend.Variable `gnark:",public"`
	ContextHi  frontend.Variable `gnark:",public"`
	ContextLo  frontend.Variable `gnark:",public"`
	Count      frontend.Variable `gnark:",public"`
	RequestHi  frontend.Variable `gnark:",public"`
	RequestLo  frontend.Variable `gnark:",public"`
	SourceHi   frontend.Variable `gnark:",public"`
	SourceLo   frontend.Variable `gnark:",public"`
	Amounts    [MaxEntries]frontend.Variable
	Blinding   frontend.Variable
}

func (c *budgetCircuit) Define(api frontend.API) error {
	api.ToBinary(c.Limit, 52)
	api.ToBinary(c.ContextHi, 128)
	api.ToBinary(c.ContextLo, 128)
	api.ToBinary(c.RequestHi, 128)
	api.ToBinary(c.RequestLo, 128)
	api.ToBinary(c.SourceHi, 128)
	api.ToBinary(c.SourceLo, 128)
	api.AssertIsDifferent(c.Blinding, 0)
	var sizes [MaxEntries]frontend.Variable
	var one frontend.Variable = 0
	for i := range sizes {
		sizes[i] = api.IsZero(api.Sub(c.Count, i+1))
		one = api.Add(one, sizes[i])
	}
	api.AssertIsEqual(one, 1) // Count is exactly one of 1..16, including in raw witnesses.
	var total frontend.Variable = 0
	for i, amount := range c.Amounts {
		api.ToBinary(amount, AmountBits) // excludes negative/field-wrap witnesses
		var active frontend.Variable = 0
		for j := i; j < MaxEntries; j++ {
			active = api.Add(active, sizes[j])
		}
		api.AssertIsEqual(api.Mul(api.Sub(1, active), amount), 0)
		total = api.Add(total, amount)
	}
	// At most 16 unsigned 48-bit amounts: no scalar-field overflow is possible.
	api.AssertIsLessOrEqual(total, c.Limit)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(domain("snapshot"), c.ContextHi, c.ContextLo, c.Count, c.Blinding)
	h.Write(c.Amounts[:]...)
	api.AssertIsEqual(h.Sum(), c.Commitment)
	// Request/source words remain constrained by ToBinary above, and Groth16
	// binds the public witness directly. Rehashing these public values adds no
	// relation to the private amounts or blinding.
	return nil
}

func domain(kind string) *big.Int {
	s := sha256.Sum256([]byte(Profile + "\n" + CircuitID + "\n" + kind))
	return new(big.Int).SetBytes(s[:16])
}
