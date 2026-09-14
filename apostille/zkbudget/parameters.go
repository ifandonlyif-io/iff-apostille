package zkbudget

import (
	"encoding/binary"
	"errors"
)

// gnark's generic binary decoder allocates from serialized counts. Validate
// every count and compressed-point boundary without allocation before calling
// ReadFrom, even for operator-selected local parameter files. This encoding is
// pinned to Scheme; a library serialization change requires a new profile.
type keyCursor struct {
	raw     []byte
	pos     int
	invalid bool
}

func (s *keyCursor) take(n uint64) []byte {
	if s.invalid || n > uint64(len(s.raw)-s.pos) {
		s.invalid = true
		return nil
	}
	x := s.raw[s.pos : s.pos+int(n)]
	s.pos += int(n)
	return x
}
func (s *keyCursor) u32() uint64 {
	b := s.take(4)
	if b == nil {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(b))
}
func (s *keyCursor) u64() uint64 {
	b := s.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (s *keyCursor) points(n, size uint64) {
	if s.invalid || n > uint64(len(s.raw)-s.pos)/size {
		s.invalid = true
		return
	}
	for i := uint64(0); i < n; i++ {
		b := s.take(size)
		if b == nil || b[0]&0x80 == 0 {
			s.invalid = true
			return
		}
	}
}
func (s *keyCursor) vector(max, size uint64) uint64 {
	n := s.u32()
	if n > max {
		s.invalid = true
		return 0
	}
	s.points(n, size)
	return n
}
func (s *keyCursor) done() bool { return !s.invalid && s.pos == len(s.raw) }

func validateVerificationKeyBytes(raw []byte) error {
	s := keyCursor{raw: raw}
	s.points(2, 48)
	s.points(2, 96)
	s.points(1, 48)
	s.points(1, 96)
	n := s.vector(publicInputs+1, 48)
	if n != publicInputs+1 || s.u32() != 0 || s.u32() != 0 || !s.done() {
		return errors.New("invalid trusted verification key layout")
	}
	return nil
}

func validateProvingKeyBytes(raw []byte) error {
	ccs, err := compile()
	if err != nil {
		return errors.New("budget circuit compilation failed")
	}
	wires := uint64(ccs.GetNbInternalVariables() + ccs.GetNbSecretVariables() + ccs.GetNbPublicVariables())
	cardinality := uint64(1)
	for cardinality < uint64(ccs.GetNbConstraints()) {
		cardinality <<= 1
	}
	s := keyCursor{raw: raw}
	if s.u64() != cardinality {
		return errors.New("invalid proving-key domain size")
	}
	// Five canonical field elements and the bounded precompute flag. Field
	// canonicality is checked by gnark after all allocation bounds are established.
	s.take(5 * 32)
	precompute := s.take(1)
	if precompute == nil || precompute[0] > 1 {
		return errors.New("invalid proving-key domain")
	}
	s.points(3, 48)
	a := s.vector(wires, 48)
	b := s.vector(wires, 48)
	z := s.vector(cardinality, 48)
	k := s.vector(wires, 48)
	s.points(2, 96)
	b2 := s.vector(wires, 96)
	n := s.u64()
	infinityA := s.u64()
	infinityB := s.u64()
	if s.invalid || n != wires || infinityA > wires || infinityB > wires || a != wires-infinityA || b != wires-infinityB || b2 != b || z != cardinality-1 || k != wires-uint64(ccs.GetNbPublicVariables()) {
		return errors.New("invalid proving-key vector counts")
	}
	for _, expected := range []uint64{infinityA, infinityB} {
		flags := s.take(wires)
		var count uint64
		for _, f := range flags {
			if f > 1 {
				s.invalid = true
			}
			count += uint64(f)
		}
		if count != expected {
			s.invalid = true
		}
	}
	if s.u32() != 0 || !s.done() {
		return errors.New("invalid proving-key trailing fields")
	}
	return nil
}
