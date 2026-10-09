package apostille

import (
	"errors"
	"time"
)

// Explicit-version signing. The functions without a "For" suffix sign Core 0.1
// and stay the default; these take any protocol in KnownProtocols.

// NewHeaderFor is NewHeader for a known protocol version.
func NewHeaderFor(protocol, kind, issuer string, signer *Signer, now time.Time) (Header, error) {
	if _, err := profileFor(protocol); err != nil {
		return Header{}, err
	}
	return headerFor(protocol, kind, issuer, signer, now), nil
}

// headerFor builds a header for a protocol the caller has already validated.
func headerFor(protocol, kind, issuer string, signer *Signer, now time.Time) Header {
	return Header{Protocol: protocol, Kind: kind, Issuer: issuer, IssuerKeyID: signer.KeyID(), IssuedAt: now.UTC().Format(TimestampLayout)}
}

// SignFor signs value as an artifact of the given protocol version. The payload
// must already name that version. As Core 0.2 recommends, the signer checks its
// own key and signature under the version's rules before releasing them.
func (s *Signer) SignFor(protocol, kind string, value any) (Envelope, error) {
	if !s.Enabled() {
		return Envelope{}, errors.New("issuer signing is disabled")
	}
	prof, err := profileFor(protocol)
	if err != nil {
		return Envelope{}, err
	}
	// A signer holds one algorithm's key; a profile with another algorithm
	// needs its own signer, and this is refused before any work.
	if prof.algorithm != s.Algorithm() {
		return Envelope{}, errors.New("signer does not support the protocol's signature algorithm")
	}
	raw, err := Canonical(value)
	if err != nil {
		return Envelope{}, err
	}
	header, err := validatePayload(prof, kind, raw)
	if err != nil {
		return Envelope{}, err
	}
	if header.IssuerKeyID != s.KeyID() {
		return Envelope{}, errors.New("signed key ID does not match signer")
	}
	message := prof.signingInput(kind, raw)
	signature, err := s.signMessage(message)
	if err != nil {
		return Envelope{}, err
	}
	if err := prof.checkKey(s.publicKeyBytes()); err != nil {
		return Envelope{}, err
	}
	if err := prof.verify(s.publicKeyBytes(), message, signature); err != nil {
		return Envelope{}, err
	}
	return Envelope{Protocol: prof.protocol, Kind: kind, Payload: rawURL.EncodeToString(raw), PayloadSHA256: Hash(raw), Signature: Signature{Algorithm: prof.algorithm, KeyID: s.KeyID(), PublicKey: s.PublicKey(), Value: rawURL.EncodeToString(signature)}}, nil
}
