package apostille

import "errors"

// Verifier reuses immutable signature and digest checks within one operation,
// such as an API submission. Its zero value is ready to use. It must not be
// shared between goroutines or retained across requests. Audience, time, grant
// bindings and other authorization checks are always evaluated on every call.
// A cache entry is keyed by the complete envelope, including its signature;
// callers cannot supply or mutate the private verified payloads.
type Verifier struct {
	verified map[Envelope]VerifiedEnvelope
	digests  map[Envelope]string
}

// DecodePayload checks the exact envelope before decoding a fresh payload copy.
func (v *Verifier) DecodePayload(envelope Envelope, kind string, dst any) error {
	if envelope.Kind != kind {
		return errors.New("wrong artifact kind")
	}
	checked, ok := v.verified[envelope]
	if !ok {
		var err error
		checked, err = VerifyEnvelope(envelope)
		if err != nil {
			return err
		}
		if v.verified == nil {
			v.verified = make(map[Envelope]VerifiedEnvelope)
		}
		v.verified[envelope] = checked
	}
	return StrictJSON(checked.Payload, dst)
}

func (v *Verifier) envelopeDigest(envelope Envelope) (string, error) {
	if digest, ok := v.digests[envelope]; ok {
		return digest, nil
	}
	digest, err := EnvelopeDigest(envelope)
	if err != nil {
		return "", err
	}
	if v.digests == nil {
		v.digests = make(map[Envelope]string)
	}
	v.digests[envelope] = digest
	return digest, nil
}
