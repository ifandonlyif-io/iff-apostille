package apostille

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var (
	rawURL         = base64.RawURLEncoding.Strict()
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
)

type Signer struct{ key ed25519.PrivateKey }

func NewSigner(encoded string) (*Signer, error) {
	if encoded == "" {
		return &Signer{}, nil
	}
	var key []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding.Strict(), base64.URLEncoding.Strict(), base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict()} {
		key, err = encoding.DecodeString(encoded)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("invalid signing key encoding")
	}
	switch len(key) {
	case ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(key)
	case ed25519.PrivateKeySize:
		if !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) {
			return nil, errors.New("inconsistent expanded signing key")
		}
	default:
		return nil, errors.New("signing key must be a 32-byte seed or 64-byte Ed25519 key")
	}
	return &Signer{key: append(ed25519.PrivateKey(nil), key...)}, nil
}

func GenerateKey() (seed string, publicKey string, err error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return rawURL.EncodeToString(key.Seed()), rawURL.EncodeToString(pub), nil
}
func (s *Signer) Enabled() bool { return s != nil && len(s.key) == ed25519.PrivateKeySize }
func (s *Signer) PublicKey() string {
	if !s.Enabled() {
		return ""
	}
	return rawURL.EncodeToString(s.key[32:])
}
func (s *Signer) KeyID() string {
	if !s.Enabled() {
		return ""
	}
	return Fingerprint(s.key[32:])
}
func Fingerprint(key []byte) string   { return "sha256:" + Hash(key) }
func KeyIdentity(keyID string) string { return "urn:apostille:key:" + keyID }
func Hash(raw []byte) string          { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func ValidID(id string) bool          { return idPattern.MatchString(id) }
func NewID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := rawURL.DecodeString(value)
	if err != nil || len(raw) != ed25519.PublicKeySize || rawURL.EncodeToString(raw) != value {
		return nil, errors.New("invalid canonical Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}
func NewHeader(kind, issuer string, signer *Signer, now time.Time) Header {
	return Header{Protocol: Protocol, Kind: kind, Issuer: issuer, IssuerKeyID: signer.KeyID(), IssuedAt: now.UTC().Format(TimestampLayout)}
}
func Timestamp(value string) (time.Time, error) {
	t, err := time.Parse(TimestampLayout, value)
	if err != nil || t.Format(TimestampLayout) != value {
		return time.Time{}, errors.New("timestamp must be UTC seconds")
	}
	return t, nil
}
func ValidIssuer(value string) bool {
	if len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value || !utf8.ValidString(value) || strings.ContainsAny(value, "?#%\\") {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "urn" {
		return u.Opaque != ""
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || strconv.FormatUint(n, 10) != port || port == "443" {
			return false
		}
	}
	return u.Scheme == "https" && u.Host != "" && u.Host == strings.ToLower(u.Host) && u.RawPath == ""
}

// StrictJSON validates bounded I-JSON before canonicalization. In the 0.1
// profile all exact quantities are strings: numeric JSON tokens are rejected.
func StrictJSON(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > MaxInputBytes || !utf8.Valid(raw) {
		return errors.New("invalid JSON size or UTF-8")
	}
	if err := validateJSON(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errors.New("invalid JSON shape or field")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}
func validateJSON(raw []byte) error {
	// Surrogate escapes are checked on the raw text, before any decoder can
	// replace an unpaired one with U+FFFD. The JCS parser rejects duplicate
	// properties; the token pass additionally bounds recursion and rejects
	// numeric tokens.
	if err := pairedSurrogateEscapes(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return errors.New("JSON nesting exceeds 24")
		}
		token, err := dec.Token()
		if err != nil {
			return errors.New("invalid JSON")
		}
		if _, ok := token.(json.Number); ok {
			return errors.New("numeric JSON values are unsupported; use decimal strings")
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for dec.More() {
					k, e := dec.Token()
					if e != nil {
						return e
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return errors.New("duplicate JSON key")
					}
					seen[key] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				close, err := dec.Token()
				if err != nil || close != json.Delim('}') {
					return errors.New("invalid object")
				}
			case '[':
				for dec.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				close, err := dec.Token()
				if err != nil || close != json.Delim(']') {
					return errors.New("invalid array")
				}
			default:
				return errors.New("unexpected JSON delimiter")
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	if _, err := jcs.Transform(raw); err != nil {
		return errors.New("invalid canonical JSON input")
	}
	return nil
}
func Canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if err := validateJSON(raw); err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}
func EnvelopeDigest(envelope Envelope) (string, error) {
	raw, err := Canonical(envelope)
	if err != nil {
		return "", err
	}
	return Hash(raw), nil
}
func signingInput(kind string, payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return append([]byte("iff-apostille/"+kind+"/0.1\n"), hash[:]...)
}
func (s *Signer) Sign(kind string, value any) (Envelope, error) {
	if !s.Enabled() {
		return Envelope{}, errors.New("issuer signing is disabled")
	}
	raw, err := Canonical(value)
	if err != nil {
		return Envelope{}, err
	}
	header, err := validatePayload(kind, raw)
	if err != nil {
		return Envelope{}, err
	}
	if header.IssuerKeyID != s.KeyID() {
		return Envelope{}, errors.New("signed key ID does not match signer")
	}
	return Envelope{Protocol: Protocol, Kind: kind, Payload: rawURL.EncodeToString(raw), PayloadSHA256: Hash(raw), Signature: Signature{Algorithm: Algorithm, KeyID: s.KeyID(), PublicKey: s.PublicKey(), Value: rawURL.EncodeToString(ed25519.Sign(s.key, signingInput(kind, raw)))}}, nil
}
func VerifyEnvelope(envelope Envelope) (VerifiedEnvelope, error) {
	if len(envelope.Payload) > MaxInputBytes || len(envelope.Signature.PublicKey) > 64 || len(envelope.Signature.Value) > 128 || len(envelope.Kind) > 64 {
		return VerifiedEnvelope{}, errors.New("envelope fields exceed size limit")
	}
	if envelope.Protocol != Protocol || envelope.Signature.Algorithm != Algorithm {
		return VerifiedEnvelope{}, errors.New("unsupported envelope protocol or algorithm")
	}
	raw, err := rawURL.DecodeString(envelope.Payload)
	if err != nil || len(raw) == 0 || len(raw) > MaxInputBytes/2 || rawURL.EncodeToString(raw) != envelope.Payload {
		return VerifiedEnvelope{}, errors.New("invalid payload encoding or size")
	}
	if Hash(raw) != envelope.PayloadSHA256 {
		return VerifiedEnvelope{}, errors.New("payload digest mismatch")
	}
	if err := validateJSON(raw); err != nil {
		return VerifiedEnvelope{}, err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return VerifiedEnvelope{}, errors.New("payload is not canonical JSON")
	}
	pub, err := ParsePublicKey(envelope.Signature.PublicKey)
	if err != nil || Fingerprint(pub) != envelope.Signature.KeyID {
		return VerifiedEnvelope{}, errors.New("key fingerprint mismatch")
	}
	signature, err := rawURL.DecodeString(envelope.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize || rawURL.EncodeToString(signature) != envelope.Signature.Value || !ed25519.Verify(pub, signingInput(envelope.Kind, raw), signature) {
		return VerifiedEnvelope{}, errors.New("invalid source signature")
	}
	header, err := validatePayload(envelope.Kind, raw)
	if err != nil {
		return VerifiedEnvelope{}, err
	}
	if header.IssuerKeyID != envelope.Signature.KeyID {
		return VerifiedEnvelope{}, errors.New("signed key ID mismatch")
	}
	return VerifiedEnvelope{Header: header, Payload: raw, KeyID: header.IssuerKeyID}, nil
}
func DecodePayload(envelope Envelope, kind string, dst any) error {
	if envelope.Kind != kind {
		return errors.New("wrong artifact kind")
	}
	v, err := VerifyEnvelope(envelope)
	if err != nil {
		return err
	}
	return StrictJSON(v.Payload, dst)
}

// SignChallenge/VerifyChallenge are purpose-separated from all protocol artifacts.
func (s *Signer) SignChallenge(message string) (string, error) {
	if !s.Enabled() {
		return "", errors.New("signing key required")
	}
	if !strings.HasPrefix(message, "iff-apostille/login/0.1\n") || len(message) > 4096 {
		return "", errors.New("invalid login challenge")
	}
	return rawURL.EncodeToString(ed25519.Sign(s.key, []byte(message))), nil
}
func VerifyChallenge(publicKey, message, signature string) bool {
	pub, err := ParsePublicKey(publicKey)
	if err != nil || len(message) > 4096 || !strings.HasPrefix(message, "iff-apostille/login/0.1\n") {
		return false
	}
	sig, err := rawURL.DecodeString(signature)
	return err == nil && len(sig) == 64 && rawURL.EncodeToString(sig) == signature && ed25519.Verify(pub, []byte(message), sig)
}
