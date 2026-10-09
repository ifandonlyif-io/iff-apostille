package apostille

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"time"
)

// CreateRegistration creates an administrator delegation and agent proof of
// possession locally. It does not register with or send anything to a service.
// It signs the administrator's natural version (Core 0.1 for Ed25519, Core 0.3
// for ML-DSA-65) and refuses an agent key of the other algorithm;
// CreateRegistrationFor takes the version explicitly.
func CreateRegistration(admin, agent *Signer, audience string, validFor time.Duration, now time.Time) (AgentRegistration, error) {
	return CreateRegistrationFor(admin.NaturalProtocol(), admin, agent, audience, validFor, now)
}

// CreateRegistrationFor is CreateRegistration for a known protocol version.
func CreateRegistrationFor(protocol string, admin, agent *Signer, audience string, validFor time.Duration, now time.Time) (AgentRegistration, error) {
	if _, err := profileFor(protocol); err != nil {
		return AgentRegistration{}, err
	}
	if !admin.Enabled() || !agent.Enabled() || now.IsZero() || validFor < time.Second || validFor > 365*24*time.Hour {
		return AgentRegistration{}, errors.New("enabled keys, issuance time and 1s–365d validity are required")
	}
	id, err := NewID()
	if err != nil {
		return AgentRegistration{}, err
	}
	d := Delegation{Header: headerFor(protocol, KindDelegation, KeyIdentity(admin.KeyID()), admin, now), AgentID: id, AgentKeyID: agent.KeyID(), AgentPublicKey: agent.PublicKey(), ServiceAudience: audience, NotBefore: now.UTC().Format(TimestampLayout), ExpiresAt: now.Add(validFor).UTC().Format(TimestampLayout), Scopes: []string{"sign_origin_statement"}}
	de, err := admin.SignFor(protocol, KindDelegation, d)
	if err != nil {
		return AgentRegistration{}, err
	}
	digest, err := EnvelopeDigest(de)
	if err != nil {
		return AgentRegistration{}, err
	}
	ae, err := agent.SignFor(protocol, KindAcceptance, Acceptance{Header: headerFor(protocol, KindAcceptance, KeyIdentity(agent.KeyID()), agent, now), AgentID: id, DelegationSHA256: digest})
	if err != nil {
		return AgentRegistration{}, err
	}
	return AgentRegistration{Delegation: de, Acceptance: ae}, nil
}

// CreateStatement streams the caller's exact artifact bytes without storing or
// uploading them. Supply a registration, or a producer-only agent UUID (not both).
// It signs the agent's natural version (Core 0.1 for Ed25519, Core 0.3 for
// ML-DSA-65) and refuses a registration of another version;
// CreateStatementFor takes the version explicitly.
func CreateStatement(reader io.Reader, mediaType string, agent *Signer, reg *AgentRegistration, agentID string, now time.Time) (Envelope, error) {
	return CreateStatementFor(agent.NaturalProtocol(), reader, mediaType, agent, reg, agentID, now)
}

// CreateStatementFor is CreateStatement for a known protocol version. It
// refuses to bind the statement to a delegation of another version, so a
// signer never emits a bundle the no-mixing rule would reject.
func CreateStatementFor(protocol string, reader io.Reader, mediaType string, agent *Signer, reg *AgentRegistration, agentID string, now time.Time) (Envelope, error) {
	if _, err := profileFor(protocol); err != nil {
		return Envelope{}, err
	}
	if reader == nil || !agent.Enabled() || now.IsZero() || (reg == nil) == (agentID == "") {
		return Envelope{}, errors.New("artifact, enabled agent, time and exactly one registration or agent ID are required")
	}
	digest := ""
	if reg != nil {
		if reg.Delegation.Protocol != protocol {
			return Envelope{}, errors.New("delegation protocol differs from the statement protocol")
		}
		d, err := VerifyRegistration(*reg, "", now)
		if err != nil {
			return Envelope{}, err
		}
		if d.AgentKeyID != agent.KeyID() {
			return Envelope{}, errors.New("agent key does not match delegation")
		}
		agentID = d.AgentID
		digest, err = EnvelopeDigest(reg.Delegation)
		if err != nil {
			return Envelope{}, err
		}
	}
	if !ValidID(agentID) {
		return Envelope{}, errors.New("invalid agent ID")
	}
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	h := sha256.New()
	size, err := io.Copy(h, reader)
	if err != nil {
		return Envelope{}, err
	}
	nonce, err := NewID()
	if err != nil {
		return Envelope{}, err
	}
	return agent.SignFor(protocol, KindStatement, Statement{Header: headerFor(protocol, KindStatement, KeyIdentity(agent.KeyID()), agent, now), AgentID: agentID, DelegationSHA256: digest, ArtifactSHA256: hex.EncodeToString(h.Sum(nil)), ArtifactSize: strconv.FormatInt(size, 10), ArtifactMediaType: mediaType, Nonce: nonce})
}

// CreateGrant creates an explicit five-minute authorization for one statement,
// registration, audience and visibility. It never makes a network request.
// It signs the administrator's natural version (Core 0.1 for Ed25519, Core 0.3
// for ML-DSA-65); CreateGrantFor takes the version explicitly.
func CreateGrant(statement Envelope, reg AgentRegistration, admin *Signer, audience, visibility string, now time.Time) (Envelope, error) {
	return CreateGrantFor(admin.NaturalProtocol(), statement, reg, admin, audience, visibility, now)
}

// CreateGrantFor is CreateGrant for a known protocol version. The statement and
// the registration must carry that version.
func CreateGrantFor(protocol string, statement Envelope, reg AgentRegistration, admin *Signer, audience, visibility string, now time.Time) (Envelope, error) {
	if _, err := profileFor(protocol); err != nil {
		return Envelope{}, err
	}
	if !admin.Enabled() || now.IsZero() {
		return Envelope{}, errors.New("enabled administrator and issuance time required")
	}
	if statement.Protocol != protocol || reg.Delegation.Protocol != protocol {
		return Envelope{}, errors.New("statement and delegation must carry the grant protocol")
	}
	d, err := VerifyRegistration(reg, audience, now)
	if err != nil {
		return Envelope{}, err
	}
	if d.IssuerKeyID != admin.KeyID() {
		return Envelope{}, errors.New("administrator key does not match delegation")
	}
	if _, err := VerifyBundle(Bundle{Protocol: protocol, Statement: statement, Delegation: &reg.Delegation, Acceptance: &reg.Acceptance}, VerifyOptions{}); err != nil {
		return Envelope{}, err
	}
	sh, err := EnvelopeDigest(statement)
	if err != nil {
		return Envelope{}, err
	}
	dh, err := EnvelopeDigest(reg.Delegation)
	if err != nil {
		return Envelope{}, err
	}
	nonce, err := NewID()
	if err != nil {
		return Envelope{}, err
	}
	return admin.SignFor(protocol, KindGrant, PublicationGrant{Header: headerFor(protocol, KindGrant, KeyIdentity(admin.KeyID()), admin, now), StatementSHA256: sh, DelegationSHA256: dh, ServiceAudience: audience, Visibility: visibility, Purpose: "issue_origin_certificate", ExpiresAt: now.Add(5 * time.Minute).UTC().Format(TimestampLayout), Nonce: nonce})
}
