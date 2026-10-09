package main

import (
	"errors"
	"flag"
	"fmt"
	"path"
	"strings"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
)

// parseProtocol maps "0.1", "0.2", "0.3" or a full protocol identifier to a
// known protocol identifier.
func parseProtocol(value string) (string, error) {
	for _, known := range core.KnownProtocols() {
		if value == known || value == path.Base(known) {
			return known, nil
		}
	}
	return "", fmt.Errorf("unsupported protocol %q: use 0.1, 0.2, 0.3 or a full protocol identifier", value)
}

// protocolAuto is the --protocol value that signs the key file's own version.
const protocolAuto = "auto"

// parseProtocolChoice is parseProtocol that also accepts "auto".
func parseProtocolChoice(value string) (string, error) {
	if value == protocolAuto {
		return protocolAuto, nil
	}
	protocol, err := parseProtocol(value)
	if err != nil {
		return "", fmt.Errorf("unsupported protocol %q: use auto, 0.1, 0.2, 0.3 or a full protocol identifier", value)
	}
	return protocol, nil
}

// naturalProtocol is the Core version a key signs when none is named: Core 0.1
// for an Ed25519 key and Core 0.3 for an ML-DSA-65 key (what the root module's
// Signer.NaturalProtocol reports).
func naturalProtocol(signer *core.Signer) string {
	if signer.Algorithm() == core.Algorithm03 {
		return core.Protocol03
	}
	return core.Protocol
}

// resolveProtocol turns a parsed --protocol choice into a protocol identifier:
// "auto" is the signing key's natural version, anything else is kept.
func resolveProtocol(choice string, signer *core.Signer) string {
	if choice == protocolAuto {
		return naturalProtocol(signer)
	}
	return choice
}

// protocolList is a repeatable flag collecting protocol versions.
type protocolList []string

func (l *protocolList) String() string { return strings.Join(*l, ",") }

func (l *protocolList) Set(value string) error {
	protocol, err := parseProtocol(value)
	if err != nil {
		return err
	}
	*l = append(*l, protocol)
	return nil
}

var _ flag.Value = (*protocolList)(nil)

// protocolLabel names a protocol as a user-facing "Core 0.x"; unknown
// identifiers are not echoed.
func protocolLabel(protocol string) string {
	for _, known := range core.KnownProtocols() {
		if protocol == known {
			return "Core " + path.Base(known)
		}
	}
	return "an unsupported protocol"
}

// algorithmFor returns the signature algorithm a protocol's signatures use.
func algorithmFor(protocol string) string {
	if protocol == core.Protocol03 {
		return core.Algorithm03
	}
	return core.Algorithm
}

// requireKeyFor refuses a key whose algorithm does not match the protocol,
// before anything is signed.
func requireKeyFor(protocol string, signer *core.Signer) error {
	if signer.Algorithm() == algorithmFor(protocol) {
		return nil
	}
	return fmt.Errorf("%s needs an %s key file, but the key file is %s",
		protocolLabel(protocol), algorithmFor(protocol), signer.Algorithm())
}

// requireSameProtocol refuses to mix a Core version with an artifact of another.
func requireSameProtocol(protocol, artifactKind, artifactProtocol string) error {
	if artifactProtocol == protocol {
		return nil
	}
	return fmt.Errorf("%s is %s but the command selects %s; versions must not mix",
		artifactKind, protocolLabel(artifactProtocol), protocolLabel(protocol))
}

var errCore01Only = errors.New("covers Core 0.1 only")

// requireCore01 refuses an input of another Core version for a profile that
// covers Core 0.1 only.
func requireCore01(profile, what, protocol string) error {
	if protocol == core.Protocol {
		return nil
	}
	return fmt.Errorf("%s is %s: the %s %w", what, protocolLabel(protocol), profile, errCore01Only)
}

func requireBundleCore01(profile, what string, bundle core.Bundle) error {
	if err := requireCore01(profile, what, bundle.Protocol); err != nil {
		return err
	}
	if err := requireCore01(profile, what+" statement", bundle.Statement.Protocol); err != nil {
		return err
	}
	for _, attached := range []*core.Envelope{bundle.Delegation, bundle.Acceptance, bundle.Certificate} {
		if attached != nil {
			if err := requireCore01(profile, what+" "+attached.Kind, attached.Protocol); err != nil {
				return err
			}
		}
	}
	return nil
}

// erc8004ProfilesFor maps accepted Core versions to the ERC-8004 binding
// profiles over them. An empty list accepts every known binding profile; Core
// 0.2 has no binding profile.
func erc8004ProfilesFor(accepted protocolList) ([]string, error) {
	if len(accepted) == 0 {
		return core.KnownERC8004Profiles(), nil
	}
	profiles := make([]string, 0, len(accepted))
	for _, protocol := range accepted {
		switch protocol {
		case core.Protocol:
			profiles = append(profiles, core.ERC8004Profile)
		case core.Protocol03:
			profiles = append(profiles, core.ERC8004Profile03)
		default:
			return nil, fmt.Errorf("--accept-protocol %s: no ERC-8004 binding profile exists for that Core version; use 0.1 or 0.3", protocolLabel(protocol))
		}
	}
	return profiles, nil
}
