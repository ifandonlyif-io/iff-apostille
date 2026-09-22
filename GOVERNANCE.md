# Alpha governance

IFF repository maintainers review and merge changes during this alpha. This is
an open implementation and specification project, not an independent standards
body, issuer accreditation program or treaty-based recognition system.

Compatibility is checked through the published specification, shared vectors
and cross-language tests. Other implementations and issuers need no IFF account
or permission under the MIT License. Recipients choose which issuers/keys to
accept; publication in this repository never makes an issuer trusted.

Ordinary implementation fixes can use pull requests. Incompatible protocol
changes need a public proposal describing exact bytes and migration, followed
by a new profile/version namespace. Experimental profiles remain explicitly
labelled until their own validation and security requirements are met.

At launch, name the maintainers who actually accept review/release duties in
GitHub access settings. Do not advertise a council, independent membership,
service-level commitment or recognized-issuer list that does not exist.

This repository is the source of truth for the protocol, the Go and JavaScript
implementations, the CLI and the experimental ZK module. Since `v0.1.0-alpha.1`
the hosted application consumes the released Go module at a pinned version and
copies the served browser assets from that module with a checked script; it
keeps no copy of this code. A change reaches the hosted service only through a
new tag here and a reviewed pin bump there, never by copying files in either
direction.
