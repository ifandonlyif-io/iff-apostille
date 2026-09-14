# Security policy

Report suspected vulnerabilities privately to `ben@tokimi.space`, the security
contact already published by the IFF organization for its public verification
projects. Once enabled, GitHub's **Security → Report a vulnerability** is another
private channel. Do not use public issues for unpublished bypasses or secrets.

Include the source revision/package version, affected component, a minimal
synthetic reproduction, expected and actual verification results, and whether
you believe a hosted service is affected. Never attach real keys, customer bot
records, private amounts, blinding values or proving-setup secrets.

This alpha has no support SLA, bounty commitment or external security audit.
Fixes target the current alpha; consumers must review upgrades and maintain
their own trust pins. Core and detached profiles are separately versioned.

Trust boundaries: verification is offline; embedded keys never bootstrap trust.
Exact issuer/key pins, agent/admin delegation and signed publication approval
are distinct controls. Login alone does not authorize publication. Claimed
timestamps cannot establish current non-revocation. A compromised producer can
sign false content; a compromised issuer can falsely describe its checks.

Local keyfiles are plaintext. Keep them outside the checkout and restrict access.
Never reuse synthetic fixture seeds. ZK source amounts and blinding remain private;
development setup is not an independent production ceremony. See the precise
[ZK limits](docs/apostille/ZK.md) and [Core specification](docs/apostille/spec/core-0.1.md).

Hosted API/server controls described in the API contract are outside this public
source snapshot. No security claim here establishes legal certification, content
truth, payment authority, TEE execution or the identity of a deployed binary.
