# Hosted issuer key pins

Operator announcement recorded on **2026-10-10 (Asia/Taipei)**.

Exact issuer: `https://ifandonlyif.io/apostille`

| Hosted Core version | Signature algorithm | Issuer key ID |
| --- | --- | --- |
| Core 0.1 | Ed25519 | `sha256:7a883829025400fc44dc4f2236b76484b30631a3f2b7e89c3258be3c71e741b2` |
| Core 0.3 | ML-DSA-65 | `sha256:66b3ed555cb24c41df445136db88ff601ac59318624476f0f09e9b3879de6e44` |

The new ML-DSA-65 issuer key was generated locally. Its key ID was recomputed
from the public key and matched the public API directory. The existing Ed25519
pin matched the value derived from the configured production signer. These are
operator-recorded checks, not an independent certification of the operator.

## Receiver trust policy

Each recipient decides independently whether to trust this repository as the
source of issuer pins. If that decision is accepted, retain a copy of this file
at a reviewed, fixed Git commit and configure the exact issuer together with the
selected key IDs in `TrustedKeyIDs` (Go) or `trustedKeyIDs` (JavaScript). Do not
silently update that policy by following the repository's default branch.

The online key directory supplies public keys for comparison; fetching it never
establishes trust or adds pins automatically. Offline verification never fetches
the directory, status, schemas or provider evidence. Retain historical pins when
keys change so historical signatures can still be checked. This announcement is
not a signed key history or a current revocation statement.

A matching issuer pin can establish `issuer_trust: accepted_by_policy`. It does
not establish organization identity or content truth, and current revocation
remains unknown. Freshness and the receiver's accepted-protocol policy remain
separate checks. Core 0.3's ML-DSA-65 signatures are post-quantum; this is not a
claim that the entire service is post-quantum. SHA-256 digest collision strength
is bounded at NIST category 2. See the [Core 0.3 security level](spec/core-0.3.md#security-level-receiver-policy-and-versioning).

## Hosted availability and deployment verification

On 2026-10-10 (Asia/Taipei), the hosted API accepted Core 0.1 and Core 0.3.
Core 0.2 remains a local signing/verification profile and is never issued by the
hosted service. Check the target service's `GET /status` `protocols` for runtime
availability; the default `/keys` directory remains Ed25519, while the explicit
Core 0.3 selector returns the ML-DSA-65 directory. See the [API contract](API.md).

The operator recorded successful deployment checks for:

- Login, private issuance, authenticated download and local bundle verification
  for both Core 0.1 and Core 0.3.
- Preservation of historical Core 0.1 bundles.
- Cross-tenant access returning HTTP 404.
- Status and key-directory responses, including both supported protocols and
  the corresponding issuer, algorithm, public key and key ID.

These checks cover API/client flows; they do not record completed browser
acceptance testing. Core 0.1 remains supported. An ML-DSA-65 administrator key
starts its own workspace; it does not migrate the agents, certificates or public
profile of an existing Ed25519 workspace. Retain that administrator key for
access to its workspace and the Ed25519 issuer pin for historical verification.
