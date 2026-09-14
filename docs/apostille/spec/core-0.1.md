# Apostille Core 0.1 — draft alpha

Status: experimental reference profile, 2026-09-14. Original specification,
schemas, vectors and reference implementations are licensed under the repository
MIT LICENSE. This is not a standards-body specification or a legal Apostille.
The English specification is normative; translated product explanations retain
the same artifact names and wire keywords.

## Purpose and profiles

Apostille binds a producer signature to an exact artifact digest. An optional
issuer signs an `origin-certificate` after checking that signature and any
included administrator delegation. Any operator may implement or issue this
format without an IFF account, wallet, chain connection or IFF permission.

The protocol identifier is `https://ifandonlyif.io/apostille/spec/0.1`. It names
the format, not the issuer, trust authority, or a URL a verifier should fetch.
The IFF hosted issuer is normally `https://ifandonlyif.io/apostille`; independent
issuers use their own exact URI. Certificate identity is `(issuer, certificate_id)`.

Core supports a producer-only statement and an optional origin certificate.
The hosted registration profile adds `agent-delegation`, `agent-acceptance` and
`publication-grant`. Unknown versions, kinds, algorithms or fields MUST fail
closed. Extensions require a new version/profile; there are no ignored security
fields or dynamically loaded adapters in 0.1.

## Encoding and signature

Inputs are UTF-8 JSON, at most 262144 bytes, with depth at most 24. Reject duplicate
properties (including escaped-equivalent names), malformed UTF-8, unpaired
surrogates, trailing JSON, and **all JSON numeric values**. Exact quantities are
decimal strings. No Unicode normalization is performed. Payload fields are all
required and never null. Optional bundle attachments are explicit nulls.

Canonical payload bytes use the RFC 8785 JSON Canonicalization Scheme, restricted
to strings, booleans, null, arrays and objects. Property order is UTF-16 code-unit
order; string escapes follow JSON serialization. The signed payload must already
be canonical. Outer bundle/envelope JSON may have insignificant whitespace and
property reordering; field names are exact and case-sensitive.

Hash is SHA-256, written as 64 lowercase hexadecimal characters. Public-key IDs
are `sha256:` followed by the hash of the raw 32-byte Ed25519 public key. All
binary fields use canonical, unpadded base64url. Ed25519 signatures are 64 bytes.

For a kind `K` and canonical payload bytes `P`, the exact signature input is:

```text
UTF8("iff-apostille/" + K + "/0.1\n") || SHA256(P)
```

`\n` above is a single LF byte; `||` denotes byte concatenation. Sign this input
with Ed25519 (not Ed25519ph); do not sign a hex digest, JSON wrapper or signature
field. `iff-apostille` is the signature-format namespace, independent of issuer.
`payload_sha256` hashes `P`. References named `statement_sha256` and
`delegation_sha256` hash the **entire canonical envelope**, including its signature
and public key, not just `payload_sha256`.

An envelope has exactly:

```text
protocol, kind, payload, payload_sha256,
signature: { algorithm, key_id, public_key, value }
```

The embedded public key permits an integrity check only. Verify its fingerprint,
payload hash, canonical encoding, signature, kind, protocol and signed
`issuer_key_id`; then validate the kind-specific payload. Maximum decoded payload
size is 131072 bytes; encoded payload is additionally capped at 262144 characters.

## Common values

Every payload includes `protocol`, `kind`, `issuer`, `issuer_key_id`, `issued_at`.
Timestamps are exact UTC seconds `YYYY-MM-DDTHH:MM:SSZ` with valid calendar dates;
fractional seconds and alternate offsets are rejected. UUIDs/nonces are canonical
lowercase UUID v4. Key actor identity is `urn:apostille:key:<key_id>`.

An issuer or service audience is an exact, nonempty ASCII HTTPS or opaque URN
identifier, at most 256 bytes. No whitespace, credentials, query or fragment is
allowed. HTTPS hosts are lowercase; percent escapes, backslashes, empty ports,
default port 443 and noncanonical numeric ports are rejected. An identifier is
never normalized, resolved via DNS, or fetched during verification.

## Artifact registry and fields

The following fields are added to the common header. See the
[machine-readable structural schema](../../../web/apostille-0.1.schema.json); signatures and relationships require the
checks in this specification, not schema validation alone.

| Kind | Additional signed fields |
| --- | --- |
| `origin-statement` | `agent_id`, `delegation_sha256`, `artifact_sha256`, `artifact_size`, `artifact_media_type`, `nonce` |
| `agent-delegation` | `agent_id`, `agent_key_id`, `agent_public_key`, `service_audience`, `not_before`, `expires_at`, `scopes` |
| `agent-acceptance` | `agent_id`, `delegation_sha256` |
| `publication-grant` | `statement_sha256`, `delegation_sha256`, `service_audience`, `visibility`, `purpose`, `expires_at`, `nonce` |
| `origin-certificate` | `certificate_id`, `statement_sha256`, `delegation_sha256`, `source_key_id`, `expires_at`, `signature_check`, `agent_binding`, `organization_binding`, `content_truth` |

A statement's issuer MUST identify the signing agent key. Its artifact digest
and size cover the exact original bytes, with no line-ending or text conversion.
Size matches `0|[1-9][0-9]{0,18}`. Media type is at most 128 UTF-8 bytes, contains
`/`, and has no CR, LF or NUL. It is metadata, never an instruction to render or
execute a file. `delegation_sha256` is empty only for the producer-only key profile.

A delegation is signed by its administrator key actor. `agent_key_id` must match
`agent_public_key`; scopes are exactly `["sign_origin_statement"]`. Validity is
the half-open interval `[not_before, expires_at)`, with expiry after not-before.
The agent signs an acceptance binding this delegation's full envelope digest
and agent UUID. This establishes administrator-key authorization and agent key
possession, **not legal entity identity, legal authority, or observed bot activity**.

A publication grant is signed by the registered administrator key actor. It binds
the exact statement, delegation, destination issuer, visibility (`private` or
`public`) and `purpose="issue_origin_certificate"`. Hosted issuance rejects a
different administrator, audience or digest, expired grants, grants issued over
120 seconds in the future, and intervals over 15 minutes. Browser/CLI grants
last 5 minutes. The nonce is the hosted idempotency key. Login signatures cannot
substitute for grants. Profile visibility authorizes only the profile, not bot
artifacts, log registration, anchoring or deanonymization.

A certificate's `signature_check` is exactly `valid`; `organization_binding` is
`unproven` and `content_truth` is `not_established`. Its `agent_binding` is
`admin_key_delegation` when a delegation digest is present, otherwise
`not_provided`. `source_key_id` matches the statement signer. The certificate
must bind the exact statement and its delegation, not a similar artifact or URL.

## Bundle and verification algorithm

The bundle has exactly `protocol`, `statement`, `delegation`, `acceptance` and
`certificate`. `statement` is an envelope; the last three are envelopes or null.
Delegation and acceptance must either both be provided or both null. Their
presence must agree with the statement's delegation digest.

1. Parse and check the strict encoding and exact fields. Verify the source
   envelope and its key actor identity.
2. If delegated, verify both envelopes, agent ID/key, acceptance digest, source
   delegation digest and source key against the delegated key.
3. If no certificate exists, return `producer_only`. No issuer trust or freshness
   is established by this profile; a producer signature can still be checked.
4. Otherwise verify the certificate envelope and all source/digest/binding
   references. The statement time must not exceed certificate issue time by over
   120 seconds. If delegated, audience must equal certificate issuer; delegation
   must be active at certificate issue time; delegation and acceptance issue
   times must not exceed it by over 120 seconds; acceptance and statement times
   must not predate delegation not-before. Certificate expiry must not exceed
   delegation expiry. Certificate expiry must be after certificate issue time.
5. Evaluate trust independently: only an **externally supplied exact issuer AND
   allowed key fingerprint** can yield `accepted_by_policy`. No supplied policy
   yields `unknown`; an incomplete/mismatching policy yields `untrusted`.
6. If an evaluation time is supplied, report `not_yet_valid`, `expired` or
   `valid_at_evaluation_time` against the certificate's half-open interval. With
   no time, report `unknown`. Time is caller-supplied/local, not a trusted timestamp.
7. If original bytes are supplied, compare both digest and exact byte count.
   Without original bytes, valid signatures do not establish possession or
   integrity of the original file. Never execute or render its contents.

The reference issuer checks active delegation and future source time before
signing; its certificate lasts at most 24 hours and no longer than delegation.
The hosted service also checks tenant membership and current revocation inside
the submission transaction. Independent issuers implement their own access policy.
Self-issued certificates are permitted, but cannot be presented as independent
third-party checks merely because a second key was used.

## Result semantics and offline boundary

`artifact_integrity=valid` means supplied signed artifacts and their relationships
verify. `issuer_trust` is a separate policy decision. `certificate_scope` is
`producer_only` or `origin_signature_checked`. `organization_binding=unproven`,
`content_truth=not_established`, `provider_evidence=not_provided`,
`log_inclusion=not_registered` and `anchor=not_requested` are fixed in 0.1.

With a certificate, `authorization_policy=current_revocation_unknown` and
`time_basis=issuer_claimed_check_time`. Without one, they are `unknown` and
`producer_claimed`. This version has no signed status snapshots, TrustPack,
revocation proof, authenticated timestamp, SCITT receipt, Merkle or chain proof.
An offline verifier MUST NOT claim current authorization from a historical
delegation, or silently fetch keys, URLs, schemas, status, DNS or RPC evidence.

The browser verifier uses no external resources and `connect-src 'none'`;
downloaded ES modules are served from localhost or an existing isolated static
server. The CLI reads local files only. Neither requires an IFF account. Key pins
are acquired separately; downloading a key directory over HTTPS is an online
bootstrap choice, not proof that an embedded or cached key is currently trusted.

## Privacy and versioning

This alpha hashes original bytes without a salt. A digest is **not anonymization**:
predictable files can be guessed; public keys, UUIDs and exact timestamps permit
linkage. Hosted publication is explicit disclosure of the full signed bundle.
Private certificate hiding does not invalidate signatures or recall copies.
Publishing a redacted version will require a separately signed artifact and
approval; selective disclosure/redaction is not implemented by 0.1.

Specifications and conformance vectors stay versioned. Format-breaking changes
must use a new protocol/signature namespace; an old signature is never reinterpreted
under new rules. Coinbase verification, LEI, vLEI, Cloudflare Wallets, W3C VC/SCITT
adapters, recorder, anchoring and signed status have reserved roadmap space only.

## References

- RFC 8785: https://www.rfc-editor.org/rfc/rfc8785.html
- RFC 8032: https://www.rfc-editor.org/rfc/rfc8032.html
- Executable Go/browser vector: `testdata/apostille/core-0.1.json`.
- Conformance and limitations: `docs/apostille/CONFORMANCE.md`.
