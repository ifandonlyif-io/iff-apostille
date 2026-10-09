# Apostille Core 0.3 — draft alpha

Status: normative profile for 0.3 artifacts, accepted 2026-10-09 under
[GOVERNANCE.md](../../../GOVERNANCE.md). The Go and JavaScript reference implementations and the conformance
vectors (`testdata/apostille/core-0.3.json`, `core-0.3-cases.json`) are released in
`v0.3.0-alpha.1` (root Go module, 2026-10-09); the
[implementation plan](../proposals/core-0.3-implementation-plan.md) tracks what has landed.
[Core 0.1](core-0.1.md) and [Core 0.2](core-0.2.md) stay normative for their own
artifacts. Licensed under the repository MIT LICENSE. This is not a
standards-body specification or a legal Apostille. The English text is
normative. The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Purpose and relation to 0.2

Core 0.3 has the same purpose, artifacts, fields, digests, identifier grammar,
version-consistency rules and verification algorithm as Core 0.2. It differs in
exactly three places:

1. **Signatures.** Every artifact signature is ML-DSA-65 (FIPS 204), pure, with
   the empty context (section "ML-DSA-65 signatures"). The Core 0.2 section
   "Strict Ed25519 verification" does not apply to 0.3 artifacts.
2. **Keys.** Every key a 0.3 artifact carries is a 1952-byte ML-DSA-65 public
   key, with the encodings and key IDs of section "Keys".
3. **Login.** The hosted registration profile's login proof for a 0.3
   administrator key uses its own prefix and ML-DSA-65 (section "Login
   challenge").

Every rule of Core 0.2 not restated here applies unchanged, by reference to the
named section of `core-0.2.md`, and through it of `core-0.1.md`. Where this
document and `core-0.2.md` differ, this document governs for 0.3 artifacts only.
A 0.1 or 0.2 signature is never reinterpreted under 0.3 rules, and a 0.3
signature never under 0.1 or 0.2 rules.

The protocol identifier is `https://ifandonlyif.io/apostille/spec/0.3`. It names
the format, not an issuer, a trust authority or a URL to fetch. Unknown versions,
kinds, algorithms and fields MUST fail closed.

## Version, signature input and consistency

For a kind `K` and canonical payload bytes `P`, the signature input is:

```text
UTF8("iff-apostille/" + K + "/0.3\n") || SHA256(P)
```

`\n` is a single LF byte; `||` is byte concatenation; `SHA256(P)` is the raw
32-byte digest. `payload_sha256` hashes `P`. `statement_sha256` and
`delegation_sha256` hash the entire canonical envelope, including its signature
and public key. Because the domain string differs, a signature made for one
version does not verify under another.

`core-0.2.md` "Version, signature input and consistency" applies with "0.3" in
place of "0.2":
- The `protocol` member of a bundle, of every envelope and of every signed
  payload MUST be the 0.3 identifier.
- A verifier selects the rule set from the signed material and rejects mixed
  versions.
- A grant names only material of its own version.
- An issuer certifies a 0.3 source only with a 0.3 certificate.

A receiver MAY restrict the versions it accepts. The verification result reports
the bundle's version in `protocol`.

## Encoding

`core-0.2.md` "Encoding" applies, except for the sizes that name Ed25519:
- public keys are 1952 bytes, so their encoded form is exactly 2603 characters;
- signatures are 3309 bytes, so their encoded form is exactly 4412 characters;
- `signature.algorithm` is exactly `ML-DSA-65`.

All other limits are unchanged: input of at most 262144 bytes and depth 24,
decoded payloads of at most 131072 bytes, canonical unpadded base64url, and the
exact envelope members `protocol, kind, payload, payload_sha256, signature`. The
structural schema is
[`web/apostille-0.3.schema.json`](../../../web/apostille-0.3.schema.json); schema
validation alone is not conformance.

## ML-DSA-65 signatures

ML-DSA-65 is the FIPS 204 parameter set with 1952-byte public keys and 3309-byte
signatures.

**Signing.**
- A signer computes FIPS 204 Algorithm 2, `ML-DSA.Sign(sk, M, ctx)`, with `M` the
  signature input above and `ctx` the empty string. The message actually signed
  is therefore `M' = 0x00 || 0x00 || M`.
- HashML-DSA (FIPS 204 Algorithm 4), a pre-hashed message representative μ
  computed outside the signer, and any non-empty context MUST NOT be used.
- A signer MUST use the hedged variant with fresh randomness.
- The deterministic variant is permitted only to generate published test
  vectors.

**Verification.** A verifier MUST perform these steps in order and reject at the
first failure:

1. Check that `signature.public_key` is 2603 characters and `signature.value` is
   4412 characters.
2. Decode both as canonical unpadded base64url. Reject unless re-encoding
   reproduces the input string, the public key is exactly 1952 bytes and the
   signature is exactly 3309 bytes.
3. Accept if and only if FIPS 204 Algorithm 3, `ML-DSA.Verify(pk, M, σ, ctx)`,
   returns true for the empty context. This includes every check the algorithm
   specifies, among them the hint-encoding check and the norm bound on `z`.

Verifiers do not distinguish hedged from deterministic signatures. A signer
SHOULD verify its own output before releasing it.

This section defines conformance. Using a cryptographic library for ML-DSA is
expected. A library is conforming only if it implements FIPS 204 (final), not a
pre-standard Dilithium round, and accepts an explicit empty context.

## Keys

- **Key ID.** A 0.3 key ID is `sha256:` followed by the 64 lowercase hex
  characters of SHA-256 over the raw 1952-byte public key. The key actor identity
  remains `urn:apostille:key:<key_id>`. A key ID does not name an algorithm: the
  version determines it.
- **Where the key rules apply.** They apply wherever a 0.3 artifact carries a
  key: `signature.public_key` in each envelope and `agent_public_key` in a
  delegation. An artifact carrying a key of any other length or encoding is
  invalid.
- **No validity check beyond length.** Every 1952-byte string is a decodable
  ML-DSA-65 public key, so 0.3 has no counterpart to 0.2's point checks.
- **Private keys.** A private key is the 32-byte FIPS 204 seed `ξ`. Key storage
  is outside this specification.

Informative: an Ed25519 seed is also 32 bytes, and using one seed with both
algorithms MUST be avoided. The reference tools keep their JSON key file and let
its `protocol` member name the algorithm: the 0.1 identifier means Ed25519 (for
0.1 and 0.2), and the 0.3 identifier means ML-DSA-65 (for 0.3 only). On import,
the derived public key must match the stored one.

## Common values

`core-0.2.md` "Common values" applies unchanged, including the identifier
grammar.

## Artifact registry and fields

`core-0.1.md` "Artifact registry and fields" applies unchanged: the five kinds,
their fields, the statement, delegation, grant and certificate rules, and the
hosted issuance limits. In 0.3:
- every `issuer` and `service_audience` value is validated by the 0.2
  identifier grammar;
- every `agent_public_key` is an ML-DSA-65 public key as in section "Keys".

## Bundle and verification algorithm

`core-0.1.md` "Bundle and verification algorithm" applies with the changes
`core-0.2.md` makes, except that every signature check in steps 1, 2 and 4 is
ML-DSA-65 verification as defined above:

- Before step 1, apply the version consistency rules. A bundle that fails them
  is invalid, and no signature is checked.
- Every signature check is ML-DSA-65 verification. Every key is checked as in
  section "Keys".
- Every identifier check is the 0.2 identifier grammar. In step 4, the
  certificate's `issuer` and the delegation's `service_audience` are compared as
  exact bytes.
- The reference issuer MUST NOT issue a certificate over a source bundle of
  another version, and MUST reject a 0.3 registration that carries a key failing
  section "Keys".

Steps 5 to 7 (trust policy, freshness, original bytes) are unchanged.

## Login challenge

The hosted registration profile proves possession of an administrator key at
login. For a 0.3 administrator key:
- the challenge message starts with `iff-apostille/login/0.3\n` and is at most
  4096 bytes;
- the signature is pure ML-DSA-65 with the empty context over the exact UTF-8
  message bytes, hedged, encoded as 4412 characters.

The `iff-apostille/login/0.1\n` prefix stays Ed25519 for 0.1 and 0.2
administrator keys. The two prefixes are distinct from each other and from every
artifact domain, and a login signature cannot substitute for a publication grant.

A 0.3 administrator key administers 0.3 registrations only. The detached
ERC-8004 and ZK profiles keep their own namespaces and are not changed by this
document; they do not cover 0.3 registrations.

## Result semantics and offline boundary

`core-0.2.md` "Result semantics and offline boundary" applies unchanged, and the
result's `protocol` is the bundle's version.

ML-DSA-65 verification establishes that a signature was made with the holder of
the key's seed under the ML-DSA hardness assumptions. Like 0.2, it does not
establish content truth, organization identity, current non-revocation, log
inclusion or anchoring.

## Security level, receiver policy and versioning

- **Security level.** Forging a 0.3 signature on a new message requires breaking
  ML-DSA-65 (NIST category 3). Attacks that need a SHA-256 collision remain
  bounded at NIST category 2, because 0.3 keeps SHA-256 for payload digests,
  envelope references, artifact digests, key IDs and the digest in the signature
  input. A change of digest requires a new version namespace.
- **Requiring post-quantum signatures.** A receiver that requires post-quantum
  signatures MUST accept only 0.3. With no restriction, a forged 0.1 or 0.2
  artifact can still report `artifact_integrity=valid`. Issuer trust still
  requires an exact issuer and key pin, so a receiver that pins only ML-DSA-65
  keys never accepts a 0.1 or 0.2 certificate by policy.
- **Old artifacts.** A 0.1 or 0.2 artifact remains verifiable under its own rules
  indefinitely and is never re-signed.
- **Privacy.** No field is added. Identifiers, keys, UUIDs and timestamps remain
  as linkable as in 0.1.

## Conformance vectors

The reference implementation publishes:
- `testdata/apostille/core-0.3.json`: a known-answer bundle from public test
  seeds, signed with the deterministic variant;
- `testdata/apostille/core-0.3-cases.json`: accept and reject cases in the format
  of the 0.1 case file.

An implementation claims 0.3 conformance by verifying the known-answer bundle and
returning the expected result for every case. The case file MUST include the
following, with a real signature wherever one can be constructed so that only the
named rule fails:

- every 0.2 case category that does not depend on Ed25519, under the 0.3
  namespace;
- a hedged signature over the known-answer content (accepted);
- public keys and signatures one byte short and one byte long, and the ML-DSA-44
  and ML-DSA-87 sizes;
- non-canonical base64url;
- `algorithm` values `ml-dsa-65`, `MLDSA65`, `ML-DSA-65 ` and `Ed25519`;
- a signature with a non-empty context, a HashML-DSA signature, and a signature
  over the 0.2 domain;
- malformed signature encodings taken from Wycheproof ML-DSA-65 tests;
- an Ed25519 key as `signature.public_key` and as `agent_public_key`;
- cross-version bundles and grants.

The 0.1 and 0.2 vector files are unchanged.

## References

- FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
- RFC 8785: https://www.rfc-editor.org/rfc/rfc8785.html
- Core 0.1: `docs/apostille/spec/core-0.1.md`
- Core 0.2: `docs/apostille/spec/core-0.2.md`
- Proposal and decisions: `docs/apostille/proposals/core-0.3-ml-dsa-65.md`
- Implementation plan: `docs/apostille/proposals/core-0.3-implementation-plan.md`
