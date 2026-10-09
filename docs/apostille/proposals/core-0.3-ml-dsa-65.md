# Proposal — Core 0.3: ML-DSA-65 signatures

Status: proposal drafted and accepted by the owner on 2026-10-09 as the basis
for [the implementation plan](core-0.3-implementation-plan.md). The normative
text is [`spec/core-0.3.md`](../spec/core-0.3.md), accepted the same day, and
governs where the two differ. Nothing is implemented yet; the plan's status
table says what has landed. Core 0.1 and Core 0.2, their vectors and their case
files stay exactly as published; a 0.1 or 0.2 signature is never reinterpreted
under these rules.

## Why a new version

Every signature that Core 0.1 and 0.2 define is Ed25519, so a cryptographically
relevant quantum computer could forge any of them for any key whose public half
is known. Every envelope publishes its key. Apostille evidence is meant to stay
checkable for years. NIST IR 8547 (initial public draft) lists EdDSA at 128 bits
and above as disallowed after 2035. Changing the signature algorithm changes the
signed bytes, so `GOVERNANCE.md` and `core-0.1.md` require a new version
namespace: a verifier must learn the algorithm from signed material, not from
context.

## Decisions taken before drafting (owner, 2026-10-09)

1. **Algorithm: pure ML-DSA-65** (FIPS 204), alone, not a composite with
   Ed25519. Reasons:
   - **References stay exact.** `statement_sha256` and `delegation_sha256` hash
     the entire envelope, signature included. ML-DSA is strongly unforgeable. A
     composite stops being strongly unforgeable once either component can be
     forged, because a fresh valid component then yields a second valid envelope
     for the same content, with a different digest.
   - **No glue to write.** Go 1.27 implements ML-DSA in the standard library, so
     no combiner code is written here.
   - **Margin.** Category 3 leaves margin over category 2.
2. **Version: Core 0.3**, defined as Core 0.2 with the signature algorithm
   replaced. 0.2's identifier grammar, version consistency and encoding rules
   apply unchanged. 0.2 keeps its accepted meaning (strict Ed25519). Because 0.2
   has no implementation yet, 0.2 and 0.3 are implemented together.
3. **Context.** Decided because no external user or issued certificate exists
   (hosted inventory, 2026-10-09). The hosted 0.1 alpha registrations are not
   migrated (see Migration).

## Version namespace (exact bytes)

- Protocol identifier: `https://ifandonlyif.io/apostille/spec/0.3`.
- Signature input for kind `K` and canonical payload bytes `P`:

  ```text
  UTF8("iff-apostille/" + K + "/0.3\n") || SHA256(P)
  ```

  `\n` is one LF byte; `||` is byte concatenation; `SHA256(P)` is the raw 32-byte
  digest. This is the 0.1 and 0.2 shape with a new domain string. Therefore no
  0.1 or 0.2 signature input is ever a 0.3 signature input, and a 0.3 signature
  input is never a valid 0.1 or 0.2 one.
- Envelope `signature.algorithm`: exactly the ASCII string `ML-DSA-65`. A 0.3
  envelope with any other value, and a 0.1 or 0.2 envelope with this value, are
  rejected.
- Version consistency: the four rules of `core-0.2.md` "Version, signature input
  and consistency" apply with "0.3" in place of "0.2". A 0.3 bundle containing a
  0.1 or 0.2 envelope or payload is invalid, and a 0.3 grant cannot name a
  statement or delegation of another version.

## Signature algorithm (exact bytes)

**Parameter set.** ML-DSA-65 as specified in FIPS 204: public key 1952 bytes,
signature 3309 bytes.

**Signing.**
- Use pure ML-DSA, FIPS 204 Algorithm 2 `ML-DSA.Sign(sk, M, ctx)`, with `M` the
  signature input above and `ctx` the **empty string**. Thus
  `M' = 0x00 || 0x00 || M`.
- Do not use HashML-DSA (Algorithm 4) or an external μ.
- The domain separation lives in `M`. A signature made with a non-empty context
  does not verify.
- Signers MUST use the hedged variant with fresh randomness (FIPS 204 default).
  The deterministic variant is permitted only for published test vectors.
  Verifiers do not distinguish the two.

**Verification.**
- FIPS 204 Algorithm 3 `ML-DSA.Verify(pk, M, σ, ctx)` with the empty context,
  including every decoding check it specifies (for example hint-encoding
  validity and the norm bound on `z`).
- An implementation MUST reject a decoded public key that is not exactly 1952
  bytes and a decoded signature that is not exactly 3309 bytes, before any other
  work.

**Encodings.** Canonical unpadded base64url, as in 0.1:
- `signature.public_key` is exactly 2603 characters.
- `signature.value` is exactly 4412 characters.
- A delegation's `agent_public_key` is exactly 2603 characters and is an
  ML-DSA-65 key.

Re-encoding the decoded bytes MUST reproduce the input string, so trailing-bit
variants fail.

**Key IDs.** `sha256:` followed by the lowercase hex SHA-256 of the raw 1952-byte
public key, so the 0.1 derivation is reused over the new key bytes. The key actor
identity remains `urn:apostille:key:<key_id>`. A key ID does not name its
algorithm. The version does, and an Ed25519 key (32 bytes) and an ML-DSA-65 key
(1952 bytes) cannot share an ID without a SHA-256 collision.

**Key validity.** Every 1952-byte string is a decodable ML-DSA-65 public key, so
0.2 Rule B has no counterpart. 0.2 "Strict Ed25519 verification" does not apply
to 0.3 artifacts.

**Limits.** The 0.1 input limits are unchanged: 262144 bytes of input, 131072
decoded payload bytes, depth 24.
- A full 0.3 bundle (statement, delegation, acceptance, certificate) is about
  35 KB, well inside 262144.
- Field-length checks on `public_key` and `value` happen before base64 decoding
  and before verification.

## Login challenge 0.3 (hosted registration profile)

A 0.3 administrator key is ML-DSA-65, so its login proof is too.
- Challenge prefix: `iff-apostille/login/0.3\n`.
- Maximum message length: 4096 bytes, as in 0.1.
- The signature is pure ML-DSA-65 with the empty context over the exact UTF-8
  message bytes, hedged. It is 3309 bytes, encoded as 4412 characters.

The login domain is distinct from every artifact domain. A login signature still
cannot substitute for a publication grant. A login key and the version of the
registrations it controls agree: a 0.3 admin key administers 0.3 delegations
only.

## Private key files (reference tools)

An ML-DSA-65 private key is the 32-byte FIPS 204 seed `ξ`. That is the same length
as an Ed25519 seed, so the key file, not the seed, must say which algorithm a
seed is for. Using one seed with both algorithms must be impossible.

The reference CLI, SDK and MCP keep the existing JSON key file,
`{protocol, key_id, public_key, seed}` with an optional `role`, and let its
`protocol` member select the algorithm:

- A file whose `protocol` is the 0.1 identifier holds an Ed25519 seed. As the
  0.2 plan already decided, it signs 0.1 and 0.2.
- A file whose `protocol` is the 0.3 identifier holds an ML-DSA-65 seed and signs
  0.3 only. Its `public_key` is 2603 characters and its `key_id` is the 0.3 key
  ID.
- On import, the public key is derived from the seed under the algorithm the file
  names, and must equal both `public_key` and `key_id`. A seed moved into a file
  of the other type therefore fails unless its metadata is deliberately
  recomputed.
- Any other `protocol` value is refused.
- The 4 KiB file limit and the owner-only permission check are unchanged. A 0.3
  key file is about 2.8 KB.
- This is a tool format, not a wire format. Independent implementations may store
  keys differently.

## Security level and the SHA-256 bound

0.3 keeps SHA-256 for `payload_sha256`, envelope references, artifact digests
and key IDs, and for the digest inside the signature input. Forging a 0.3
signature on a new message requires breaking ML-DSA-65 (category 3). An attack
that needs a SHA-256 collision is bounded at NIST category 2, which is defined by
SHA-256 collision search. Examples are substituting an artifact or envelope
behind an existing reference. Changing every digest would rename fields across
the format and its consumers. It is left to a later version, which must again
use a new namespace.

**Residual risk.** If ML-DSA were broken classically, 0.3 artifacts would have no
second signature to fall back on. Apostille artifacts are not registered in a
transparency log or anchored (`log_inclusion=not_registered`,
`anchor=not_requested`), so nothing hash-based records their existence either. A
later profile can register certificates in the IFF log, whose daily anchors are
hash-based. Until then this risk is accepted, not mitigated.

## Receiver policy, downgrade, privacy

- A receiver MAY restrict accepted versions, as in 0.2. A receiver that requires
  post-quantum signatures MUST accept only 0.3. With no restriction, a forged 0.1
  or 0.2 artifact could still report `artifact_integrity=valid`.
- Trust still requires an exact issuer **and** key pin. A receiver that pins only
  ML-DSA-65 issuer keys never returns `accepted_by_policy` for a 0.1 or 0.2
  certificate, whatever the integrity result.
- No field is added; linkability is as in 0.1. ML-DSA public keys are larger but
  no less linkable than Ed25519 keys.

## Vectors

The reference implementation publishes:
- `testdata/apostille/core-0.3.json`: a known-answer bundle from public test
  seeds, signed with the deterministic variant.
- `testdata/apostille/core-0.3-cases.json`: accept and reject cases in the 0.1
  case-file format.

The case file includes, each with a real signature wherever one can be built so
that only the named rule fails:
- Every 0.2 case category that does not depend on Ed25519, under the 0.3
  namespace. That covers encoding, identifiers, fields, relationships and
  version consistency.
- A hedged (non-deterministic) signature over the known-answer content, which
  MUST be accepted.
- Public key and signature lengths of ±1 byte, ML-DSA-44 and ML-DSA-87 sizes,
  and non-canonical base64url.
- `algorithm` variants: `ml-dsa-65`, `MLDSA65`, `ML-DSA-65 ` and `Ed25519`.
- A signature made with a non-empty context, a HashML-DSA signature, a signature
  over the 0.2 domain, and a 0.2 Ed25519 envelope relabelled 0.3.
- Malformed signature encodings from Wycheproof ML-DSA-65 test groups (invalid
  hint encoding, `z` out of range), re-signed into envelopes where the format
  allows.
- An Ed25519 key in a 0.3 envelope and in a 0.3 delegation's `agent_public_key`.
- Cross-version bundles: a 0.2 or 0.1 envelope in a 0.3 bundle, and a 0.3 grant
  naming a 0.2 statement.

An implementation claims 0.3 conformance by verifying the known-answer bundle
and returning the expected result for every case. The 0.1 and 0.2 vector files
are unchanged.

## Migration

1. Publish the specification and vectors. Go and JS verify 0.1, 0.2 and 0.3,
   selected by `bundle.protocol`. The 0.1 path does not change.
2. SDK, CLI and MCP gain explicit signing versions 0.2 and 0.3, and typed 0.3 key
   files. Signing fails early when versions would mix.
3. The hosted service adds the following and certifies a 0.3 statement with a
   0.3 certificate:
   - an ML-DSA-65 issuer key, published beside the existing Ed25519 key, which
     stays listed for 0.1 verification;
   - 0.3 login;
   - 0.3 registration, grant validation and issuance;
   - field and request limits sized for ML-DSA.
4. Alpha registrations are not migrated. A 0.3 login with a new ML-DSA-65 admin
   key creates a new workspace. The two existing 0.1 workspaces have no agents or
   certificates. Their owners register again, and the alpha notice says so before
   the switch.
5. The default signing version moves from 0.1 directly to 0.3 once step 3 is
   deployed, on a date announced in advance. With no registrations to move, 0.2
   decision 10's gate reduces to "hosted issues 0.3". 0.2 stays available behind
   the explicit option for independent issuers. Hosted 0.1 issuance stops at the
   switch.
6. 0.1 and 0.2 artifacts stay verifiable under their own rules indefinitely.
   Nothing is re-signed.

## Out of scope (separate proposals)

- The IFF transparency log, STH, monitor observations and Service Receipt
  signatures. A new log epoch for these is planned in `iff-trust-oracle`.
- The ERC-8004 binding profile. Its admin signature is Ed25519, so a 0.3
  registration needs a binding profile 0.2 with an ML-DSA-65 admin signature.
  Until then, ERC-8004 binding is available for 0.1 registrations only.
- The ZK budget profile, which stays experimental and tied to 0.1 statements.
- Changing digests away from SHA-256.

## Decisions recorded on acceptance (2026-10-09)

1. **Accepted as drafted.**
2. **Browser signing is allowed for the alpha.** The browser signs with the
   vendored `@noble/post-quantum`. The UI and the documentation state that it is
   not independently audited and does not claim constant-time signing. The CLI,
   which uses the Go standard library, is the recommended path for administrator
   keys.
3. **Still open:** the switch date in Migration step 5, and the wording and
   placement of the alpha notice. Both gate the default switch, not the
   implementation.

## Implementation notes (not normative)

- **Go.** `crypto/mldsa` (Go 1.27): `NewPrivateKey(MLDSA65(), seed)`,
  `(*PrivateKey).Sign(nil, M, &Options{})` (hedged; the reader argument is
  ignored), `SignDeterministic` for vectors, and
  `Verify(pk, M, sig, &Options{})`. The root module moves to `go 1.27.0` with
  toolchain `go1.27.2`. The nested modules, the hosted service and Apostille
  Local need Go 1.27 when they next bump their pin of the root module; their
  current 0.1 pins are unaffected.
- **JS.** Vendor `@noble/post-quantum` 0.7.1 (2026-08-27) ML-DSA and the exact
  `@noble/hashes` files it imports into `web/`, pinned with notices in
  `docs/apostille/NOTICES.md`. Keep `script-src 'self'` and the offline
  `connect-src 'none'`. Confirm that its `ml_dsa65` accepts an explicit empty
  context, keygen from a 32-byte seed, and rejects the Wycheproof malformed
  encodings. The Go/JS differential suite runs at 0.3.
- **Shared work with 0.2.** Version selection, the identifier grammar and
  no-mixing are written once and serve 0.2 and 0.3. Strict Ed25519 applies to
  0.2 only.
- **Hosted limits.** Raise the login signature guard (128 characters today) to
  4412. Admin and agent key columns must hold 2603 characters. Request body and
  stored bundle limits must allow about 40 KB per bundle. Inventory these in
  `iff-trust-oracle` before deploying.
