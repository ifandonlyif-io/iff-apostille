# Core 0.3 implementation plan

This plan implements [`spec/core-0.3.md`](../spec/core-0.3.md) (ML-DSA-65), accepted
2026-10-09 with [its proposal](core-0.3-ml-dsa-65.md). Core 0.3 is Core 0.2 with
the signature algorithm replaced, so this plan runs alongside the
[Core 0.2 implementation plan](core-0.2-implementation-plan.md):

- 0.2's contracts C1 to C8 and its executor gotchas apply here too.
- This document records only what 0.3 adds or changes.
- Each 0.3 phase lands with, or after, the 0.2 phase of the same number.

Each phase starts with the main model writing a handoff specification. A
Sonnet-class agent implements it, and the main model reviews the result against
the acceptance criteria before the status table changes.

## Status

| Phase | Scope | Status | Note |
| --- | --- | --- | --- |
| 1 | `spec/core-0.3.md` + `web/apostille-0.3.schema.json` | ✅ DONE | Accepted 2026-10-09; the schema is the 0.2 schema with 16 lines changed (`$id`, title, protocol constants, algorithm, key and signature lengths) |
| 2 | Go: 0.3 profile, ML-DSA-65 signer and verifier, 0.3 key files, login 0.3 helpers, 0.3 vectors | ✅ DONE | Landed 2026-10-09; see Phase 2 outcome |
| 3 | JS: vendored `@noble/post-quantum`, 0.3 verify and sign, consumers for 0.3 vectors, Go/JS differential at 0.3 | ⬜ pending | Lands with 0.2 Phase 3 |
| 4 | CLI, browser verifier and signing UI (with the signing disclosure), docs, notices | ⬜ pending | New UI strings need reviewed translations in four locales |
| 5 | Release tags for the root and nested modules | ⬜ pending | The user decides the tag names |
| 6 | Hosted service and API client (`iff-trust-oracle`) | ⬜ pending | External; ML-DSA issuer key provisioned by the owner |
| 7 | Default signing version switches from 0.1 to 0.3 | ⬜ pending | Gated on Phase 6 deployed, the announced date and the alpha notice |

## Approved decisions (do not relitigate)

1. **Pure ML-DSA-65**, FIPS 204 Algorithm 2 and 3, with the empty context.
   Signing is hedged. The deterministic variant is used for published vectors
   only. No composite, no HashML-DSA, no external μ.
2. **Core 0.3 = Core 0.2 with the signature algorithm replaced.** Domain
   `iff-apostille/<kind>/0.3` followed by LF, over `SHA256(P)` as in 0.1/0.2.
   Algorithm string `ML-DSA-65`. Key IDs are `sha256:` over the 1952-byte key.
3. **SHA-256 stays** for every digest. The category 2 bound is documented, not
   fixed.
4. **Key files keep the JSON format.** `protocol` selects the algorithm: 0.1
   means Ed25519 (signs 0.1 and 0.2), 0.3 means ML-DSA-65 (signs 0.3 only).
   Import derives the public key under that algorithm and requires it to match.
5. **Login 0.3**: prefix `iff-apostille/login/0.3` followed by LF, at most 4096
   bytes, pure ML-DSA-65 with the empty context, hedged.
6. **Browser signing is allowed for the alpha** with the vendored
   `@noble/post-quantum`. The UI and docs state that it is not independently
   audited and does not claim constant-time signing. The CLI is recommended for
   administrator keys.
7. **Migration.**
   - Alpha 0.1 registrations are not migrated.
   - The default goes from 0.1 directly to 0.3.
   - Hosted 0.1 issuance stops at the switch.
   - 0.2 remains an explicit option.
8. **Go 1.27 is required.** The root module moves to `go 1.27.0`, toolchain
   `go1.27.2`, and uses the standard library `crypto/mldsa`. There is no
   third-party Go ML-DSA library.
9. **JS library: `@noble/post-quantum` 0.7.1** (published 2026-08-27). Vendored
   with the exact `@noble/hashes` files it imports, pinned with SHA-256 and notices
   in `docs/apostille/NOTICES.md`. The SDK still has no external npm runtime
   dependency, but it contains third-party code, as 0.2 decision 8 words it.

## Contracts (additions to the 0.2 contracts)

### C1′ — The 0.3 profile

A third entry in the 0.2 profile table. Every field below comes from the
profile; the verification code has no `if protocol == "0.3"` branch.

| Field | 0.3 value |
| --- | --- |
| Protocol | the 0.3 identifier |
| Domain suffix | `0.3` |
| Algorithm string | `ML-DSA-65` |
| Public key | 1952 bytes, encoded as 2603 characters |
| Signature | 3309 bytes, encoded as 4412 characters |
| Key validator | exact length only |
| Identifier validator | the 0.2 grammar |
| Signature verifier | `mldsa.Verify(pk, M, sig, &mldsa.Options{})` |

- Encoded-length checks happen before any base64 decoding.
- The `Verifier` cache stays keyed by the complete envelope.

### C2′ — Signers

- The signer type carries its algorithm.
  - Untyped seeds through the existing `NewSigner` stay Ed25519.
  - A separate constructor builds an ML-DSA-65 signer from a 32-byte seed.
  - Signing an artifact whose profile algorithm differs from the signer's
    algorithm fails before any work.
- Production signing calls `(*mldsa.PrivateKey).Sign` (hedged).
- `SignDeterministic` is reachable only from test code; for example, an
  unexported hook used by the vector generator.
- Login: separate sign and verify functions for the 0.3 prefix. The 0.1 login
  functions are unchanged.
- Key generation for ML-DSA-65 returns a 0.3 key file. The seed comes from
  `crypto/rand` through `mldsa.GenerateKey`, and the file stores
  `PrivateKey.Bytes()`.

### C3′ — Key files

- Same JSON shape and limits as today (`maxKeyFileBytes` = 4 KiB; a 0.3 file is
  about 2.8 KB) and the same owner-only permission check.
- `protocol` must be the 0.1 or the 0.3 identifier. A 0.2 identifier is refused,
  because 0.2 signing uses 0.1 key files.
- `seed` is 43 canonical characters.
- On import, derive the public key under the named algorithm and require it to
  equal both `public_key` and `key_id`.
- The same rules apply in Go (CLI, SDK) and JS (`importKeyFile`,
  `generateKeyFile`).

### C5′ — Vectors

- New files `testdata/apostille/core-0.3.json` (known answer, deterministic
  signatures from the existing public fixture seeds used as ML-DSA seeds) and
  `testdata/apostille/core-0.3-cases.json` (format 1). A distinct generator test
  function writes them.
- The 0.1 and 0.2 files must stay byte-identical.
- The case list is `spec/core-0.3.md` "Conformance vectors".
- The hedged-signature accept case is generated once and committed as bytes. The
  generator must not regenerate it on every run, or the file would never be
  deterministic. Keep it in a fixed input file that the generator copies, or
  produce it with fixed randomness through a test-only path that feeds FIPS 204's
  `rnd`.
- Wycheproof ML-DSA-65 malformed encodings: take them from Go's own test data
  (`crypto/mldsa/mldsa_wycheproof_test.go` and its data source), and record the
  source file and test IDs in the case notes.
- Every reject case carries the reject-with-intended-reason self-check, as in
  0.1 and 0.2.

### C6′ — JS

- **Vendored files.** Vendor `@noble/post-quantum` 0.7.1 ML-DSA and its exact
  `@noble/hashes` imports at fixed paths under `web/`, as upstream release bytes.
  Add them to the three asset lists (0.2 C6).
- **Before vendoring, prove these with tests:**
  - `ml_dsa65` keygen from a 32-byte seed matches Go's public key for the same
    seed;
  - signing and verifying with an explicit empty context;
  - it rejects every Wycheproof malformed case Go rejects;
  - it verifies Go's hedged and deterministic signatures, and Go verifies its
    signatures.
- **Module layout.** A new module holds the 0.3 signer and verifier;
  `web/apostille-core.mjs` dispatches by version. WebCrypto stays the 0.1 path.
- **Signing disclosure.** Browser 0.3 signing shows the disclosure from decision
  6 wherever a key is generated or used to sign. The text lives in
  `web/apostille-messages.mjs` in all four locales.

### C7′ — CLI

- `--protocol` gains `0.3`.
- Key generation gains an algorithm choice (`ed25519` or `ml-dsa-65`). The
  default stays `ed25519` until Phase 7.
- `verify --accept-protocol` accepts `0.3`, and its output shows the bundle's
  protocol.
- A 0.3 signing command refuses a 0.1 key file, and a 0.1 or 0.2 command refuses
  a 0.3 key file.

### C8′ — Hosted service (Phase 6, `iff-trust-oracle`)

Inventory first, change second:

- **Login and keys.** The login signature length guard (128 characters today)
  must reach 4412 for 0.3. Admin and agent public key columns must hold 2603
  characters.
- **Size limits.** Request body limits for registration, submission and
  issuance, and the stored bundle and certificate size, must fit about 40 KB per
  bundle.
- **Issuer key.**
  - An ML-DSA-65 issuer seed is supplied to the API role only, as a secret the
    owner generates; never in Git, logs or tool output.
  - The key directory publishes it beside the Ed25519 issuer key, which stays
    listed for 0.1 verification.
- **Login and workspaces.** 0.3 login creates or finds the workspace by the
  ML-DSA admin key ID. 0.1 workspaces are left as they are.
- **Other consumers.** `apostille-mcp` key-file signing follows C3′. The hosted
  read-only MCP profile is unaffected beyond verification.
- **API client.** `apostille/client` validates 0.3 responses against the
  protocol it submitted.
- **Pin bump.** The hosted service needs Go 1.27 to bump its pin of this module.

## Executor gotchas (0.3 additions)

1. **Raising the Go version ripples.** Raising `go` to 1.27.0 in the root module
   requires `go 1.27.0` or later in `cmd/apostille` and `apostille/zkbudget`, and
   a tidy in all three. CI images and `.github/workflows/ci.yml` must use Go
   1.27.2. Run every Go command with `GOWORK=off` and a 1.27 toolchain.
2. **`mldsa.PrivateKey.Sign` ignores its `io.Reader` argument** and is always
   hedged. Passing a deterministic reader does not make vectors reproducible;
   use `SignDeterministic` for the known-answer bundle.
3. **The hedged accept case is not reproducible by construction** (C5′). Do not
   "fix" a changing case file by switching it to deterministic signing. Commit
   the bytes once.
4. **Size checks now differ by profile.** Today `VerifyEnvelope` rejects
   `public_key` over 64 characters and `value` over 128. Those limits must come
   from the profile, or every 0.3 envelope is rejected before signature work.
   The 0.1 behaviour must stay byte-for-byte identical on the 0.1 case file.
5. **Exact lengths, not maxima.** A 0.3 key of 2602 or 2604 characters and a
   signature of 4411 or 4413 are rejects with their own cases. Base64url of 1952
   bytes ends in a character whose low bits must be zero; canonical re-encoding
   catches that.
6. **Library context defaults differ.** Check that the JS library's default
   context is empty and that passing it explicitly gives the same signature
   input. A mismatch shows up only in the Go/JS differential, so run it.
7. **Fixture seeds.** Reusing the existing public fixture seeds as ML-DSA seeds
   is fine for test material only, and it is exactly the cross-algorithm reuse
   that production must never do. Keep the reuse confined to test code, and keep
   the key-file import check (C3′) that rejects a seed placed in the other
   type's file.
8. **Case file size.** The 0.3 case file is about 7.7 MB, against 600 KB for
   0.1, because every envelope carries a 2.6 KB key and a 4.4 KB signature,
   base64-wrapped inside bundles. Keep it out of the npm package and the offline
   archive (0.2 decision 11), and check that the JS test runner's memory and
   file-size limits are not hit.
9. **Unknown-version cases need a value that never becomes real.** The 0.2
   generator first used the 0.3 identifier as "unknown". Both generators now use
   `…/spec/never-defined`.
10. **`ParseKeyFile` is stricter than today's CLI** for 0.1 files: 43 canonical
    characters only, with no standard-alphabet or 64-byte expanded form. Every
    file the CLI or browser generates already has this form, and no external key
    file exists. Phase 4 therefore switches the CLI to `ParseKeyFile` as is.

## Phases

### Phase 2 — Go reference implementation and 0.3 vectors

Dependencies: 0.2 Phase 2 landed.

Deliverables:
- the C1′ profile, C2′ signers, C3′ key files and login 0.3 helpers;
- the 0.3 known-answer vector and case file (C5′);
- unit tests, plus 0.3 seeds in the fuzz targets;
- the Go version bump and tidy in all three modules.

Size: medium.

Acceptance:
- `make check`, `make security` and `make fuzz` green with no skips.
- The 0.1 and 0.2 vector and case files are byte-identical.
- The 0.3 generator is deterministic across two processes, apart from the
  committed hedged case.
- Every case listed in the specification is present.

Outcome (2026-10-09):

- **What landed.**
  - `profile03` in the table, verifying with `mldsa.Verify` and an explicit empty
    context; `Protocol03` and `Algorithm03`.
  - An algorithm-carrying `Signer` with `NewMLDSASigner`, `GenerateMLDSAKey` and
    `Algorithm()`. `SignFor` refuses a mismatched algorithm before any work.
  - Hedged signing. Deterministic signing sits behind an unexported flag that
    only `_test.go` sets, which a test confirms by scanning the sources.
  - `SignChallenge03` and `VerifyChallenge03`.
  - `KeyFile`, `ParseKeyFile` and `GenerateMLDSAKeyFile`.
  - The Go version moved to `go 1.27.0`, toolchain `go1.27.2`, and CI to 1.27.2.
    The nested modules changed their toolchain line only and still pin the
    released root.
- **Vectors.**
  - `core-0.3.json`: 42,165 bytes, sha256 `56b3108b…6c8c`.
  - `core-0.3-cases.json`: 7.7 MB, sha256 `65f8a61f…1099`. It has 269 bundle
    cases (29 accept, 240 reject), 54 strict-JSON cases and 353 identifier cases.
  - Two committed inputs: `core-0.3-hedged.json`, the hedged known-answer bundle
    generated once, and `core-0.3-wycheproof.json`. The latter holds 13 invalid
    ML-DSA-65 verify tests from C2SP Wycheproof commit `ee7b4f7e…`, the version
    Go 1.27.2 pins, with Apache-2.0 attribution in `NOTICES.md`.
  - HashML-DSA cases are built through external μ, with a control showing that
    external μ over the pure `M′` equals pure signing.
  - Seven constructed malformed encodings isolate the hint rules and both sides
    of the `z` bound.
  - A 0.3 grant naming a 0.2 statement is a unit test, because the case format
    cannot express it.
- **Verified.**
  - With Go 1.27.2: `make check` (no skips), `make fuzz`, the isolation script,
    tidy in all three modules and `go vet`.
  - `make security` reports no reachable vulnerability. The nested modules list
    four advisories in `golang.org/x/crypto` v0.54.0 that their code does not
    call; that is separate dependency work.
  - The 0.1 files and `core-0.2.json` are byte-identical. Both generators run
    deterministically across processes.
- **Deviations.**
  - The case file size (gotcha 8).
  - The 0.2 unknown-version fix (gotcha 9).
  - `signERC8004` now refuses a non-Ed25519 signer rather than panicking.

### Phase 3 — JS reference implementation and cross-checks

Dependencies: Phase 2 vectors.

Deliverables:
- the vendored files and notices, with the C6′ pre-vendoring proofs;
- the 0.3 verifier and signer;
- browser and built-SDK consumers for both 0.3 vector files;
- the Go/JS differential at 0.3, with an empty divergence table as the target.

Acceptance: all consumers green with no skips, and Go and JS agree on every 0.3
case.

### Phase 4 — CLI, UI, docs

Deliverables:
- C7′;
- browser key generation and signing at 0.3, with the disclosure;
- updates to `docs/apostille/` (SDK, CLI, API, CONFORMANCE, README index) and the
  root README in four languages, kept to the repository's translation practice.

Acceptance: UI tests, the four-locale dictionary test, and manual verifier
checks offline with `connect-src 'none'`.

### Phase 5 — Release

Tag the root, `cmd/apostille` and `apostille/zkbudget` modules in the order
`docs/apostille/RELEASE.md` gives, after the user picks the version names. A
release note states that verifying any version now needs Go 1.27 for module
consumers.

### Phase 6 — Hosted service and API client

C8′, in `iff-trust-oracle`, through a reviewed pin bump and
`make apostille-assets-sync`. Never copy files from this repository.

### Phase 7 — Default switch

Dependencies:
- Phase 6 deployed;
- the alpha notice published (owner wording and placement still open);
- the announced date reached.

The SDK and CLI defaults become 0.3, and hosted 0.1 issuance stops. 0.1 and 0.2
signing stay behind explicit options.

## User-input checklist

- Phase 5: release version names.
- Phase 6: generate and provision the ML-DSA-65 issuer seed (owner only).
- Phase 7: switch date, and the alpha notice wording and placement.
