# Core 0.2 implementation plan

Living plan for implementing [the Core 0.2 proposal](core-0.2-strict-identifiers-and-keys.md)
(exact identifier grammar, strict Ed25519, versioned namespace). A fresh session
starts here: read the status table, then the decisions and contracts, then only
the phase you are about to execute. Update the status table and append a phase's
outcome the moment that phase lands, not later.

Working conventions for this repository apply throughout: read `AGENTS.md`,
`README.md`, `SECURITY.md` and `docs/apostille/spec/core-0.1.md` before changing
verification; `GOWORK=off` for every Go command; `make check`, `make security`
and `make fuzz` before calling a phase done; new code in new files where
possible so the upstream copy stays a file copy.

## Status

| Phase | Scope | Status | Note |
| --- | --- | --- | --- |
| 0 | Land the 0.1 conformance work this plan builds on | 🟡 partial | Code complete and verified on branch `test/conformance-cases-fuzz` (2026-09-22); not committed; not upstreamed to `iff-trust-oracle` |
| 1 | Normative `spec/core-0.2.md` + `web/apostille-0.2.schema.json` | ⬜ pending | Needs Phase 0 landed; user approves the normative text |
| 2 | Go: profiles, identifier grammar, strict Ed25519, no-mixing, explicit-version signing, 0.2 vectors | ⬜ pending | Needs Phase 1 |
| 3 | JS: same rules, vendored curve library, consumers for 0.2 vectors, Go/JS differential at 0.2 | ⬜ pending | Needs Phase 2 vectors; user confirms the vendored library |
| 4 | CLI, browser verifier UI, docs, notices | ⬜ pending | Needs Phases 2 and 3; new UI strings need reviewed translations |
| 5 | Hosted service and API client (lives in `iff-trust-oracle`) | ⬜ pending | External to this repository; also carries the login/registration key check |
| 6 | Default signing version switches to 0.2 | ⬜ pending | Gated on Phase 5 deployed, registrations migrated, announced date |

## Approved decisions (do not relitigate)

Settled with the user on 2026-09-21 and 2026-09-22. State them as facts.

1. **No Rust rewrite.** Go stays the reference and hosted implementation; JS
   stays the browser and SDK implementation. A verify-only Rust crate is a
   possible later addition, not part of this plan.
2. **Core 0.1 is frozen.** Its known-answer vector, byte formats and accept/reject
   behaviour do not change. The only 0.1 fix was the unpaired-surrogate scan,
   which implemented text the 0.1 specification already had.
3. **Top-level scalars** are a retained helper difference (`parseStrict` accepts,
   `StrictJSON` rejects). The protocol rule is "the root of a bundle, envelope
   and payload is an object", pinned by conformance cases. Do not change the
   helpers to zero the differential.
4. **Namespace.** Core 0.2 with protocol ID `https://ifandonlyif.io/apostille/spec/0.2`
   and signature domain `iff-apostille/<kind>/0.2` followed by LF. Not a named
   profile on 0.1 bytes.
5. **No mixing.** Delegation, acceptance, statement, publication grant and
   certificate that refer to one another carry one version, in envelope and
   signed payload. A verifier selects rules from `bundle.protocol` and rejects
   any envelope or payload naming another version; grant validation rejects a
   grant whose version differs from the statement and delegation it names.
6. **Identifier grammar** is the proposal's Rule A: lowercase `https://` and
   `urn:`; canonical IPv4 and hexadecimal RFC 5952 IPv6 with no dotted tail and
   no zone, `::` only where a run of two or more zero groups exists; RFC 3986
   `pchar` path alphabet with percent escapes still forbidden (accept `! * ' ( )`,
   reject bare `| ^ [ ]`); reject dot segments, non-LDH or empty host labels, a
   final host label that starts with a digit without being a number, port `0`,
   and a URN without both `nid` and `nss`; **empty path segments stay valid**;
   identifiers compare as exact bytes; no URL parser decides acceptance.
7. **Strict Ed25519** is the proposal's Rule B: `S < L`; `A` and `R` canonically
   encoded, not the identity, and in the prime-order subgroup (`[L]P` is the
   identity, which also excludes mixed-order points); then the RFC 8032 equation.
   "Call the library's strict mode" is not conformance.
8. **Dependencies.** A Go curve library enters the root module and a curve
   library is vendored into `web/`, each pinned to an exact version with its
   notice in `docs/apostille/NOTICES.md`. Wording: the JS package has no
   external npm runtime dependency and contains third-party code; never "zero
   dependencies".
9. **Hosted key check now.** The hosted service applies the Rule B key check to
   login and registration keys as its own access policy, as separate work,
   after inventorying already-registered keys. Historical 0.1 offline
   verification keeps 0.1 rules.
10. **Default switch is gated.** SDK and CLI default to 0.1 until the hosted
    service issues 0.2 and registrations that use it have moved, on an announced
    date. Verifier support alone is not the condition.
11. **Case files are not shipped** in the npm package or the offline verifier
    archive (they are hundreds of kilobytes of exact bytes). The SDK build copies
    them into the git-ignored `spec/` directory for its tests only.

## Architecture contracts

Written before the phases that consume them. Exact Go and JS identifier names are
chosen in each phase's handoff specification; the shapes below are fixed.

### C1 — Version selection (Go and JS)

- Constants: the existing 0.1 protocol string is unchanged; a second constant
  holds the 0.2 string; a list of known protocols holds both.
- One internal **profile** per version: protocol string, signature-domain
  suffix, identifier validator, public-key validator, signature verifier. Every
  version-dependent branch goes through the profile; no `if protocol == …`
  scattered through verification.
- `VerifyEnvelope` selects the profile from `envelope.protocol` and rejects an
  unknown value. Payload validation requires `payload.protocol` to equal the
  envelope's.
- Bundle verification selects the profile from `bundle.protocol` and requires
  every present envelope (statement, delegation, acceptance, certificate) to
  carry that protocol. Grant validation requires grant, statement and delegation
  to agree. Issuance gives the certificate the bundle's protocol.
- `VerifyOptions` (Go) and the options object (JS) gain an **accepted protocols**
  list. Unset means every known version is accepted; when set, a bundle whose
  protocol is not listed is rejected before any signature work. The result's
  `protocol` field reports the bundle's version. All other result dimensions are
  unchanged from 0.1.
- The `Verifier` cache stays keyed by the complete envelope, which includes the
  protocol, so entries never cross versions. It gets no version field.

### C2 — Signing with an explicit version

- Every signing entry point (header construction, envelope signing, registration,
  statement, grant, issuance) has a form that takes the protocol explicitly and
  validates it against the known list. The existing 0.1-signing functions remain
  and are the "explicit 0.1" form until Phase 6, when only the defaults change.
- A 0.2 statement or grant refuses at signing time to bind to a delegation or
  statement of another version. Signers never emit a bundle that the no-mixing
  rule would reject.
- Key files are unchanged. Their `protocol` member names the key-file format,
  which did not change; a key file signs either version. CLI and JS keep
  accepting only the existing key-file protocol string.

### C3 — Rule B implementation shape

- Go: one function that takes a 32-byte encoding and returns an error unless the
  point decodes, re-encodes to the same 32 bytes, is not the identity, and
  `[L-1]P + P` is the identity; `L-1` is a canonical scalar. Apply it to `A` and
  to `R`. Check `S < L` by comparing the little-endian bytes against `L` before
  any decoding. Then call `crypto/ed25519.Verify` for the equation: with `A` and
  `R` torsion-free, cofactored and cofactorless verification agree.
- JS: the same four steps over the vendored library's point type. If the
  library's scalar multiplication rejects or reduces scalars at or above `L`,
  use `[L-1]P + P` there too, or its own torsion-free test, and prove the choice
  with the mixed-order vector.
- Do not rely on incidental library behaviour for any step. Go's `ed25519.Verify`
  happens to compare the recomputed `R` against the given bytes (so it rejects a
  non-canonical `R`) but decodes `A` without re-encoding (so it accepts a
  non-canonical `A`); 0.2 checks both explicitly.
- The public-key rule applies wherever 0.2 carries a key: `signature.public_key`
  and a delegation's `agent_public_key`.

### C4 — Identifier grammar implementation shape

- Byte-level, hand-written validator in each language, structured as the ABNF in
  the proposal: scheme literal, host (exact IPv4, bracketed canonical IPv6,
  LDH labels with the final-label rule), port, segments, or `urn:` with `nid`
  and `nss`. No `net/url`, no `URL`.
- IPv6 canonical check is "parse eight groups, re-serialize by the rule, compare
  bytes".
- Table tests come from the vectors; Go additionally fuzzes the validator
  (accept implies ASCII, length ≤ 256, none of `% ? # \`, whitespace or
  control bytes), and the Go/JS differential runs every identifier value at 0.2
  expecting **zero** divergences.

### C5 — Vectors and generator

- New files `testdata/apostille/core-0.2.json` (known answer, same shape as the
  0.1 file) and `testdata/apostille/core-0.2-cases.json` (same schema as the 0.1
  case file, `format: 1`, `protocol` set to 0.2). The 0.1 files are untouched.
- The generator in `apostille/conformance_cases_test.go` is parameterized by
  profile; the 0.2 writer is a distinct test function so `-run` can select it.
  The 0.1 generator's output bytes must not change.
- Every 0.1 case category is regenerated under 0.2, plus the identifier
  boundaries, the IPv6 accept and reject lists, the Ed25519 vectors and the
  cross-version vectors listed in the proposal's "Vectors" section. The
  **mixed-order key** vector is mandatory in every implementation's suite.
- Ed25519 vector construction (test-only, deterministic from the fixture seeds):
  `A` = identity with `R` = identity, `S = 0` isolates the key rule; `A` = the
  order-2 point with `R` = identity or the order-2 point, `S = 0`, likewise;
  mixed-order `A` = fixture key plus the order-2 point, signature `S = r + k·a`
  with `r` iterated until `k` is a multiple of 8, so that a cofactorless
  verifier accepts it and only the subgroup rule fails. **Identity `R` on an
  honest key with a valid signature**: `S = k·a mod L` where
  `k = SHA-512(R || A || M) mod L`; then `[S]B = O + [k]A` and Go
  `ed25519.Verify` accepts it (reproduced as differential edge case
  `ed25519/genuine-key-r-identity-valid-s`, Go and Node both accept at 0.1).
  Only the "R is not the identity" clause rejects it, so it catches an
  implementation that checks `A` and forgets `R`. Such a signature reveals `a`
  (`a = S·k⁻¹`), which is why no honest signer produces one; it is test-only
  material built from the fixture seed. `R` of order 2, 4 or 8, or mixed order,
  on an honest key cannot validate cofactorless, since `R` must equal
  `[S − k·a]B`, a prime-order-subgroup point; those vectors test rejection only.
- All three consumers (Go, browser modules, built SDK) run both case files. The
  fuzz seeds include the 0.2 inputs.

### C6 — JS module layout

- Vendored curve library at a fixed path under `web/`, exact upstream release
  bytes, version and SHA-256 recorded in `docs/apostille/NOTICES.md`, license
  text under `docs/apostille/notices/`. Requirements: MIT or BSD license,
  single-file ESM importable without a bundler, exposes canonical point decoding
  and either scalar multiplication or a torsion-free test, current maintained
  release.
- The strict verifier lives in a new module that imports the vendored file;
  `web/apostille-core.mjs` dispatches by version. WebCrypto remains the 0.1
  path.
- CSP stays `script-src 'self'`. New files must be added to three fixed lists:
  `scripts/build-verifier.py` assets, `sdk/apostille-js/scripts/build.mjs`
  copies, and the asset assertion in `web/apostille-ui.test.mjs`.
- `web/apostille-0.2.schema.json` is the 0.1 schema with the protocol constant
  changed; both ship. Type declarations under `sdk/apostille-js/src/` gain the
  version option and the accepted-protocols option.

### C7 — CLI

- `delegate`, `sign`, `grant` and `issue` take `--protocol` with values `0.1`
  and `0.2`; default `0.1` until Phase 6. `verify` takes a repeatable
  `--accept-protocol`; default accepts both known versions; output shows the
  bundle's protocol. Key handling is unchanged.

### C8 — Hosted service and API client (Phase 5, `iff-trust-oracle`)

- The hosted service adds 0.2 registration, grant validation and issuance and
  refuses a 0.2 submission until then. `apostille/client` validates responses
  against the protocol of what it submitted and against its configured accepted
  list; it does not itself refuse to submit 0.2. Login and registration keys get
  the Rule B key check as hosted policy, preceded by an inventory of registered
  keys.

## Executor gotchas

Specific traps that already cost time. Re-verify a claim before acting on it if
the code may have moved.

1. **`UPDATE_APOSTILLE_FIXTURES=1` rewrites every generator's output**, including
   the frozen `core-0.1.json`. Always pass `-run` with the one writer you mean,
   then confirm `git diff --stat -- testdata/apostille/core-0.1.json` is empty.
   Do the same for `core-0.2.json` once it exists and is frozen.
2. **The file-writing tools decode backslash-u escapes with valid hex into the
   character they name**, silently; lone surrogates survive. Test rows about
   escapes became rows with no escape in them and still passed; `go vet`
   caught one as a duplicate map key. Spell such bytes with the `jsonText`
   token helper in `apostille/conformance_cases_test.go` (`<hhhh>`, `<bs>`,
   `<rocket>`, `<replacement>`) or build them numerically, and dump the on-disk
   bytes with a `repr`/`ascii` check afterwards. Handoff documents are affected
   too: describe escapes in words there.
3. **`[L]P` cannot be computed by loading `L` into a scalar type.** Verified
   against `filippo.io/edwards25519` v1.1.0: `SetCanonicalBytes(L)` fails,
   `SetUniformBytes` reduces `L` to zero, and `[0]P` is the identity for every
   point, so the check passes degenerate keys. Use `[L-1]P + P`. `Point.SetBytes`
   accepts non-canonical encodings by design; re-encode and compare.
4. **A new root dependency ripples into the nested modules.** `cmd/apostille`
   and `apostille/zkbudget` use `replace ../..`, so their `go.sum` files change.
   Run `GOWORK=off go -C <module> mod tidy` in `.`, `apostille/zkbudget` and
   `cmd/apostille`; CI fails on any tidy diff. `scripts/check-apostille-module-isolation.sh`
   only guards gnark and gnark-crypto, so the curve library is allowed, but run it.
5. **`make check` leaves an untracked binary `cmd/apostille/apostille`** (it is
   not git-ignored). Delete it, or add `/cmd/apostille/apostille` to `.gitignore`
   once the user agrees.
6. **Node interop and differential tests skip silently when `node` is missing.**
   Never accept a green run with skips; `docs/apostille/RELEASE.md` says so.
7. **Existing source and test files are byte-identical to `iff-trust-oracle`.**
   Put new code in new files; when an existing file must change, keep the diff
   minimal and list it for upstreaming at the end of the phase. Never write into
   the upstream checkout unasked.
8. **Browser UI strings live in one four-locale dictionary** (`web/apostille-messages.mjs`);
   a test requires every key in all four, and Simplified Chinese is a reviewed
   static dictionary. A new string needs reviewed translations before the test
   can pass honestly.
9. **Key files carry the 0.1 protocol string and both CLI and JS reject any
   other.** Contract C2 keeps that; do not "upgrade" key files.
10. **`apostille/client` checks response protocol against 0.1** in two places
    (`client.go`). Hosted 0.2 responses need Phase 5's client change; a 0.2
    statement submitted earlier fails at the server, which is intended.
11. **Go's `ed25519.Verify` is cofactorless** and compares the recomputed `R`
    bytes. It therefore accepts `R` = identity with `S = k·a` on an honest key
    (C5 has the construction), so the "R is not the identity" check must be
    explicit and its vector mandatory. `R` of order 2, 4 or 8 on an honest key
    can never validate; those vectors test rejection only and do not isolate
    the subgroup rule.
12. **The differential tables are exact** (`apostille/differential_test.go`): an
    unlisted divergence fails, and so does a listed one that stops reproducing.
    Adding 0.2 corpus items means running once with an empty 0.2 table and
    populating it from observed output; the target for 0.2 is an empty table.
    The 48 identifier entries and 6 scalar entries at 0.1 stay.
13. **Fuzz throughput varies run to run** because the corpus persists in the Go
    build cache; it is not a signal. A crasher is written under
    `apostille/testdata/fuzz/` and must be kept and reported.
14. **The case files are large** (about 600 KB each). Keep them out of
    `package.json` `files` and `scripts/build-verifier.py`; the SDK build copies
    them into git-ignored `spec/` for tests.

## Phases

Each phase starts with the main model writing a handoff specification (as in
Phase 0), a Sonnet-class agent implementing it, and the main model reviewing the
result against the acceptance criteria before the status table changes.

### Phase 0 — Land the 0.1 conformance work

Dependencies: none. This is the base every later phase edits.

What it is: branch `test/conformance-cases-fuzz`, uncommitted as of 2026-09-22.
Contents: `testdata/apostille/core-0.1-cases.json` (215 cases) with its Go
generator/consumer, JS consumers for browser modules and built SDK, three fuzz
targets and `make fuzz`, the Go/JS differential suite with exact divergence
tables, the unpaired-surrogate fix (`apostille/surrogates.go` plus a three-line
call in `apostille/crypto.go`), the root-must-be-object cases, the 0.1
specification clarifications, `CONFORMANCE.md`, and the Core 0.2 proposal.

Acceptance: committed on this repository's history (commit type `test:` for the
suite, `fix:` for the surrogate scan, `docs:` for the rest, or as the user
prefers); `make check`, `make security` and `make fuzz` green on the committed
tree; the upstream list applied to `iff-trust-oracle` by the user or with the
user's explicit go-ahead.

Upstream list: `apostille/surrogates.go`, `apostille/surrogates_test.go`,
`apostille/crypto.go` (3 lines + comment), `apostille/conformance_cases_test.go`,
`apostille/fuzz_test.go`, `apostille/differential_test.go`,
`web/apostille-cases.test.mjs`, `sdk/apostille-js/test/cases.test.mjs`,
`sdk/apostille-js/scripts/build.mjs`, `testdata/apostille/core-0.1-cases.json`,
`Makefile`, `.github/workflows/ci.yml`, `docs/apostille/CONFORMANCE.md`,
`docs/apostille/spec/core-0.1.md`, `docs/apostille/README.md`, `README.md`,
`docs/apostille/proposals/`. Go import paths and the node relative imports
follow the upstream tree.

Outcome: (append when landed)

### Phase 1 — Normative specification and schema

Dependencies: Phase 0 landed.

Deliverables: `docs/apostille/spec/core-0.2.md`, normative, derived from the
proposal: purpose and relation to 0.1, version namespace and exact signature
input, the no-mixing rule as verification steps, Rule A as ABNF plus constraints
with the IPv6 canonical procedure, Rule B as the four steps with `L` and `p`
stated, unchanged sections referenced rather than copied, result semantics,
receiver policy, privacy, and the vector file names. `web/apostille-0.2.schema.json`.
`docs/apostille/README.md` links the draft. The proposal's status line points at
the specification. Size: medium; main-model writing.

Acceptance: the user approves the normative text. Every rule in it is testable by
a vector planned in C5. No sentence changes a 0.1 rule.

Outcome: (append when landed)

### Phase 2 — Go reference implementation and 0.2 vectors

Dependencies: Phase 1 approved.

Deliverables, in new files where possible: profiles and version dispatch (C1);
explicit-version signing forms (C2); `filippo.io/edwards25519` in the root
module with the strict point and signature functions (C3); the byte-level
identifier validator (C4); no-mixing enforcement in source, grant and issuance
checks; `AcceptedProtocols`; the 0.2 known-answer vector and case file (C5)
generated deterministically; unit tests, `FuzzValidIssuer02`, and 0.2 seeds in
the existing fuzz targets; notices for the new dependency; tidy in all three
modules. Size: large.

Acceptance: `make check`, `make security`, `make fuzz` green; 0.1 vector and
0.1 case file byte-identical to Phase 0; 0.2 generator deterministic across two
processes; every C5 vector present, including the mixed-order key; the
reject-with-intended-reason self-check pattern from the 0.1 generator applied to
every 0.2 reject case; upstream list produced.

Outcome: (append when landed)

### Phase 3 — JS reference implementation and cross-checks

Dependencies: Phase 2 vectors exist. The user confirms the curve library choice
(C6) before it is vendored.

Deliverables: vendored library plus notice and license text; strict verifier
module; identifier validator; version dispatch and accepted-protocols option in
`web/apostille-core.mjs`; `.d.ts` updates; both JS case consumers run the 0.2
file; `web/apostille-0.2.schema.json` served; Go/JS interop tests at 0.2 (Go
vector verified in JS, JS-signed 0.2 bundle verified and issued in Go, verified
in JS); differential corpora extended to 0.2. Size: large.

Acceptance: the 0.2 differential tables are empty, or every remaining entry has
been turned into a specification fix in Phase 1's document with the user's
approval; all three consumers agree on every 0.2 case; `npm pack --dry-run`
lists the vendored file and no case file; CSP unchanged; `make check` green with
no skipped interop test.

Outcome: (append when landed)

### Phase 4 — CLI, browser verifier UI, documentation

Dependencies: Phases 2 and 3.

Deliverables: CLI flags (C7) with tests in `cmd/apostille`; verifier page shows
the protocol and accepts both versions, with new strings in all four locales;
`README.md` table row for Core 0.2; `SDK.md`, `CLI.md`, `CONFORMANCE.md`,
`RELEASE.md` and `NOTICES.md` updated, `NOTICES.md` wording per decision 8;
`API.md` notes that hosted 0.2 is pending Phase 5. Size: medium.

Acceptance: `make check` green including `apostille-local-test`; the offline
verifier archive builds and a local no-network browser check passes
(`CONTRIBUTING.md` requirement); translations reviewed.

Outcome: (append when landed)

### Phase 5 — Hosted service and API client (external)

Dependencies: Phase 2 for the Go code the service imports. Lives in
`iff-trust-oracle`; this plan only records it because Phase 6 depends on it.

Deliverables there: 0.2 registration, grant validation and issuance; response
protocol handling in `apostille/client` (C8); the Rule B key check on login and
registration keys as hosted policy; a key inventory before deployment; migration
`0000NN` numbering per that repository's rules. Size: owned by that repository.

Acceptance: recorded here by the user when deployed, with the date.

Outcome: (append when landed)

### Phase 6 — Default signing version

Dependencies: Phase 5 deployed; registrations that use the hosted service moved
to 0.2; a switch date announced in advance.

Deliverables: SDK, CLI and browser signing default to 0.2; 0.1 signing stays
behind the explicit option for the stated deprecation window; documentation
updated. Size: small.

Acceptance: the default-path examples in `sdk/apostille-js/examples/` and the
CLI documentation produce 0.2 bundles that verify in both implementations; a 0.1
key file still signs; 0.1 verification unchanged.

Outcome: (append when landed)

## User-input checklist

Everything that needs the user, in one place.

- [ ] Phase 0: commit the branch (or say how), and apply or authorize the upstream list.
- [ ] Phase 1: approve `docs/apostille/spec/core-0.2.md` as normative.
- [ ] Phase 3: confirm the JS curve library to vendor (name, version, license).
- [ ] Phase 4: review new UI strings in all four locales (Simplified Chinese is a reviewed dictionary).
- [ ] Phase 5: schedule the `iff-trust-oracle` work and the key inventory; record the deployment date here.
- [ ] Phase 6: announce the default-switch date and the 0.1 deprecation window.
- [ ] Optional: approve adding `/cmd/apostille/apostille` to `.gitignore`.
