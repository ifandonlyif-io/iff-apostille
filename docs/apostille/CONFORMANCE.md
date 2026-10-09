# Conformance — Core 0.1 alpha, with Core 0.2 and 0.3 in the source tree

Reference implementations: `apostille/` (Go), `web/apostille-core.mjs`
(WebCrypto), and the JS SDK built from the same browser modules. JSON schema
validation alone does not establish signatures, binding or receiver trust.

```sh
make check
make security
make fuzz   # optional locally; FUZZTIME=30s per target by default
```

Root Go tests cover core/client and the included safe HTTP helper. CLI and ZK
are separate modules tested with `GOWORK=off`. Browser tests cover core,
ERC-8004 and the shared offline/console UI logic. SDK tests include mocked API
contract responses; the hosted API/store implementation and its Postgres tests
are outside this repository. This matrix does not certify a hosted deployment.

Shared known-answer vector: `testdata/apostille/core-0.1.json`, generated from
public test seeds and fixed timestamps. Never use fixture keys for live issuance.
Ordinary tests reject drift. `UPDATE_APOSTILLE_FIXTURES=1` is reserved for
deliberate vector work, never a shortcut to pass packaging changes.

Machine-readable cases: `testdata/apostille/core-0.1-cases.json` lists accept and
reject cases for bundle verification, strict JSON with canonicalization, and
issuer identifiers. `input_b64` is the exact input in unpadded base64url;
`input_gen` repeats `repeat_b64` `count` times and is used only for the size
bound. `options` carry the caller's issuer pin, key pins and evaluation time.
Only `expect` is normative: `reject` means any error, `accept` lists every result
dimension, and `artifact_match` applies when `artifact_b64` is present. `reason`
and error text are informative. A strict JSON `accept` case also gives the exact
canonical bytes. Negative cases about encoding, field values, bindings, time and
certificate assertions carry real signatures from the public test seeds, so they
fail on the stated rule and not on a bad signature. The generator is
deterministic and ordinary tests reject drift. Regenerate only this file with
`UPDATE_APOSTILLE_FIXTURES=1 GOWORK=off go test -run TestWriteConformanceCases ./apostille`;
without `-run` the variable also rewrites the known-answer vector. Go, the browser
modules and the built SDK each run every case. The file is about 600 KB and is not
shipped in the npm package or the offline verifier archive.

Go interoperability tests require Node. They verify the shared Go vector in JS,
and sign with random browser keys, verify/issue in Go, then verify in JS.
Negative cases include signature/payload tampering, wrong issuer/key pins,
source/certificate grafting, missing delegation, wrong audience/purpose,
expired/future grants, duplicate keys, Unicode/BOM/numeric JSON, depth and byte
bounds. The API clients also test response verification and session boundaries.

`make fuzz` mutates the strict parser, whole-bundle verification and validly
signed payloads; its seeds come from the case file and also run under `make check`.
A deterministic differential suite signs about a thousand mutated envelopes,
parses about 150 JSON texts, and requires Go and the browser implementation to
return the same verdict and, when both accept, the same canonical bytes.

Known differences between the two reference implementations are listed exactly
in `apostille/differential_test.go`; a new difference, or a listed one that stops
reproducing, fails the suite. They are deliberately absent from the case file,
which pins only verdicts both implementations share and the specification states:
- Identifier syntax is implemented with each language's URL parser. Go accepts
  and JS rejects an uppercase `URN:` scheme and non-canonical IP-literal hosts
  such as `https://127.1/a`; Go rejects and JS accepts the path characters
  `! * ' ( ) | ^ [ ]`. Ordinary lowercase-host HTTPS and `urn:` identifiers are
  unaffected.
- The parsing helpers differ on a top-level scalar: JS `parseStrict` accepts one
  and Go `StrictJSON` does not. This is a retained helper difference, not a
  protocol one: the root of a bundle, envelope and payload must be an object,
  both verification entry points enforce that, and the case file pins it.
Core 0.1 does not say how to treat small-order Ed25519 public keys. Go and Node
accept them, so a degenerate key admits a signature valid for any message; some
libraries refuse such keys. Trust never comes from an embedded key. Identifier
syntax and degenerate keys change what a verifier accepts, so they are addressed
by Core 0.2 rather than by reinterpreting 0.1: see the
[Core 0.2 specification](spec/core-0.2.md) and the section below.

Go previously accepted two consecutive unpaired surrogate escapes and decoded
them to U+FFFD. The specification already required rejection and the browser
implementation rejected them, so this was fixed within 0.1 and the forms are now
shared reject cases. A signed payload could never carry one, because payload
bytes must already be canonical.

Offline output leaves organization identity, content truth, current revocation,
log inclusion and anchoring unproven/not provided. Independent issuer acceptance
requires caller-supplied issuer AND key pins. Evaluation time is a caller choice,
not an authenticated timestamp.

## Core 0.2 and Core 0.3

Go and JavaScript reference implementations of both versions are in this source
tree; neither is in `v0.1.0-alpha.1`. Each version has its own files and the 0.1
files are unchanged:

| File | Contents |
| --- | --- |
| `testdata/apostille/core-0.2.json`, `core-0.3.json` | Known-answer bundles from public test seeds (0.3 signed with the deterministic variant) |
| `testdata/apostille/core-0.2-cases.json` | 1.2 MB: 240 bundle cases (28 accept, 212 reject), 54 strict-JSON and 353 identifier cases |
| `testdata/apostille/core-0.3-cases.json` | 7.7 MB: 269 bundle cases (29 accept, 240 reject), 54 strict-JSON and 353 identifier cases |
| `testdata/apostille/core-0.3-hedged.json` | A hedged known-answer bundle, generated once; the generators only copy it |
| `testdata/apostille/core-0.3-wycheproof.json` | 13 invalid ML-DSA-65 verify tests from C2SP Wycheproof, with attribution in [NOTICES.md](NOTICES.md) |

The case files use the 0.1 format and rules: only `expect` is normative, and
every reject case is checked to fail for its stated reason. Go, the browser
modules and the built SDK each run every case. Regenerate a version's files with
`UPDATE_APOSTILLE_FIXTURES=1 GOWORK=off go test -run '^TestWriteCore02(Vector|Cases)$' ./apostille`
(or `Core03`), vector first; never regenerate to make a failing test pass. The
case files are not shipped in the npm package or the offline verifier archive;
the SDK ships `vectors-0.2.json`, `vectors-0.3.json` and the schemas.

**Claiming conformance.** An implementation may claim Core 0.2 or Core 0.3
conformance for the versions it names, for example "verifies Core 0.1 and 0.3",
once it verifies that version's known-answer bundle and returns the expected
verdict and result for every case of that version, under the case's options
(including the accepted-protocol list). 0.3 verification is ML-DSA-65 as
FIPS 204 defines it: the pure variant with the empty context. Conformance to one
version says nothing about another. The claim applies to the published cases and
exact formats; it is not certification, an audit, or a statement about
post-quantum security beyond the 0.3 specification's
[security level](spec/core-0.3.md#security-level-receiver-policy-and-versioning).

**Go/JS differential.** The differential suite also runs at 0.2 (2249 items; Go
and JS each accept 713) and at 0.3 (2270 items; each accepts 721). The 0.2 and
0.3 divergence tables are empty, so any difference at either version fails the
suite; the 0.1 tables above are unchanged. Interoperability tests also verify the
0.2 and 0.3 vectors across languages and issue bundles signed in the browser.

ERC-8004 and experimental ZK have separate profiles/tests; neither changes Core
0.1. An independent implementation is expected to verify the known-answer vector
and return the expected result for every case. Passing these suites is not
third-party certification or a cryptographic audit. Compatibility claims apply
to the published cases and exact formats.
