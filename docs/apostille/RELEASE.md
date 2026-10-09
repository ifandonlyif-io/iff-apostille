# Source alpha release preparation

`v0.3.0-alpha.1` is the second alpha release: root Go module `v0.3.0-alpha.1`
(packages `apostille`, `apostille/client`, `util`), `apostille/zkbudget/v0.3.0-alpha.1`
and `cmd/apostille/v0.3.0-alpha.1`, tagged in that order. The root tag was cut
on 2026-10-09 at merge commit `9ba79a8` after CI passed, and
`apostille/zkbudget/v0.3.0-alpha.1` at `a5ad03c` (its pin of that root) after CI
passed; the CLI tag follows the merge of the CLI branch. Root module checksum
`h1:Dk+ZRfacmxNDixLnxDt/hYrAxfbYC67hThrMkkmFe+M=`. Verified from a clean module
cache through proxy.golang.org: a consumer verifies the published Core 0.1 and
Core 0.3 known-answer bundles with issuer and key pins (`accepted_by_policy`).
The `zkbudget` and CLI tags are not covered by that proxy check.
It contains Core 0.1, Core 0.2 (exact identifier grammar, strict Ed25519) and
Core 0.3 (pure ML-DSA-65, FIPS 204) in the Go root module, the browser
verifier/console and the JS SDK source; the CLI supports `--protocol 0.1|0.2|0.3`,
`keygen --algorithm ml-dsa-65` and `verify --accept-protocol`. Core 0.1 remains
the default signing version until a switch is announced. Go 1.27 is required for
module consumers. Not included: no npm package, no prebuilt CLI binaries, and the
hosted service and hosted API client do not support Core 0.2 or 0.3 yet; the
ERC-8004 binding and ZK budget profiles cover Core 0.1 only.

`v0.1.0-alpha.1` was the first release: root Go module `v0.1.0-alpha.1`
(packages `apostille`, `apostille/client`, `util`), `apostille/zkbudget/v0.1.0-alpha.1`
and `cmd/apostille/v0.1.0-alpha.1`, tagged in that order on 2026-09-22 after CI
passed on `d2c72c8`. No CLI binary release and no npm package are published.
Preserve protocol/profile identifiers and vector bytes independently of software
package versions. Core 0.2 and 0.3 were implemented in the source tree but not in
that release (they are in `v0.3.0-alpha.1`); every release note must say which Core versions its tag contains,
and that 0.1 remains the default signing version until a switch is announced.

## Validate a clean source checkout

```sh
make check
make security
make apostille-build
mkdir -p dist
npm pack ./sdk/apostille-js --pack-destination ./dist
```

The browser modules vendor `@noble/curves`, `@noble/hashes` and
`@noble/post-quantum` under `web/vendor/noble/`. Before a release that includes
Core 0.2 or 0.3, check that the tree still matches the pinned upstream tarballs:

```sh
dir="$(mktemp -d)" && (cd "$dir" && npm pack @noble/curves@2.4.0 @noble/hashes@2.4.0 @noble/post-quantum@0.7.1)
node scripts/vendor-noble.mjs "$dir" --check
```

The script verifies each tarball against the pinned registry integrity value and
fails on any difference; it writes nothing with `--check`. See
[NOTICES.md](NOTICES.md).

`make check` builds, vets and race-tests the root and isolated CLI/ZK modules,
runs Go/JS conformance, type-checks the JS SDK and builds the offline verifier.
Node 22+ is required: do not accept silently skipped Go/JS interop tests.
First builds download public dependencies. Offline runtime does not imply an
offline initial build; pre-populate all three modules' caches when required.

Review the npm tarball file list and install it into a new temporary project.
The conformance case files (`core-0.2-cases.json` is 1.2 MB and
`core-0.3-cases.json` 7.7 MB) stay out of the npm package and the offline
verifier archive; they ship only in the source archive. The package carries the
vectors and schemas.
Verify offline imports, declarations and examples there. The core package has
no npm runtime dependencies. Do not include node_modules, secrets or private
application artifacts. Retain source LICENSE, synthetic-vector notice and
applicable dependency licenses for anything distributed.

`make verifier` produces `dist/verifier/` and a ZIP from an explicit asset list,
with file checksums and fixed ZIP timestamps. Test in a browser served on loopback:
network activity must be local static assets only, with no API/RPC/telemetry.
Archive hashes identify bytes, not the trustworthiness of the issuer or build.

## First source release

1. Review the exact files, MIT attribution, dependency notices, SECURITY contact
   and alpha limitations. Enable GitHub private vulnerability reporting; verify
   it is actually available before advertising its link as operational.
2. Create a new repository with fresh history. Do not expose another repository
   or copy its `.git` directory. Use read-only CI permissions, require conformance
   checks before merging, and name the actual maintainers with release access.
3. Run the public CI on the initial commit. Choose a software tag only after it
   passes. A proposed first tag is `v0.1.0-alpha.1`; Core stays `0.1`.
4. Publish source first. Record source revision, toolchain and artifact hashes.
   Include all modules and fixtures in the source archive. Do not describe this
   as independently audited/reproduced or as a deployed-binary attestation.

## Nested modules and later releases

The nested modules pin released root versions and have no `replace` directive,
which is what lets `go install ...@version` work. The cost is that a change in
the root module is not seen by `apostille/zkbudget` or `cmd/apostille` until a
new root tag exists. To test a nested module against uncommitted root changes,
add `replace github.com/ifandonlyif-io/iff-apostille => ../..` (and the ZK
module's counterpart) locally and never commit it; CI's tidy check rejects a
committed replace by way of the changed `go.mod`.

A root version that contains Core 0.3 moves the module to `go 1.27.0` (toolchain
`go1.27.2`), because it uses the standard library `crypto/mldsa`. Module
consumers need Go 1.27 once they pin such a root version, to verify or sign any
Core version, and the release note must say so. The nested modules and the hosted
service keep working on their current pins until they bump the root version.

Release order for the next version: tag the root after CI passes; in the ZK
module pin the new root version, tidy, test against the downloaded root, commit
and tag `apostille/zkbudget/<version>`; in the CLI module pin both, tidy, test,
commit and tag `cmd/apostille/<version>`; then verify `go get` of the root and
`go install` of the CLI from a clean module cache through the public proxy.
Never invent dependency sums; let `go mod tidy` fetch them. Keep a LICENSE in
each module. Downstream, the hosted service bumps its `go.mod` pin and runs its
asset sync for the served browser modules; it does not copy files from here. See [Go multi-module release rules](https://go.dev/doc/modules/managing-source).

The proposed npm name is `@ifandonlyif/apostille`. Verify scope/package ownership
before first publication. Use an explicit alpha dist-tag and public access.
Configure [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) for
the exact repository/workflow/environment when available, with a reviewed initial
package bootstrap. No publishing workflow or long-lived npm token is bundled in
this preview. Do not switch users to registry install instructions before a
clean external install and provenance inspection succeed.

Before distributing a CLI binary, generate a notice bundle for its actual linked
dependencies (including ZK), Go runtime and platform-specific build, with full
license texts. This source preview does not yet prepare public binary archives.
Do not bundle private amounts, source keys or development proving/setup secrets.
