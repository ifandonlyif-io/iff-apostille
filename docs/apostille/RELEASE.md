# Source alpha release preparation

`v0.1.0-alpha.1` is the first release: root Go module `v0.1.0-alpha.1`
(packages `apostille`, `apostille/client`, `util`), `apostille/zkbudget/v0.1.0-alpha.1`
and `cmd/apostille/v0.1.0-alpha.1`, tagged in that order on 2026-09-22 after CI
passed on `d2c72c8`. No CLI binary release and no npm package are published.
Preserve protocol/profile identifiers and vector bytes independently of software
package versions: Core stays `0.1`, and the accepted Core 0.2 specification has
no implementation, which every release note must say.

## Validate a clean source checkout

```sh
make check
make security
make apostille-build
mkdir -p dist
npm pack ./sdk/apostille-js --pack-destination ./dist
```

`make check` builds, vets and race-tests the root and isolated CLI/ZK modules,
runs Go/JS conformance, type-checks the JS SDK and builds the offline verifier.
Node 22+ is required: do not accept silently skipped Go/JS interop tests.
First builds download public dependencies. Offline runtime does not imply an
offline initial build; pre-populate all three modules' caches when required.

Review the npm tarball file list and install it into a new temporary project.
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

Release order for the next version: tag the root after CI passes; in the ZK
module pin the new root version, tidy, test against the downloaded root, commit
and tag `apostille/zkbudget/<version>`; in the CLI module pin both, tidy, test,
commit and tag `cmd/apostille/<version>`; then verify `go get` of the root and
`go install` of the CLI from a clean module cache through the public proxy.
Never invent dependency sums; let `go mod tidy` fetch them. Keep a LICENSE in
each module. See [Go multi-module release rules](https://go.dev/doc/modules/managing-source).

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
