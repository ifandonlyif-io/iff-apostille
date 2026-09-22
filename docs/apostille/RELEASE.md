# Source alpha release preparation

`v0.1.0-alpha.1` is the first tag of the root Go module (packages `apostille`,
`apostille/client`, `util`). The nested CLI and ZK modules get their own tags by
the procedure in "Later installable modules" below; until then they build from
a full checkout. No CLI binary release and no npm package are published.
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

## Later installable modules and registry packages

Nested CLI/ZK modules currently use local replacements and `v0.0.0` source pins.
A downstream module does not inherit replacements, and `go install ...@version`
rejects replace-dependent command modules. Source builds use the complete
checkout; those install commands are deliberately not advertised.

For remotely installable modules, publish the root first, pin its actual version
in the ZK module, remove that local replacement, tidy/test in a clean consumer,
and tag `apostille/zkbudget/v0.1.0-alpha.1`. Then pin both actual versions in the
CLI module, remove its replacements, tidy/test and tag
`cmd/apostille/v0.1.0-alpha.1`. Re-test byte compatibility at each step. These are
separate reviewed commits after remote tags exist; never invent dependency sums.
Keep a LICENSE in each module. See [Go multi-module release rules](https://go.dev/doc/modules/managing-source).

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
