# Apostille by IFF

Portable, issuer-neutral signatures for agent artifacts. An agent signs a file
manifest, an administrator delegates its key, and an issuer records the checks
it performed. A recipient can verify the resulting bundle locally, without an
IFF account or an Internet connection. You can use the SDK or implement the
published specification and conformance vectors yourself.

**Alpha.** Core protocol `0.1`, the Go module release `v0.1.0-alpha.1` and the
SDK package `0.1.0-alpha.1` are different version namespaces. The Go root module
(packages `apostille`, `apostille/client`, `util`) is released as
`v0.1.0-alpha.1`, and the CLI and ZK modules carry the tags
`cmd/apostille/v0.1.0-alpha.1` and `apostille/zkbudget/v0.1.0-alpha.1`. No npm
package and no CLI binaries are published.
Core 0.2 is an accepted specification with no implementation or vectors yet;
see the [roadmap](#roadmap).

## Who uses what

- **Recipients of a bundle** verify it in the browser verifier served by the
  hosted service or from this repository, or with the local CLI. Neither needs
  an IFF account, a key lookup or a network connection. With a Go toolchain:

  ```sh
  go install github.com/ifandonlyif-io/iff-apostille/cmd/apostille@v0.1.0-alpha.1
  apostille verify --offline --bundle bundle.json --issuer <exact issuer> --key-id <pinned key id>
  ```
- **Go developers** import the released module:

  ```sh
  go get github.com/ifandonlyif-io/iff-apostille@v0.1.0-alpha.1
  ```

  API reference: [pkg.go.dev](https://pkg.go.dev/github.com/ifandonlyif-io/iff-apostille@v0.1.0-alpha.1/apostille).
  Integration guide: [docs/apostille/SDK.md](docs/apostille/SDK.md).
- **JavaScript developers** pack the SDK from this checkout (see below); a
  registry release is planned separately.
- **Reviewers and independent implementers** start from the specification,
  schema and conformance cases, and from the tagged source on GitHub.

| Component | Source | What it provides |
| --- | --- | --- |
| Core 0.1 | [spec](docs/apostille/spec/core-0.1.md), [schema](web/apostille-0.1.schema.json), [vectors](testdata/apostille/core-0.1.json), [cases](testdata/apostille/core-0.1-cases.json) | Exact bytes and positive/negative verification cases |
| Go | [core](apostille/), [API client](apostille/client/) | Offline signing/verification; explicitly invoked hosted calls |
| JavaScript / TypeScript | [SDK](sdk/apostille-js/) | Offline default import and separate `/client` entry |
| Local CLI | [commands](docs/apostille/CLI.md) | Key generation, signing, local issuance and verification |
| Browser verifier | [source](web/), `make verifier` | Four-language local verification; no key lookup, RPC or telemetry |
| ERC-8004 profile | [spec](docs/apostille/spec/erc8004-binding-0.1.md) | Detached issuer-checked historical ownership evidence |
| Experimental ZK | [guide](docs/apostille/ZK.md), [module](apostille/zkbudget/) | Local committed-budget predicate, Go/CLI only |

## Try the source

Prerequisites: Go toolchain `go1.26.6` (module language minima are in `go.mod`),
Node.js 22+, npm, Python 3 and make. The initial build downloads public
dependencies; signing and offline verification do not need the network.

```sh
make check
make apostille-build
make verifier
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist/verifier
```

Open `http://127.0.0.1:8080/`. Browser ES modules need an HTTP origin, so `file://`
is unsupported. The page uses only local assets and `connect-src 'none'`.
Import a bundle and independently obtained issuer/key pins. The browser does not
generate or verify ZK proofs; use the separate CLI/Go module.

Pack the JS SDK without publishing:

```sh
make sdk
mkdir -p dist
npm pack ./sdk/apostille-js --pack-destination ./dist
```

See [SDK examples](sdk/apostille-js/README.md), [Go integration](docs/apostille/SDK.md)
and [release instructions](docs/apostille/RELEASE.md). The CLI and ZK modules
pin the released root module rather than this checkout; a root change reaches
them at the next root tag (see RELEASE.md for the local development workaround).

## Roadmap

Core 0.2 ([specification](docs/apostille/spec/core-0.2.md),
[schema](web/apostille-0.2.schema.json)) adds an exact identifier grammar, strict
Ed25519 verification and a versioned namespace. It is accepted but has no
reference implementation or conformance vectors; nothing may claim 0.2
conformance yet. The [implementation plan](docs/apostille/proposals/core-0.2-implementation-plan.md)
tracks its status. An npm release of the JS SDK and prebuilt CLI binaries are
also planned; neither is part of `v0.1.0-alpha.1`.

## What verification means

A valid signature establishes integrity and key possession. Accepting an issuer
requires your own exact issuer/key pin. It does not establish content truth,
complete bot history, organization identity, current non-revocation, payment
safety or legal effect. This project is not a Hague Apostille or government
certification. Hashes can still identify/link records; hashing is not anonymization.

ERC-8004 bindings report `issuer_checked` historical observations; current
ownership remains unknown. ZK proves a predicate about the committed input vector,
not that upstream data is complete or truthful. Its single-party development setup
is experimental, has no external audit and is not a production trust ceremony.
Coinbase verification, LEI/vLEI and Cloudflare Wallets remain planned integrations.

The hosted API implementation, tenant database, issuer credentials and production
deployment configuration are outside this source release. The [API contract](docs/apostille/API.md)
documents the client integration surface; it is not a self-hosting package.
These producer records do not feed IFF's x402 monitor, transparency log or reputation.

## Participate

[Contributing](CONTRIBUTING.md) · [Governance](GOVERNANCE.md) ·
[Security](SECURITY.md) · [Conformance](docs/apostille/CONFORMANCE.md)

MIT for original code/specification/schema/vectors; retain the existing copyright
and [third-party notices](docs/apostille/NOTICES.md). Synthetic fixture keys are
public test material: never deploy or trust them. Source publication does not
prove which binary runs on a hosted server.
