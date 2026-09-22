# Apostille by IFF

Portable, issuer-neutral signatures for agent artifacts. An agent signs a file
manifest, an administrator delegates its key, and an issuer records the checks
it performed. A recipient can verify the resulting bundle locally, without an
IFF account or an Internet connection. You can use the SDK or implement the
published specification and conformance vectors yourself.

**Source preview / alpha.** Core protocol `0.1` and SDK package
`0.1.0-alpha.1` are different version namespaces. No npm package, downloadable
CLI release or Go module release is claimed by this preview.

| Component | Source | What it provides |
| --- | --- | --- |
| Core 0.1 | [spec](docs/apostille/spec/core-0.1.md), [schema](web/apostille-0.1.schema.json), [vectors](testdata/apostille/core-0.1.json), [cases](testdata/apostille/core-0.1-cases.json) | Exact bytes and positive/negative verification cases |
| Core 0.2 | [spec](docs/apostille/spec/core-0.2.md), [schema](web/apostille-0.2.schema.json) | Accepted profile: exact identifier grammar, strict Ed25519, versioned namespace; no implementation or vectors yet |
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
and [release instructions](docs/apostille/RELEASE.md). Nested CLI/ZK modules have
local `replace` directives for source builds: do not use `go install ...@version`
or copy only one nested module from this preview.

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
