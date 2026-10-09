# Apostille documentation

Start with the [source repository overview](../../README.md).

- [Core 0.1 specification](spec/core-0.1.md), [schema](../../web/apostille-0.1.schema.json), [synthetic vectors](../../testdata/apostille/core-0.1.json), [accept/reject cases](../../testdata/apostille/core-0.1-cases.json)
- [SDK integration](SDK.md), [CLI](CLI.md), [hosted API contract](API.md)
- [Hosted issuer key pins and deployment verification](HOSTED_KEYS.md)
- ERC-8004 detached profile: [0.1](spec/erc8004-binding-0.1.md) (Core 0.1, Ed25519) and [0.3](spec/erc8004-binding-0.3.md) (Core 0.3, ML-DSA-65; [vector](../../testdata/apostille/erc8004-binding-0.3.json)); [experimental ZK guide](ZK.md)
- [Conformance](CONFORMANCE.md), [release preparation](RELEASE.md), [notices](NOTICES.md)
- [Core 0.2 specification](spec/core-0.2.md) (accepted; released in v0.3.0-alpha.1), [schema](../../web/apostille-0.2.schema.json), [vectors](../../testdata/apostille/core-0.2.json), [cases](../../testdata/apostille/core-0.2-cases.json), [proposal](proposals/core-0.2-strict-identifiers-and-keys.md), [implementation plan](proposals/core-0.2-implementation-plan.md)
- [Core 0.3 specification](spec/core-0.3.md) (ML-DSA-65; accepted; released in v0.3.0-alpha.1), [schema](../../web/apostille-0.3.schema.json), [vectors](../../testdata/apostille/core-0.3.json), [cases](../../testdata/apostille/core-0.3-cases.json), [proposal](proposals/core-0.3-ml-dsa-65.md), [implementation plan](proposals/core-0.3-implementation-plan.md)
- [Security](../../SECURITY.md), [contributing](../../CONTRIBUTING.md), [governance](../../GOVERNANCE.md)

New keys are ML-DSA-65 (Core 0.3) by default in the SDKs, the CLI and the browser
page from `v0.4.0-alpha.1`; Ed25519 and Core 0.1 remain supported for existing keys and
verification.

Hosted API descriptions document integration behavior; this repository contains
clients and protocol tools, not the hosted server/database/deployment. Local
signing and verification need no IFF account. Coinbase/LEI/vLEI/Cloudflare Wallets
are planned, not currently implemented provider checks.
