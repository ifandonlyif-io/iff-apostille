# Apostille documentation

Start with the [source repository overview](../../README.md).

- [Core 0.1 specification](spec/core-0.1.md), [schema](../../web/apostille-0.1.schema.json), [synthetic vectors](../../testdata/apostille/core-0.1.json), [accept/reject cases](../../testdata/apostille/core-0.1-cases.json)
- [SDK integration](SDK.md), [CLI](CLI.md), [hosted API contract](API.md)
- [ERC-8004 detached profile](spec/erc8004-binding-0.1.md), [experimental ZK guide](ZK.md)
- [Conformance](CONFORMANCE.md), [release preparation](RELEASE.md), [notices](NOTICES.md)
- Proposals (not implemented): [Core 0.2 identifier grammar and strict Ed25519](proposals/core-0.2-strict-identifiers-and-keys.md), [its implementation plan](proposals/core-0.2-implementation-plan.md)
- [Security](../../SECURITY.md), [contributing](../../CONTRIBUTING.md), [governance](../../GOVERNANCE.md)

Hosted API descriptions document integration behavior; this repository contains
clients and protocol tools, not the hosted server/database/deployment. Local
signing and verification need no IFF account. Coinbase/LEI/vLEI/Cloudflare Wallets
are planned, not currently implemented provider checks.
