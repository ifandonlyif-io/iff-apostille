# Conformance — Core 0.1 alpha

Reference implementations: `apostille/` (Go), `web/apostille-core.mjs`
(WebCrypto), and the JS SDK built from the same browser modules. JSON schema
validation alone does not establish signatures, binding or receiver trust.

```sh
make check
make security
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

Go interoperability tests require Node. They verify the shared Go vector in JS,
and sign with random browser keys, verify/issue in Go, then verify in JS.
Negative cases include signature/payload tampering, wrong issuer/key pins,
source/certificate grafting, missing delegation, wrong audience/purpose,
expired/future grants, duplicate keys, Unicode/BOM/numeric JSON, depth and byte
bounds. The API clients also test response verification and session boundaries.

Offline output leaves organization identity, content truth, current revocation,
log inclusion and anchoring unproven/not provided. Independent issuer acceptance
requires caller-supplied issuer AND key pins. Evaluation time is a caller choice,
not an authenticated timestamp.

ERC-8004 and experimental ZK have separate profiles/tests; neither changes Core
0.1. Passing these suites is not third-party certification or a cryptographic
audit. Compatibility claims apply to the published cases and exact formats.
