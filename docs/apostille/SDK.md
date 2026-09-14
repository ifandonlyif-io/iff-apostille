# Apostille SDK integration — alpha

Use the SDK to sign a file or selected bot record that your application already
has, optionally submit its signed manifest to an issuer, and independently verify
the returned bundle. It does not capture a bot's complete activity, synchronize
records, upload originals or prove that a bot performed the claimed work.

## Packages and release status

| Interface | Location | Network boundary |
| --- | --- | --- |
| JavaScript/TypeScript Core 0.1 | `@ifandonlyif/apostille`, also `/core` | Strictly offline signing and verification |
| JavaScript hosted API client | `@ifandonlyif/apostille/client` | Only explicitly requested API calls |
| Go core and helpers | `github.com/ifandonlyif-io/iff-apostille/apostille` | Local artifact signing and verification |
| Go hosted API client | `github.com/ifandonlyif-io/iff-apostille/apostille/client` | Separate online client |
| Local CLI | `cmd/apostille` | Local files only; no hosted submission command |

The JavaScript package version is **0.1.0-alpha.1 and is not published to npm**.
Use `npm pack` from this checkout and install the resulting `.tgz`, following the
[package README](../../sdk/apostille-js/README.md). The runnable examples import
the installed package rather than files from `web/`. Go code is available in this
checkout; do not assume an SDK release tag or module registry publication. There
is no Python SDK in this iteration.

The JavaScript examples require Node.js 22+. Browser consumers need a secure
context with WebCrypto Ed25519; a bundler can resolve the package's ESM imports.
Both languages use the same Core 0.1 wire artifacts and shared conformance vectors.
See the [normative specification](spec/core-0.1.md) for exact signing bytes.

## A caller-controlled integration

1. Select the original file or serialize the exact bot record in your application.
   Preserve those bytes; changing whitespace in a JSON original changes its digest.
2. Keep administrator and agent keys separately. Register a signed administrator
   delegation and the agent's proof of possession when using hosted issuance.
3. Hash and sign locally. The statement binds artifact digest, size, media type,
   agent and delegation; it does not contain the original file.
4. For hosted issuance, log in and separately create an artifact/audience/visibility-
   bound grant. Choose `private` unless public distribution is explicitly approved.
   Send only statement and grant to `submit` after registering the agent.
5. Save the issuance response and bundle. Download by the returned certificate ID;
   preserve the original independently. A public ID is not private download access.
6. The recipient verifies the bundle offline and separately compares the original.
   If issuer trust is required, supply the exact expected issuer and key fingerprint
   from a source accepted by the recipient's policy.

The [offline example](../../sdk/apostille-js/examples/offline.mjs) generates local
keys and a producer-only bundle, then compares the original without network access.
The [hosted example](../../sdk/apostille-js/examples/hosted.mjs) requires `--submit`
before any request and defaults to private issuance. `--public` is an additional
explicit publication choice. It does not make the workspace profile public.
Both examples use `.apostille-private/`, private file permissions and exclusive
creation for new outputs. These paths are excluded from Git and Docker in this
repository; add the same exclusions in another project. The example reads files
into memory with a 64 MiB input cap; use the [CLI](CLI.md) for streamed larger files.

## Go: stream a caller-supplied original, then explicitly submit

The following functions compile against this checkout. `demoSigner` generates a
temporary key locally; call it separately for administrator and agent in a
disposable demonstration. For continuing use, persist the generated seed securely
before registering, then load it with `core.NewSigner` on later runs. Do not log
seeds or generate a replacement administrator key on each bot execution: the
workspace is bound to that key, and the alpha has no account recovery.

`submitPrivate` is an online operation only when the caller invokes it. Pass an
original `io.Reader` that you opened yourself, your two signers, and the intended
API base URL and exact issuer. `CreateStatement` streams the reader locally;
neither the original nor the private keys are sent to the API.

```go
package example

import (
	"context"
	"io"
	"time"

	core "github.com/ifandonlyif-io/iff-apostille/apostille"
	"github.com/ifandonlyif-io/iff-apostille/apostille/client"
)

func demoSigner() (*core.Signer, error) {
	seed, _, err := core.GenerateKey()
	if err != nil {
		return nil, err
	}
	return core.NewSigner(seed) // Demo only: the seed is not persisted here.
}

func submitPrivate(ctx context.Context, original io.Reader, admin, agent *core.Signer,
	baseURL, issuer string) (issued client.Certificate, err error) {
	now := time.Now().UTC()
	reg, err := core.CreateRegistration(admin, agent, issuer, 30*24*time.Hour, now)
	if err != nil {
		return issued, err
	}
	statement, err := core.CreateStatement(original, "application/octet-stream", agent, &reg, "", now)
	if err != nil {
		return issued, err
	}
	c, err := client.New(client.Config{BaseURL: baseURL, Issuer: issuer})
	if err != nil {
		return issued, err
	}
	defer c.ClearSession()
	if _, err = c.Login(ctx, admin); err != nil {
		return issued, err
	}
	if _, err = c.RegisterAgent(ctx, "Go example agent", reg); err != nil {
		return issued, err
	}
	grant, err := core.CreateGrant(statement, reg, admin, issuer, "private", time.Now().UTC())
	if err != nil {
		return issued, err
	}
	issued, err = c.Submit(ctx, statement, grant)
	if err != nil {
		return issued, err
	}
	downloaded, err := c.GetBundle(ctx, issued.ID)
	if err != nil {
		return issued, err // Preserve issued.ID and issued.Bundle on download failure.
	}
	issued.Bundle = downloaded.Bundle
	return issued, nil
}
```

This single-run example registers a new agent each time. A continuing integration
must also save and reuse its registration, retain the statement/grant before
submission and durably save the issuance response. Agent registration is capped;
do not turn this function into an automatic recorder/retry loop. Keep the original
separately and retain a nonempty returned certificate even if a later download
fails. Login does not publish a profile, and the grant above explicitly authorizes
private issuance only.

For offline Go verification, call `core.VerifyBundle(bundle, core.VerifyOptions{
ExpectedIssuer: expectedIssuer, TrustedKeyIDs: []string{independentKeyID},
Now: evaluationTime})`, check the returned policy dimensions, and separately call
`core.VerifyArtifact(result, originalBytes)` when comparing an original. Loading
that original and deciding the issuer/key pin remain caller responsibilities.

## What each verification result means

`verifyBundle` checks signatures and the bindings between attached artifacts.
It throws on invalid Core input; a successful result still contains separate
policy dimensions. `verifyArtifact(result, originalBytes)` compares the supplied
original digest and length. Call it when the original is part of your decision.

- `artifact_integrity: valid` is signature/binding validity, not content truth.
- `certificate_scope: producer_only` means no issuer certificate is attached.
- `issuer_trust: unknown` means no trust decision was established. Supplying an
  exact issuer plus matching independently obtained key pin can return
  `accepted_by_policy`; mismatching or incomplete certificate pins are `untrusted`.
- `freshness` depends on the explicit evaluation time. An accepted issuer pin does
  not override expiry or establish current revocation status.
- `organization_binding: unproven`, `content_truth: not_established` and current
  revocation unknown remain real limitations of the alpha.

Neither core verifier fetches a key directory, schema, status, provider evidence,
RPC response or telemetry. The online `keys()` method only retrieves the current
directory. Calling it does not configure a verifier's trust policy. Keep historical
pins separately when the issuer rotates keys; signed key/status history is not
included in this alpha.

## Hosted operation and failure handling

The JavaScript constructor is `new ApostilleClient({baseURL, issuer, accessToken?,
timeoutMs?, allowInsecureLocalhost?})`. Set `baseURL` to the full API namespace,
for example `https://ifandonlyif.io/api/apostille/v1`, and `issuer` to the exact
signed audience, for example `https://ifandonlyif.io/apostille`. These identifiers
are different. Constructing the client has no network side effect. The loopback
HTTP exception is opt-in for local development, never a production default.

`login(signer)` checks the challenge's expected issuer/key and signs it locally,
then retains the returned bearer token in memory. It does not send or save a
private key. `clearSession()` forgets this client's token; it does not revoke an
already issued bearer token. Hosted tokens last 15 minutes. No automatic token
refresh, re-login, publication or retry is performed. A reusable bot integration
must deliberately decide when to authenticate and which records to submit.

If a submission response is lost, the server may already have issued the
certificate. Use authenticated history and download before creating another
grant. Server idempotency uses the signed grant nonce and exact submission hash;
replaying an expired grant or revoked authorization is not a recovery mechanism.
The example saves statement/grant before submission and the returned bundle before
its separate download, so partial failures leave local recovery material.

Consult [API.md](API.md) for current routes, response shapes, errors and limits.
The SDK does not bypass the 256 KiB JSON body limit, 100-agent workspace limit,
100-new-certificates/day quota, tenant access or separate publication grant.
`hideCertificate` only stops future public serving; it cannot erase copies already
distributed or turn a private certificate public. Agent revocation is irreversible.

Hosted issuance is opt-in on the server and requires migration `000010`, the
independent API-only signing key and existing production authentication/Redis
configuration. A local SDK install does not imply the public service is enabled.
These producer statements remain isolated from x402 observations, public cards,
status webhooks, transparency logs and ERC-8004 reputation.

## Optional ERC-8004 identity binding

The Go hosted client exposes `ERC8004Config`, `CreateERC8004Binding`, and
`GetERC8004Binding` for the optional, private detached ERC-8004 binding profile
0.1. It is not a Core 0.2 organization binding and does not change Core 0.1
signed envelopes or bundles. Build the request locally with
`core.CreateERC8004Request`, obtain the EOA owner's exact EIP-191 signature over
`core.ERC8004OwnerMessage`, then submit both explicitly. The client verifies
each returned snapshot locally against its configured issuer and optional
independent key pins. A snapshot records issuer-checked ownership at its signing
time; it never establishes current ownership, organization identity, or payment
authority. This profile is separate from Core 0.1 bundles and is not published by
a public workspace. The authenticated administrator thereby authorizes an
identity connection; it remains isolated from x402 v3 evidence, reputation,
anchors, and payment flows.

`ERC8004Config()` calls the public `/erc8004/config` route without a bearer
token. Create and retrieval use the private `POST` and `GET
/agents/{id}/erc8004` routes. Binding creation is capped at 100 new requests per
workspace per UTC day and currently shares the login-challenge per-IP rate-limit
bucket. Rechecking ownership requires a new signed request. An exact same-nonce
retry returns the original snapshot; changed content for the same nonce is an
idempotency conflict. The API's `issuer_checked` snapshot is an EOA-only
observation of owner matching at finalized canonical and latest state; it makes
no current ownership, company, or payment claim.

The server defaults `APOSTILLE_ERC8004_ENABLED=false`. When enabled, its API
role needs either `ETHEREUM_RPC_URL` with `ERC8004_IDENTITY_REGISTRY_ETH`, or
`BASE_RPC_URL` with `ERC8004_IDENTITY_REGISTRY_BASE`; it requires no transaction
key. Persistence is migration `000011_apostille_erc8004_binding`. Assign any
future Coinbase migration the next available number rather than reusing `000011`.
Check `/api/apostille/v1/erc8004/config` for runtime availability; operators must verify their production RPCs before enabling the feature.

## Experimental local ZK budget SDK

`apostille/zkbudget` and `cmd/apostille` are independent Go modules so their
gnark 0.16.3 / gnark-crypto 0.21.0 dependencies do not upgrade the production
server's root graph (gnark-crypto 0.18.1). Both use Go 1.25.7+ and the pinned
Go 1.26.6 toolchain. Use `make apostille-build` to build the CLI and
`make apostille-local-test` to build, vet and race-test both modules. Ordinary
root `go test ./...` does not traverse nested modules; CI runs them explicitly.
Do not add a shared `go.work`, which would combine module version selection.

These modules are available from this checkout, with local `replace` directives;
no module release is advertised. An external prototype must explicitly replace
both `github.com/ifandonlyif-io/iff-apostille` and
`github.com/ifandonlyif-io/iff-apostille/apostille/zkbudget` with their local
checkout directories. A dependency's `replace` directives are not inherited.

Importing `zkbudget` disables **gnark's process-wide logger** once during package
initialization. This keeps compile/prove/verify progress out of SDK stdout/JSON,
and also affects other gnark users in the same process. If progress is required,
configure `github.com/consensys/gnark/logger.Set` explicitly at application
startup before concurrent gnark operations. Do not toggle it per request;
`solver.WithLogger` alone does not control the other components' logger.

The Go package `apostille/zkbudget` provides `NewSnapshot`, `SignSnapshot`,
`NewRequest`, `Setup`, `InspectCircuit`, `NewProver` and `NewVerifier` for the detached
`zk-budget/0.1` profile. It proves that all 1–16 committed unsigned amounts sum
to no more than a receiver-selected limit, while keeping the amounts and
blinding local. Source authenticity uses existing Core 0.1 signatures. The
verification key, source key and receiver request must be selected independently
of the proof. See the [walkthrough](ZK.md) and [profile](spec/zk-budget-0.1.md).

This alpha uses a development single-party trusted setup. The JavaScript SDK,
browser verifier and hosted API do not evaluate ZK proofs; ordinary Core
verification of a signed artifact must not be interpreted as ZK verification.
The Go result records `EvaluatedAt` (`evaluated_at` in JSON) as the caller's exact
UTC evaluation time and separately reports committed-vector completeness, unknown
current authorization and caller-managed replay protection. `InspectCircuit()`
reproduces the local `circuit_sha256` for comparison with setup metadata, without
a trusted setup. It does not certify a remote key's relationship to that circuit. Source business truth and
payment authority are not established.

No Coinbase/LEI/vLEI/Cloudflare identity integration, recorder, redaction engine,
signed status snapshot, Merkle log, SCITT/VC profile, anchor or payment operation
is implemented by this SDK. The [alpha capability guide](README.md) remains the
service boundary; successful example runs are self-tests, not external adoption.

## Download verification policy

Both hosted clients enforce their configured exact issuer for downloaded owner and
public certificates. JavaScript `getBundle()` returns `{ bundle, verification }`;
Go `GetBundle()` returns `client.VerifiedBundle`. Public certificate records also
include `verification` / `Verification`. Keep `bundle` as the portable signed file.

Optionally configure independently established `trustedKeyIDs` (JavaScript) or
`TrustedKeyIDs` (Go). With a matching pin the result is `accepted_by_policy`; without
a key pin it is `untrusted`, even when the issuer matches. Issuer or configured-key
mismatches and invalid certificates fail with `invalid_certificate_response`.
The same policy is applied to `submit()` responses. Keys are never fetched or
automatically trusted. Freshness is evaluated at download time; content truth and
current revocation remain unproven/unknown.
