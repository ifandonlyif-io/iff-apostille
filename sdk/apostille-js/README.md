# Apostille JavaScript SDK — 0.1.0-alpha.1

`@ifandonlyif/apostille` is an ESM JavaScript package with TypeScript declarations
for Apostille Core 0.1. This alpha is **not published to the npm registry**. Install
a locally packed archive from this checkout. Node.js 22 or later is required for
the examples; browser use requires WebCrypto Ed25519 in a secure context.

The main import and `/core` entrypoint are strictly offline. They sign the bytes
the caller supplies and verify portable bundles. The separate `/client` entrypoint
makes explicitly requested hosted API calls. Neither entrypoint is a complete bot
recorder: collecting bot records, selecting files, retaining originals and deciding
what may be submitted remain the application's responsibility.

The separate experimental ZK budget profile currently requires the repository's
Go `apostille/zkbudget` package or `apostille zk-verify` CLI. This JavaScript SDK
does not generate or verify ZK proofs. Verifying a Core signature over a snapshot
manifest only authenticates that manifest; it does not establish its budget
predicate. See [ZK guide](https://github.com/ifandonlyif-io/iff-apostille/blob/main/docs/apostille/ZK.md).

## Install this checkout locally

From the repository root, pack the SDK and install it into an isolated example
directory. `npm pack` creates a local archive; it does not publish anything.

```bash
mkdir -p output/apostille-sdk-demo
npm pack ./sdk/apostille-js --pack-destination ./output/apostille-sdk-demo
cd output/apostille-sdk-demo
npm init -y
npm install --ignore-scripts ./ifandonlyif-apostille-0.1.0-alpha.1.tgz
cp node_modules/@ifandonlyif/apostille/examples/*.mjs .
```

The archive contains the runtime modules, declarations, examples, [specification](spec/core-0.1.md),
schema, test vector and MIT license. The repository excludes `output/` and `.apostille-private/`
from Git and Docker contexts. In a different project, add equivalent exclusions;
private key JSON files contain usable seeds. Keep production keys in a suitable
secret store outside the checkout. Example keys are saved with `0600` permissions
inside private directories on Unix.

The package also includes the optional, separate ERC-8004 binding profile. It
does not extend Core bundles. `createERC8004Request()` signs a five-minute
administrator request, `erc8004OwnerMessage()` reconstructs the exact EIP-191
text for an EOA wallet, and `verifyERC8004Binding()` verifies a returned snapshot
offline. The verifier performs no wallet recovery or chain lookup. It reports the
issuer's recorded check as `provider_evidence: issuer_checked` while keeping
`current_ownership: unknown`, `organization_binding: unproven`, and
`payment_authority: not_established` separate.

```js
import {
  createERC8004Request,
  erc8004OwnerMessage,
  verifyERC8004Binding,
} from '@ifandonlyif/apostille';

const request = await createERC8004Request(admin, registration, {
  chain_id: '8453',
  registry_address: '0x1111111111111111111111111111111111111111',
  erc8004_agent_id: '42',
  owner_address: '0x2222222222222222222222222222222222222222',
}, issuer);
const walletText = await erc8004OwnerMessage(request);
// Ask the user's EOA wallet to personal_sign walletText only after an explicit UI action.
const result = await verifyERC8004Binding(bindingDocument, {
  issuer,
  trustedKeyIDs: [independentlyPinnedIssuerKey],
  now: new Date(),
});
```

## Offline signing and verification

Run the copied example with an original file you choose:

```bash
node offline.mjs /absolute/path/to/your-record.json
```

It generates local administrator and agent keys, a delegation and signed artifact
manifest, then saves and verifies a producer-only bundle. It also compares the
supplied original's SHA-256 and size. It never connects to IFF. The bundle has
`certificate: null`, `certificate_scope: producer_only` and
`issuer_trust: unknown`; local signatures do not establish content truth or a
verified organization. The example reads up to 64 MiB into memory; use the
streaming CLI for larger files ([CLI guide](https://github.com/ifandonlyif-io/iff-apostille/blob/main/docs/apostille/CLI.md)).

For a certificate received separately, load its JSON and your original locally:

```js
import { readFile } from 'node:fs/promises';
import { decodeBytes, verifyBundle, verifyArtifact } from '@ifandonlyif/apostille';

const result = await verifyBundle(decodeBytes(await readFile('bundle.json')), {
  issuer: 'https://issuer.example/apostille',
  keyIDs: ['sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'],
  at: new Date(),
});
const originalMatches = await verifyArtifact(result, new Uint8Array(await readFile('record.json')));
if (result.issuer_trust !== 'accepted_by_policy' ||
    result.freshness !== 'valid_at_evaluation_time' || !originalMatches) {
  throw new Error('The bundle does not satisfy this application\'s trust/original policy.');
}
```

Replace the example issuer and fingerprint with independently established values.
An embedded key or a fresh `/keys` response is not automatically a trust pin.
Verification performs no key, status, schema, provider or telemetry fetch.
`artifact_integrity: valid` concerns signatures and bindings; original-file
comparison is a separate operation. Check the returned freshness under your own
policy; current revocation remains unknown even when a pin is accepted.

## Explicitly online hosted client

```js
import { ApostilleClient } from '@ifandonlyif/apostille/client';

const client = new ApostilleClient({
  baseURL: 'https://ifandonlyif.io/api/apostille/v1',
  issuer: 'https://ifandonlyif.io/apostille',
  timeoutMs: 10_000,
});
const status = await client.status(); // This line makes a network request.
```

Constructing a client does not connect or publish. The constructor may also take
`accessToken` and `allowInsecureLocalhost`; the latter is an explicit development
exception for a loopback HTTP service. Hosted issuance must be enabled by the
service operator; this alpha's local availability does not prove production is
enabled or deployed.

`hosted.mjs` makes **no request without `--submit`**. To run it against a service
you intend to use, set both its API base URL and exact issuer identifier:

```bash
export APOSTILLE_BASE_URL='https://ifandonlyif.io/api/apostille/v1'
export APOSTILLE_ISSUER='https://ifandonlyif.io/apostille'
node hosted.mjs /absolute/path/to/your-record.json --submit
```

This opts into login/workspace creation, agent registration and **private**
issuance. Add `--public` only to approve public distribution of the complete
signed bundle. It includes linkable public keys, UUIDs, timestamps, digest and
size; the original file and private keys remain local. A public certificate does
not automatically make the workspace profile public. The example reuses the
saved administrator, agent and registration in `.apostille-private/hosted-example`;
back them up. It does not recover lost keys or refresh an expired delegation.
Use `APOSTILLE_STATE_DIR` for a separate demonstration workspace and independently
obtain `APOSTILLE_ISSUER_KEY_ID` if the downloaded certificate must satisfy a pin.

The example creates a separate visibility-bound signed grant immediately before
submission, saves the returned bundle, then downloads it by certificate ID. It
does not call `keys()` to silently establish trust. API calls have no automatic
retry. A timeout may happen after the server commits; inspect `me()` and retrieve
the existing bundle before submitting a fresh grant. An identical submission is
idempotent only while its original grant and authorization remain valid.

`registerAgent()` accepts both a new 201 response and an identical 200 replay.
Retry with the same signed delegation and workspace to retrieve the original
record, even when the agent quota is full; a changed display name does not update
it. A different delegation for an existing agent ID returns 409
`agent_already_registered`. Replays still require valid current authorization.

The SDK and console share a 10-second default request deadline and an 8 MiB
response byte cap. The deadline covers headers and body streaming; a response
over the cap is canceled. The SDK reports `request_timeout` or
`response_too_large`, and the console clears its working message with an error.

| Client method | Purpose |
| --- | --- |
| `status()`, `keys()` | Read capabilities or the current public key directory |
| `createChallenge(publicKey)`, `login(signer)` | Create a challenge or sign in; `login` keeps its bearer token in client memory |
| `setAccessToken(token)`, `clearSession()` | Set or forget the in-memory token; clearing does not revoke an already issued token |
| `me()`, `updateWorkspace({name, is_public})` | Read own records or explicitly change the profile |
| `registerAgent(name, registration)`, `revokeAgent(id)` | Register signed delegation/PoP or irreversibly revoke an agent |
| `erc8004Config()` | Read the public, credential-free registry capability list |
| `createERC8004Binding(id, request, ownerSignature)`, `getERC8004Binding(id)` | Create or retrieve a private ERC-8004 snapshot and verify the response locally |
| `submit(statement, grant)`, `getBundle(id)` | Submit signed metadata or download your certificate bundle |
| `hideCertificate(id)` | Hide an existing public certificate; this cannot publish a private one |
| `getPublicCertificate(publicID)`, `getPublicOrganization(publicID)` | Read explicitly public records |

The client accepts neither raw-file uploads nor private-key API parameters.
`createChallenge()` and `login(signer)` validate the complete message against the
configured issuer, key ID, UUID v4 challenge ID, canonical UTC expiry (future and
at most seven minutes away), and exact `register_or_login` purpose before signing.
Altered or extended messages fail with `invalid_challenge`; `signLogin()` also
enforces this structure when used directly. The browser console shares this check.

`login(signer)` signs locally; it does not persist the signer. Login is separate
from publication authorization. The service has tenant, token, grant, size and
rate limits; see [API guide](https://github.com/ifandonlyif-io/iff-apostille/blob/main/docs/apostille/API.md).

Owner routes use `Authorization: Bearer <token>`; the server accepts any case for
the scheme and HTTP whitespace between it and the token. SDK and console requests
to `/status`, `/keys`, login and `/public/*` omit the token.

Challenge requests default to 10 per client IP per minute (server configuration:
`APOSTILLE_CHALLENGE_RATE_LIMIT_PER_MINUTE`). A 429 `challenge_rate_limit` error
exposes `retryAfter` in seconds. Creating more challenges keeps only the latest
five unconsumed challenges for that key; obtain a new one if an older one was
invalidated. Daily issuance limits reset at the UTC boundary of the API issuance
clock; a quota 429 exposes the same boundary through `retryAfter`.

This iteration does not include a Python SDK, bot recorder, Coinbase/LEI/vLEI or
Cloudflare identity verification, signed status history, Merkle log, SCITT profile,
anchor or payment functionality. See [SDK guide](https://github.com/ifandonlyif-io/iff-apostille/blob/main/docs/apostille/SDK.md)
for the JavaScript/Go boundaries and integration checklist.

## Download verification

`getBundle(id)` returns `{ bundle, verification }`; `getPublicCertificate(id)` adds
`verification` to its public record. Both require an issuer certificate matching
the exact configured `issuer`. Set optional `trustedKeyIDs: [independentKeyID]` to
enforce an independently obtained key pin. Without pins, `issuer_trust` is
`untrusted`; a matching pin yields `accepted_by_policy`. A mismatched issuer or
configured pin fails with `ApostilleAPIError` code `invalid_certificate_response`.
The same issuer/key checks apply to `submit()` responses. Do not use `/keys` as an
automatic trust source. Save the returned `bundle` as the portable signed file;
`verification` is local policy output, including freshness at download time.

```js
const { bundle, verification } = await client.getBundle(certificateID);
console.log(verification.issuer_trust);
```
