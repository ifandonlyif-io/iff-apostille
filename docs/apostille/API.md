# Hosted API — alpha

Base: `/api/apostille/v1`. This namespace is separate from x402 `/api/v3`.
Write requests use `Content-Type: application/json`, strict UTF-8 JSON ≤256 KiB;
duplicates, unsupported fields and numeric request values are rejected.
No multipart upload or private-key parameter is accepted. JSON API responses
may contain numeric operational metadata such as `expires_in`; signed artifacts
follow the numeric-free Core profile.

The experimental `zk-budget/0.1` profile runs through the local Go SDK/CLI;
there is no hosted ZK proving or verification endpoint. Existing submission
routes may certify a source's signed commitment manifest under their existing
publication grants, but never evaluate the budget predicate. A valid origin
certificate alone is not a valid budget proof. See the [ZK guide](ZK.md).

| Method/path | Input / result |
| --- | --- |
| GET `/status` | Protocol, configured issuer, enabled flag, authoritative `limits.max_agents` and `limits.max_daily_certificates`, implemented/planned capabilities |
| GET `/keys` | Current issuer public key/fingerprint; online bootstrap only |
| POST `/auth/challenges` | `{public_key}` → 201 `{challenge_id,message,expires_at,issuer}`; 10/client IP/minute by default and latest 5 unconsumed per public key retained |
| POST `/auth/verify` | `{challenge_id,message,signature}` → `{access_token,token_type,expires_in,workspace}` |
| GET `/me` | Own workspace, registered agents and recent certificates; the current workspace limits are returned by `/status` |
| PUT `/workspace` | `{name,is_public}` → own updated profile |
| POST `/agents` | `{name,delegation,acceptance}` → 201 agent record; identical replay → 200 stored record |
| POST `/agents/{id}/revoke` | Irreversibly stops new issuance for this agent |
| GET `/erc8004/config` | Public detached ERC-8004 binding configuration; no bearer token is sent |
| POST `/agents/{id}/erc8004` | Own signed binding request and EOA owner signature → private immutable binding snapshot |
| GET `/agents/{id}/erc8004` | Latest own private binding snapshot; other tenants receive 404 |
| POST `/submissions` | `{statement,grant}` → 201 certificate record including `bundle`; identical live-grant retry → 200 stored record |
| GET `/certificates/{id}/bundle` | Own signed bundle; other tenants receive 404 |
| POST `/certificates/{id}/hide` | Stops public serving; cannot publish a private certificate |
| GET `/public/certificates/{public_id}` | Explicitly public bundle only; 404 when private/hidden |
| GET `/public/organizations/{public_id}` | Explicitly public name/profile, marked self-declared |

GET routes also support HEAD. Protected routes (from `/me` through certificate
hiding) use `Authorization: Bearer <access_token>`; the scheme is
case-insensitive and standard HTTP whitespace is accepted. Tokens last 15 minutes and
cannot authorize legacy endpoint-owner routes. The challenge signature is raw
Ed25519 over the returned exact UTF-8 message, then unpadded base64url; it uses a
separate login purpose/domain, never the artifact signing preimage. Check expected
issuer/key before signing. The console and JS SDK reconstruct the entire message
from the expected issuer, administrator key ID, UUID v4 challenge ID and canonical
UTC expiry in seconds. Expiry must be in the future and at most seven minutes away;
the purpose must be exactly `register_or_login`, with no extra lines. No signature
is made unless the reconstruction matches every byte. Obtain a new challenge
after expiry or replay.
Expired challenges are deleted immediately in bounded batches. Creating a sixth
pending challenge for the same administrator key succeeds and invalidates the
oldest pending challenge, retaining the latest five.
`APOSTILLE_CHALLENGE_RATE_LIMIT_PER_MINUTE` configures the dedicated IP limit
(default 10) when rate limiting is enabled. Exceeding it returns 429
`challenge_rate_limit` with `Retry-After` in seconds. Cleanup removes up to 1,000
expired rows per insertion.

ERC-8004 binding is an optional, detached [binding profile 0.1](spec/erc8004-binding-0.1.md). It is
not the planned Core 0.2 organization binding and never alters Core 0.1 signed
envelopes or bundles. An authenticated workspace administrator explicitly
authorizes the connection by signing the request and obtaining the specified
agent token owner's EIP-191 signature. The API observes an EOA owner at both a
finalized canonical block and latest state, then issues an `issuer_checked`
snapshot. It does not claim current ownership, company identity, or payment
authority. The returned document supports offline integrity verification;
issuer trust additionally requires an independently supplied exact issuer/key
pin. Verification never fetches keys or chain state.

The profile is disabled unless `APOSTILLE_ERC8004_ENABLED=true`; its default is
`false`. Enable either the existing Ethereum pair `ETHEREUM_RPC_URL` and
`ERC8004_IDENTITY_REGISTRY_ETH`, or the Base pair `BASE_RPC_URL` and
`ERC8004_IDENTITY_REGISTRY_BASE`. It runs in the API role and needs no
transaction signing key. Migration `000011_apostille_erc8004_binding` stores
the private immutable snapshots. A future Coinbase migration must use the next
available migration number, never reuse `000011`.

The quota is 100 new binding requests per workspace per UTC day. This release
also shares the login-challenge per-IP rate-limit bucket. A recheck always uses
a new signed request. Retrying the same nonce and exact request returns 200 with
the original snapshot; the same nonce with different request content returns
409. This profile remains isolated from x402 v3 cards, observations, webhooks,
transparency logs, anchors, and ERC-8004 reputation.

Build delegation, acceptance, statement and grant with the browser core or CLI;
see the normative spec for byte-level signing. Hosted service resolves the agent
from its tenant registration, checks administrator/grant/digest/audience, and
does not accept an arbitrary certificate supplied by a client. New certificates
last at most 24 hours, capped by delegation expiry. Agent registration is capped
at one year; the browser uses 30 days. The 100-certificate quota is evaluated
against the API issuance clock and resets at the next UTC day boundary;
`Retry-After` uses that same boundary.

Idempotency uses the signed grant nonce plus a canonical hash of the entire
submission. Same nonce/different content returns 409. Retry requires grant and
agent authorization still valid at the API boundary; after expiry use authenticated
history/download instead of assuming a replay will issue or return a certificate.
The store preserves the original certificate on replay, even after hiding it.
Agent registration is also idempotent: a valid retry for the same workspace and
signed delegation returns the original immutable record, including after the
workspace reaches its agent quota. Request fields such as a changed display name
do not rewrite that record; the same agent ID with a different delegation returns
409.

Errors use `{error:true,code,message}`. Client-actionable codes include
`invalid_request`, `invalid_public_key`, `invalid_profile`, `invalid_agent`,
`delegation_exceeds_one_year`, `invalid_source_statement`, `invalid_submission`,
and `submission_too_large` (400); `authentication_required`,
`invalid_authentication_proof`, and `invalid_session` (401);
`invalid_agent_authorization`, `invalid_publication_grant`, `agent_inactive`, and
`source_authorization_inactive` (403); `agent_not_found`, `certificate_not_found`,
and `profile_not_found` (404); `idempotency_conflict`, `agent_already_registered`,
and `agent_limit_reached` (409); `challenge_rate_limit` and
`daily_submission_limit` (429 plus Retry-After); `apostille_service_unavailable`
and `challenge_rate_limit_unavailable` (503). Input/auth errors intentionally do
not echo raw signed data or secrets.

The JS SDK and console default to a 10-second deadline (including response reads)
and an 8 MiB streaming response cap. Only owner requests attach bearer tokens;
status, keys, login and public routes omit them.

No public listing/search API, provider validation, log/anchor action, public
republication boolean, or account recovery endpoint exists in this alpha.

### SDK download policy

The HTTP bundle response is unchanged. Hosted SDKs require the configured exact
issuer on downloaded certificates, return local verification alongside the
portable bundle, and optionally enforce independently configured issuer key pins.
See [SDK integration](SDK.md) for the new download return shape and
`invalid_certificate_response` errors. No `/keys` result is automatically trusted.
