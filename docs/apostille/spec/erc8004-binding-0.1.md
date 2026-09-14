# ERC-8004 binding profile 0.1

This optional profile links an existing Apostille agent registration to an ERC-8004 Identity Registry token. It is a separate document, not a Core 0.1 extension: no Core payload, signature, bundle, organization claim, x402 evidence, reputation, or anchor changes. The API stores it privately. A public workspace does not publish it.

Profile: `https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.1`.
Its envelopes use the Core envelope container and strict string-quantity/JCS rules, but this profile's protocol, kinds and signature domains. Core 0.1 verifiers reject these envelopes. A dedicated verifier handles them without network access.

## Request and consent

`erc8004-binding-request` has the five Header fields (`protocol`, `kind`, `issuer`, `issuer_key_id`, `issued_at`) and exactly:

`agent_id`, `agent_key_id`, `delegation_sha256`, `service_audience`, `chain_id`, `registry_address`, `erc8004_agent_id`, `owner_address`, `nonce`, `expires_at`, `purpose`.

The administrator signs it. `issuer` is its `urn:apostille:key:<key_id>` identity. The local registration supplies the exact Apostille UUID, agent key and delegation digest. `service_audience` is the intended Apostille issuer. `purpose` is `link_identity_private`. Nonce is a random UUIDv4. Issuance/expiry are UTC seconds, maximum five minutes apart. The request must be active when checked and signed, with at most two minutes of future-clock tolerance. Addresses are nonzero, lowercase `0x` plus 40 hex digits. Chain ID is a positive uint256 decimal string; token ID is a uint256 decimal string including zero; no leading zeroes. The hosted adapter initially supports configured Ethereum (1) and Base (8453) registries only.

Admin signature input is UTF-8 `iff-apostille/erc8004-binding/request/0.1\n` followed by the raw 32-byte SHA-256 of canonical payload bytes. The owner then uses EIP-191 `personal_sign` on this exact text (no trailing newline):

```text
iff-apostille/erc8004-binding/owner/0.1
issuer:<service_audience>
admin_key_id:<issuer_key_id>
agent_id:<agent_id>
agent_key_id:<agent_key_id>
delegation_sha256:<delegation_sha256>
chain_id:<chain_id>
registry_address:<registry_address>
erc8004_agent_id:<erc8004_agent_id>
owner_address:<owner_address>
nonce:<nonce>
issued_at:<issued_at>
expires_at:<expires_at>
purpose:link_identity_private
request_sha256:<SHA-256 of complete canonical request envelope>
```

Clients reconstruct this text locally. Login is not this consent. No transactions, token approvals, registration minting, wallet private keys, agentWallet/payment authority, or operator approvals are involved. EOA owner signatures only; contract wallets and delegated-code wallets are unsupported in this version.

## Issuer snapshot

The server verifies administrator signature, active stored registration, tenant scope, EIP-191 owner signature and an allowlisted registry. It queries chain ID, a fresh finalized block, registry code, `ownerOf(uint256)` and owner code at that block hash. It also checks latest owner against the signed owner to reject already-observed transfers. All reads are bounded and read-only; a client cannot choose an RPC URL. A finalized block more than one hour old or over two minutes in the future is rejected. RPC responses are evidence observed by the issuer, not a portable Ethereum state proof.

`erc8004-binding` payload has the five Header fields plus exactly:

`request` (the complete signed request envelope), `owner_signature` (lowercase 65-byte 0x hex), `block_number` (uint256 decimal string), `block_hash` (0x + 64 lowercase hex digits), `block_timestamp` (UTC seconds), `expires_at`, `check` (`owner_of_eoa`).

The issuer signs UTF-8 `iff-apostille/erc8004-binding/snapshot/0.1\n` followed by the raw SHA-256 of canonical payload bytes. Snapshot expiry is no later than one hour after issuance or delegation expiry, whichever comes first. The request must have been active at snapshot issuance. The document has exactly `protocol`, `binding`, `delegation`, `acceptance`; the latter two retain their original Core 0.1 envelopes. The binding signs the complete request, including admin signature and exact registration digest, and the EIP-191 signature.

Offline verification checks both Ed25519 signatures, all profile constraints, the Core registration at snapshot issuance, and all cross-bindings. The issuer's owner-signature and chain checks are reported as `provider_evidence=issuer_checked`; the browser does not independently recover the EVM signer or verify a chain state proof. `current_ownership=unknown`, `organization_binding=unproven`, and `payment_authority=not_established` always remain separate. Without an external exact issuer/key pin, `issuer_trust=unknown`; a supplied issuer mismatch is an error. Freshness is `within_validity`, `expired`, `not_yet_valid`, or `not_checked`; a fresh snapshot still does not establish current ownership. The snapshot cannot grant offer-signing or payment rights.

## Hosted API

- `GET /api/apostille/v1/erc8004/config`: public `{profile, enabled, networks:[{chain_id,registry_address}], max_binding_age_seconds:3600, wallet_support:"eoa_only"}`; no RPC URLs or credentials.
- `POST /api/apostille/v1/agents/:id/erc8004`: authenticated `{request,owner_signature}`. Returns 201 for a new private record, 200 for an identical nonce retry, 409 for conflicting nonce content. The stored record has `{id,agent_id,document,created_at,expires_at}`. Identical retries return the original snapshot, never refreshed observations. Create a new signed request to recheck ownership.
- `GET /api/apostille/v1/agents/:id/erc8004`: authenticated latest private record, or 404. Historical signatures remain immutable after transfer or agent revocation; retrieval never asserts current validity.

Feature flag `APOSTILLE_ERC8004_ENABLED` defaults false and requires Apostille in the API role and at least one complete allowlisted RPC/identity-registry configuration. Ethereum/Base use existing RPC and identity registry settings without any transaction key. Admission is capped at 100 snapshots/workspace/UTC day plus per-IP request limiting. A disabled/unconfigured provider returns 503 and does not advertise an active integration. No automatic publication, telemetry from the offline verifier, provider lookup during offline verification, or writes to any chain.

## Validation

Positive Go/JavaScript interoperability and negative vectors cover altered identity tuples, admin or owner proof, nonce, audience, registration, canonical bytes and pins; uint256 boundaries; stale/future observations; ownership transfer; unsupported wallets; tenant isolation; replay/conflict/quota/revocation races; RPC chain mismatch, body limits and redirects. Core 0.1 known-answer vectors must remain unchanged. Storage migrations require clean up/down/up verification.

Reference: [ERC-8004 Identity Registry](https://eips.ethereum.org/EIPS/eip-8004#identity-registry), retrieved 2026-09-14. ERC-8004 remains a draft; this profile pins only the ERC-721 `ownerOf(uint256)` ownership meaning. Registration ownership does not certify a company, advertised capabilities, endpoint control, or payment authority.
