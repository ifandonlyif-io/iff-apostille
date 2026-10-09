# ERC-8004 binding profile 0.3

Status: normative for 0.3 binding documents, accepted 2026-10-10 by the owner.
This profile is [ERC-8004 binding profile 0.1](erc8004-binding-0.1.md) for Core
0.3 registrations, with ML-DSA-65 signatures. Every rule of 0.1 not restated
here applies unchanged. A 0.1 document is never reinterpreted under 0.3 rules,
and a 0.3 document never under 0.1 rules.

Profile: `https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.3`.

The version number matches Core 0.3, the Core version of the registration it
binds. There is no binding profile 0.2.

## What changes from 0.1

1. **Registration.** The bound registration is a Core 0.3 registration. The
   document's `delegation` and `acceptance` are Core 0.3 envelopes, verified
   under [Core 0.3](core-0.3.md).
2. **Signatures.** The administrator signature on `erc8004-binding-request` and
   the issuer signature on `erc8004-binding` are ML-DSA-65, made and verified as
   in Core 0.3 "ML-DSA-65 signatures": pure ML-DSA, empty context, hedged signing,
   `signature.algorithm` exactly `ML-DSA-65`, 2603-character public keys and
   4412-character signatures, and `sha256:` key IDs over the raw 1952-byte key.
3. **Signature inputs.** For canonical payload bytes `P`:
   - request: UTF-8 `iff-apostille/erc8004-binding/request/0.3\n` followed by
     the raw SHA-256 of `P`;
   - snapshot: UTF-8 `iff-apostille/erc8004-binding/snapshot/0.3\n` followed by
     the raw SHA-256 of `P`.
4. **Owner consent text.** It is the 0.1 text with its first line replaced by
   `iff-apostille/erc8004-binding/owner/0.3`. All other lines and their order are
   unchanged.
5. **Version consistency.** The envelopes' and payloads' `protocol` is the 0.3
   profile identifier. The request's `agent_key_id` and `delegation_sha256` name a
   Core 0.3 registration. A verifier rejects a document that mixes 0.1 and 0.3
   material anywhere.

## What stays the same, and its limits

- The payload fields, time rules, address and integer grammars, issuer chain
  checks, API shapes and result semantics are those of 0.1.
- The wallet owner's consent is an EIP-191 `personal_sign` signature over
  secp256k1, as required by Ethereum externally owned accounts. **It is not
  post-quantum**, and nothing in this profile can make it so. Only the
  administrator and issuer signatures are post-quantum.
- The issuer's chain observation remains issuer-checked evidence, not a portable
  state proof. Current ownership, organization identity and payment authority are
  not established.

## Hosted API

`GET /erc8004/config` lists both profiles in `profiles` (keeping `profile` as the
0.1 identifier for older clients). `POST /agents/:id/erc8004` accepts a 0.3 request
for an agent of a Core 0.3 workspace and returns a 0.3 document signed by the
hosted ML-DSA-65 issuer key; a 0.1 request is accepted only for a Core 0.1
registration where the service still issues Core 0.1.

## Vectors

The reference implementation publishes `testdata/apostille/erc8004-binding-0.3.json`
(a known-answer document from public test seeds, deterministic signatures) and
covers, as in 0.1, every altered identity tuple, admin or owner proof, nonce,
audience, registration digest, canonical bytes and pin, plus: an Ed25519
signature or key in a 0.3 document, 0.1 material inside a 0.3 document and the
reverse, a Core 0.1 registration under a 0.3 request, and the 0.1 owner-text first
line under a 0.3 request.
