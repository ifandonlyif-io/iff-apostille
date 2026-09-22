# Apostille Core 0.2 — draft alpha

Status: normative profile for 0.2 artifacts, accepted 2026-09-22 under
[GOVERNANCE.md](../../../GOVERNANCE.md). No reference implementation or
conformance vectors exist yet; the
[implementation plan](../proposals/core-0.2-implementation-plan.md) tracks them,
and no implementation may claim 0.2 conformance before they do. [Core 0.1](core-0.1.md)
stays normative for 0.1 artifacts. Licensed under the repository MIT LICENSE.
This is not a standards-body specification or a legal Apostille. The English
text is normative. The words MUST, MUST NOT, SHOULD and MAY are used as in
RFC 2119.

## Purpose and relation to 0.1

Core 0.2 has the same purpose, artifacts, fields, digests, encodings and
verification algorithm as Core 0.1. It differs in exactly three places:

1. **Identifiers.** Issuer and audience identifiers are defined by an exact
   grammar (section "Identifier grammar") instead of prose, so that every
   implementation returns the same verdict.
2. **Signatures.** Ed25519 verification is strict (section "Strict Ed25519
   verification"): the scalar is in range, both points are canonically encoded,
   neither is the identity, and both lie in the prime-order subgroup.
3. **Version consistency.** All artifacts that refer to one another carry the
   same version, and a verifier selects the rule set from the signed material.

Every rule of Core 0.1 not restated here applies unchanged, by reference to the
named section of `core-0.1.md`. Where this document and `core-0.1.md` differ,
this document governs for 0.2 artifacts only. A 0.1 signature is never
reinterpreted under 0.2 rules, and a 0.2 signature never under 0.1 rules.

The protocol identifier is `https://ifandonlyif.io/apostille/spec/0.2`. As in
0.1, it names the format, not an issuer, a trust authority or a URL to fetch.
Unknown versions, kinds, algorithms and fields MUST fail closed.

## Version, signature input and consistency

For a kind `K` and canonical payload bytes `P`, the signature input is:

```text
UTF8("iff-apostille/" + K + "/0.2\n") || SHA256(P)
```

`\n` is a single LF byte and `||` is byte concatenation. Everything else about
signing follows `core-0.1.md` "Encoding and signature": sign the input with
Ed25519 (not Ed25519ph), never a hex digest, JSON wrapper or signature field;
`payload_sha256` hashes `P`; `statement_sha256` and `delegation_sha256` hash
the entire canonical envelope. Because the domain string differs, a signature
made for one version does not verify under the other.

The `protocol` member of a bundle, of every envelope and of every signed
payload MUST be the 0.2 identifier. A verifier:

1. selects the rule set from `bundle.protocol`, or from `envelope.protocol` when
   verifying a single envelope, and rejects an unknown value;
2. rejects a bundle in which any present envelope (`statement`, `delegation`,
   `acceptance`, `certificate`) or any signed payload names another version;
3. when validating a publication grant, rejects a grant whose version differs
   from that of the statement and delegation it names;
4. when issuing, gives the certificate the version of the source bundle and
   MUST NOT certify a source of another version.

A receiver MAY restrict the versions it accepts. With no restriction, every
version the implementation knows is accepted. The verification result reports
the bundle's version in `protocol`. The login challenge prefix
`iff-apostille/login/0.1\n` and the detached ERC-8004 and ZK profiles keep
their own namespaces and are not changed by this document.

## Encoding

`core-0.1.md` "Encoding and signature" applies unchanged: UTF-8 JSON of at most
262144 bytes and depth at most 24; the root of a bundle, an envelope and a
signed payload is an object; duplicate properties (including escaped-equivalent
names), malformed UTF-8, unpaired surrogate escapes, trailing JSON and all JSON
numeric values are rejected; a surrogate escape is paired only when a high
surrogate escape is immediately followed by a low surrogate escape, tested as
written; canonical payload bytes are the restricted RFC 8785 form; SHA-256
digests are 64 lowercase hex characters; public-key IDs are `sha256:` over the
raw 32-byte key; binary fields use canonical unpadded base64url; signatures
are 64 bytes; the envelope has exactly `protocol, kind, payload,
payload_sha256, signature`; decoded payloads are at most 131072 bytes. The
structural schema is [`web/apostille-0.2.schema.json`](../../../web/apostille-0.2.schema.json);
schema validation alone is not conformance.

## Strict Ed25519 verification

Let `p = 2^255 − 19`, let `L = 2^252 + 27742317777372353535851937790883648493`
(decimal `7237005577332262213973186563042994240857116359379907606001950938285454250989`),
let `B` be the base point of RFC 8032 section 5.1, and let "identity" be the
neutral element, whose encoding is the byte `0x01` followed by 31 zero bytes.
Point encoding and decoding are RFC 8032 sections 5.1.2 and 5.1.3.

Given a 32-byte public key `A`, a 64-byte signature `R || S` and the signature
input `M`, a verifier MUST perform these steps in order and reject at the first
failure:

1. Interpret `S` as a little-endian integer. Reject unless `S < L`.
2. Decode `A` and `R`. Reject if either fails to decode. Reject unless
   re-encoding each decoded point reproduces its 32 input bytes exactly. This
   rejects an encoded `y ≥ p` and an encoding whose sign bit is set while
   `x = 0`.
3. For each decoded point `P` in `{A, R}`: reject if `P` is the identity;
   reject unless `[L]P` is the identity. A point passing both is a non-identity
   element of the prime-order subgroup; the eight small-order points and every
   point of mixed order fail.
4. Let `k = SHA-512(R || A || M)` over the input bytes of `R` and `A`,
   interpreted little-endian and reduced modulo `L`. Accept if and only if
   `[S]B = R + [k]A`.

Because step 3 makes `A` and `R` torsion-free, `[k]A` equals `[k mod L]A` and
the cofactored equation `[8][S]B = [8]R + [8][k]A` gives the same verdict as
step 4; an implementation MAY use either form.

Steps 2 and 3 apply to every public key a 0.2 artifact carries, not only when
a signature is checked: `signature.public_key` in each envelope and
`agent_public_key` in a delegation. An artifact carrying a key that fails them
is invalid. A signer SHOULD verify its own output under these steps before
releasing it. A key generated and used as RFC 8032 describes always passes.

This section defines conformance. Using a cryptographic library for point
decoding, multiplication and the equation is expected; relying on a library's
"strict" mode is not sufficient, because such modes differ and one that
rejects only small-order points still accepts a mixed-order key. Informative:
the eight small-order encodings, checked by recomputation, are

```text
0100000000000000000000000000000000000000000000000000000000000000
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000080
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
```

and `9599999999999999999999999999999999999999999999999999999999999999` (the base
point plus the order-2 point) is a mixed-order point that a small-order
blocklist accepts and step 3 rejects. Note that on an honest key the
signature `R = identity`, `S = k·a mod L` satisfies step 4; only step 3 rejects
it. Both are conformance vectors.

## Common values

`core-0.1.md` "Common values" applies unchanged for `protocol`, `kind`,
`issuer_key_id`, `issued_at`, timestamps, UUIDs and the key actor identity
`urn:apostille:key:<key_id>`. Identifiers are replaced by the following.

### Identifier grammar

Applies to `issuer` in every signed payload header and to `service_audience`.
An identifier is 1 to 256 bytes of ASCII that matches `identifier` below and
satisfies the constraints that follow. The ABNF is RFC 5234 with the RFC 7405
`%s` case-sensitive string extension.

```abnf
identifier  = https-id / urn-id

https-id    = %s"https://" host [ ":" port ] *( "/" segment )
host        = ipv4 / "[" ipv6 "]" / reg-name
reg-name    = label *( "." label )
label       = lower-alnum [ *( lower-alnum / "-" ) lower-alnum ]
port        = %x31-39 *4DIGIT
segment     = *pchar

urn-id      = %s"urn:" nid ":" nss
nid         = lower-alnum *( lower-alnum / "-" ) lower-alnum
nss         = pchar *( pchar / "/" )

pchar       = unreserved / sub-delims / ":" / "@"
unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
lower-alnum = %x61-7A / DIGIT

ipv4        = dec-octet "." dec-octet "." dec-octet "." dec-octet
dec-octet   = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
ipv6        = <canonical text of an IPv6 address; see below>
```

Constraints:

- A `label` is 1 to 63 bytes and a `reg-name` at most 253 bytes. The final
  label of a `reg-name` MUST NOT start with a digit. A host that ends in a
  number is therefore an address and MUST match `ipv4` exactly; `127.1`,
  `256.1.1.1`, `1.2.3.4.5`, `2130706433` and `0x7f.0.0.1` are rejected by the
  grammar alone.
- `ipv6` is the RFC 5952 sections 4.1 to 4.3 text form restricted to
  hexadecimal groups: eight 16-bit groups written in lowercase hexadecimal
  without leading zeros, a zero group written `0`, no dotted-decimal tail and no
  zone. `::` is present if and only if the address contains a run of two or more
  consecutive zero groups; it then appears once and replaces the longest such
  run, the leftmost when two runs have the same length. A verifier parses the
  groups, re-serializes them by this rule and requires the result to equal the
  input bytes. `2001:db8:1:2:3:4:5:6`, `2001:db8:0:1:1:1:1:1`, `::`, `::1`,
  `1::` and `2001:db8::1:0:0:1` are canonical; `2001:db8::1:1:1:1:1`,
  `2001:db8:0:0:1:1:1:1`, `2001:db8:1::0:0:1`, `2001:DB8::1`, `2001:0db8::1`,
  `::ffff:1.2.3.4` and `fe80::1%eth0` are not.
- `port` is 1 to 65535 and MUST NOT be `443`.
- A `nid` is 2 to 32 bytes and lowercase. RFC 8141 treats a NID as
  case-insensitive; this profile accepts only the lowercase spelling and does
  not convert, so `urn:EXAMPLE:x` is rejected.
- No `segment` is `.` or `..`. An empty segment is valid: `https://a.example/`,
  `https://a.example/x/` and `https://a.example//x` are three distinct valid
  identifiers.
- As in 0.1: no userinfo, query, fragment, percent escape, backslash, whitespace
  or non-ASCII byte. Percent escapes remain forbidden, so the path alphabet is
  RFC 3986 `pchar` without `pct-encoded`.

Acceptance is defined by this grammar alone, over the bytes as written. An
implementation MUST return the grammar's verdict and MUST NOT normalize,
resolve, fetch or rewrite an identifier; the behaviour of a general-purpose URL
parser is not a reference for acceptance. Identifiers are compared as exact
bytes, so `https://a.example/x` and `https://a.example/x/` are different
issuers. `https://ifandonlyif.io/apostille`, `urn:apostille:key:sha256:<64 hex>`
and every identifier in the 0.1 vectors satisfy this grammar.

Illustrative verdicts, all of which are conformance cases: accepted —
`https://issuer.example/apostille`, `https://issuer.example:8443/a`,
`https://127.0.0.1/a`, `https://[::1]/a`, `https://issuer.example/a!b`,
`https://issuer.example/a(b)`, `urn:example:private-issuer`, `urn:example:a/b`;
rejected — `HTTPS://issuer.example/a`, `URN:example:x`, `urn:EXAMPLE:x`,
`https://Issuer.example/a`, `https://issuer.example:443/a`,
`https://issuer.example:0/a`, `https://issuer.example:08443/a`,
`https://issuer.example./a`, `https://issuer_example/a`,
`https://-issuer.example/a`, `https://issuer.9x/a`, `https://issuer.example/a|b`,
`https://issuer.example/a[b]`, `https://issuer.example/a/../b`,
`https://issuer.example/./a`, `https://issuer.example/a%20b`,
`https://user@issuer.example/a`, `urn:x`, `urn:example:x y`.

## Artifact registry and fields

`core-0.1.md` "Artifact registry and fields" applies unchanged: the kinds
`origin-statement`, `agent-delegation`, `agent-acceptance`, `publication-grant`
and `origin-certificate`, their fields, the statement, delegation, grant and
certificate rules, and the hosted issuance limits. Every `issuer` and
`service_audience` value is validated by the identifier grammar above, and
every `agent_public_key` by steps 2 and 3 of strict verification.

## Bundle and verification algorithm

`core-0.1.md` "Bundle and verification algorithm" applies with these changes:

- Before step 1, apply the version consistency rules of this document. A
  bundle that fails them is invalid, and no signature is checked.
- Every signature check in steps 1, 2 and 4 is strict Ed25519 verification.
- Every identifier check is the identifier grammar.
- In step 4, the certificate's `issuer` and the delegation's
  `service_audience` are compared as exact bytes.
- The reference issuer additionally MUST NOT issue a certificate over a source
  bundle of another version, and MUST apply steps 2 and 3 of strict
  verification to every key in a 0.2 registration. A hosted service SHOULD
  apply the same key check to login keys under its own access policy.

Steps 5 to 7 (trust policy, freshness, original bytes) are unchanged.

## Result semantics and offline boundary

`core-0.1.md` "Result semantics and offline boundary" applies unchanged. The
result's `protocol` is the bundle's version. `artifact_integrity`,
`issuer_trust`, `certificate_scope`, `agent_binding`, `organization_binding`,
`authorization_policy`, `freshness`, `time_basis`, `content_truth`,
`provider_evidence`, `log_inclusion` and `anchor` keep their 0.1 values and
meanings. Strict verification establishes that a signature was made with a
well-formed key; it does not establish content truth, organization identity,
current non-revocation or anything else 0.1 leaves unproven.

## Privacy and versioning

`core-0.1.md` "Privacy and versioning" applies unchanged. In addition:

- A 0.1 artifact remains verifiable under 0.1 rules indefinitely and is never
  re-signed. A receiver that requires strict verification MUST refuse 0.1
  artifacts rather than assume it, because a degenerate key can still produce
  valid 0.1 signatures.
- An issuer or audience whose 0.1 identifier is outside the grammar needs a
  conforming identifier for 0.2. That is a new identifier, and receivers
  establish a new pin for it; existing pins are unaffected.
- No field is added. Identifiers, keys, UUIDs and timestamps remain as linkable
  as in 0.1.
- A later incompatible change again requires a new version namespace.

## Conformance vectors

The reference implementation publishes `testdata/apostille/core-0.2.json`
(known-answer bundle from public test seeds) and
`testdata/apostille/core-0.2-cases.json` (accept and reject cases in the same
format as the 0.1 case file). An implementation claims 0.2 conformance by
verifying the known-answer bundle and returning the expected result for every
case. The case file MUST include, with a real signature wherever one can be
constructed so that only the named rule fails: every 0.1 case category under
the 0.2 namespace; both sides of every identifier boundary and every IPv6
example above; the eight small-order points as `A` and as `R`; identity `R`
with the valid signature `S = k·a mod L` on an honest key; non-canonical `A`
and `R`; a mixed-order `A` with a signature a cofactorless verifier accepts;
`S = L` and `S = S₀ + L`; and cross-version material (a 0.1 envelope in a 0.2
bundle, a 0.2 payload signed under the 0.1 domain, a 0.1 signature relabelled
0.2). The 0.1 vector files are unchanged.

## References

- RFC 8785: https://www.rfc-editor.org/rfc/rfc8785.html
- RFC 8032: https://www.rfc-editor.org/rfc/rfc8032.html
- RFC 3986: https://www.rfc-editor.org/rfc/rfc3986.html
- RFC 5234 and RFC 7405: https://www.rfc-editor.org/rfc/rfc5234.html, https://www.rfc-editor.org/rfc/rfc7405.html
- RFC 5952: https://www.rfc-editor.org/rfc/rfc5952.html
- RFC 8141: https://www.rfc-editor.org/rfc/rfc8141.html
- Core 0.1: `docs/apostille/spec/core-0.1.md`
- Proposal and decisions: `docs/apostille/proposals/core-0.2-strict-identifiers-and-keys.md`
- Implementation plan: `docs/apostille/proposals/core-0.2-implementation-plan.md`
