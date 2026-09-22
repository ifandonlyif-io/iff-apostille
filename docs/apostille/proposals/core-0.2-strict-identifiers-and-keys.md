# Proposal — Core 0.2: exact identifier grammar and strict Ed25519

Status: proposal drafted 2026-09-21, reviewed and accepted 2026-09-22 as the
basis for [the implementation plan](core-0.2-implementation-plan.md); the
normative text is [`spec/core-0.2.md`](../spec/core-0.2.md), accepted the same
day, and governs where the two differ. Nothing is implemented yet; the plan's
status table says what has landed. Core 0.1,
its known-answer vector and its case file stay exactly as published; a 0.1
signature is never reinterpreted under these rules.

## Why a new version

Two parts of 0.1 let conforming verifiers disagree, and both fixes narrow what a
verifier accepts. `GOVERNANCE.md` and `core-0.1.md` require a new version
namespace for that, because a verifier must learn which rule set applies from
signed material and not from context.

1. **Identifiers.** 0.1 describes issuer and audience identifiers in prose, and
   each reference implementation leans on its language's URL parser. The
   differential suite (`apostille/differential_test.go`) pins the result: Go
   accepts and JS rejects `URN:example:x` and non-canonical IP-literal hosts such
   as `https://127.1/a`; Go rejects and JS accepts the path characters
   `! * ' ( ) | ^ [ ]`. Both accept forms the prose never mentions, such as an
   uppercase `HTTPS://` scheme, port `0` and dot segments.
2. **Ed25519.** 0.1 says RFC 8032 and nothing about degenerate points, where
   libraries differ. Go `crypto/ed25519` and Node WebCrypto both accept the
   identity as a public key, and then `R = identity, S = 0` verifies **every**
   message. Other libraries refuse small-order points. Refusing only those still
   admits mixed-order keys, so library choice would keep deciding the verdict.

## Version namespace (exact bytes)

- Protocol identifier, in `bundle.protocol`, every `envelope.protocol` and every
  signed `payload.protocol`: `https://ifandonlyif.io/apostille/spec/0.2`.
- Signature input for kind `K` and canonical payload bytes `P`:
  `UTF8("iff-apostille/" + K + "/0.2\n") || SHA256(P)`.
- Unchanged from 0.1: artifact kinds and fields, strict JSON and the restricted
  RFC 8785 canonical form, unpadded base64url, `sha256:` key IDs over the raw
  32-byte key, envelope digests, timestamps, UUIDs, the bundle verification
  algorithm and every result dimension.
- No mixing. Delegation, acceptance, statement, publication grant and certificate
  that refer to one another all carry the same version, in the envelope and in
  the signed payload. A verifier selects the rule set from `bundle.protocol` and
  rejects any envelope or payload that names another version; grant validation
  rejects a grant whose version differs from the statement and delegation it
  names. A 0.2 statement therefore cannot cite a 0.1 delegation.
- The login challenge prefix and the detached ERC-8004 and ZK profiles have their
  own namespaces and are not changed here.

## Rule A — identifier grammar

Applies to `issuer` in every signed header and to `service_audience`. An
identifier is 1 to 256 bytes of ASCII matching this ABNF (RFC 5234; literal
strings are case-sensitive), plus the constraints below. Verifiers test the
characters as written. They MUST NOT normalize, resolve or fetch an identifier,
and MUST NOT let a general-purpose URL parser decide acceptance.

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
ipv6        = <canonical hexadecimal IPv6 text, defined below>
```

Constraints the ABNF does not express:

- `label` is 1 to 63 bytes and `reg-name` at most 253. The final label of a
  `reg-name` does not start with a digit, so a host that ends in a number is an
  address and must match `ipv4` exactly. This rejects `127.1`, `256.1.1.1`,
  `1.2.3.4.5`, `2130706433` and `0x7f.0.0.1` without consulting a parser.
- `ipv6` is the RFC 5952 text form (sections 4.1 to 4.3) restricted to
  hexadecimal groups: eight 16-bit groups, lowercase, no leading zeros, a zero
  group written `0`, no dotted-decimal tail (section 5 is excluded) and no zone.
  `::` is used if and only if the address has a run of two or more consecutive
  zero groups. It then appears once and replaces the longest such run, the
  leftmost on a tie. An address with no zero group, or only isolated ones, has
  all eight groups and no `::`: `2001:db8:1:2:3:4:5:6` and `2001:db8:0:1:1:1:1:1`
  are canonical, `2001:db8::1:1:1:1:1` is not. A verifier parses the eight
  groups, re-serializes them by this rule and requires the bytes to equal the
  input.
- `port` is 1 to 65535 and not `443`.
- `nid` is 2 to 32 bytes.
- No segment is `.` or `..`. An empty segment is ordinary: `https://a.example/`,
  `https://a.example/x/` and `https://a.example//x` are all valid and, like every
  identifier, distinct from one another because comparison is over exact bytes.
- As in 0.1: no userinfo, query, fragment, percent escape, backslash, whitespace
  or non-ASCII byte. Percent escapes stay forbidden, so the path alphabet is
  RFC 3986 `pchar` without `pct-encoded`.

`urn:apostille:key:sha256:<64 hex>`, `https://ifandonlyif.io/apostille` and every
identifier in the 0.1 vectors satisfy this grammar.

| 0.1 behaviour | 0.2 verdict |
| --- | --- |
| `URN:example:x` (Go accepts, JS rejects); `HTTPS://…` (both accept) | reject: scheme is lowercase |
| non-canonical IP literals (Go accepts, JS rejects) | reject; `127.0.0.1` and `[::1]` accept |
| path `! * ' ( )` (Go rejects, JS accepts) | accept: RFC 3986 `sub-delims` |
| path `\| ^ [ ]` (Go rejects, JS accepts) | reject: not `pchar` |
| port `0`; `urn:x`; trailing-dot, empty or underscore labels; a final host label that starts with a digit without being a number, such as `9x`; dot segments (both accept) | reject |
| empty path segments: `//`, trailing `/` (both accept) | accept, compared as exact bytes |

## Rule B — strict Ed25519 verification

Given a 32-byte public key `A`, a 64-byte signature `R || S` and the signature
input `M`, with `p = 2^255 - 19` and group order
`L = 7237005577332262213973186563042994240857116359379907606001950938285454250989`:

1. Read `S` as a little-endian integer and reject unless `S < L`.
2. Decode `A` and `R` by RFC 8032 section 5.1.3, and additionally reject a
   non-canonical encoding: clear the top bit to get `y` and require `y < p`;
   reject if `x` cannot be recovered; reject if `x = 0` and the sign bit is set.
   Equivalently, re-encoding the decoded point reproduces the 32 input bytes.
3. Reject unless each of `A` and `R` is a point `P` with `P != identity` and
   `[L]P = identity`. This admits exactly the non-identity points of the
   prime-order subgroup, excluding the eight small-order points and every
   mixed-order point.
4. Compute `k = SHA-512(R || A || M) mod L` over the encoded bytes and accept if
   and only if `[S]B = R + [k]A`. With `A` and `R` torsion-free the cofactored
   equation gives the same verdict, so either may be used.

The same key rule applies wherever 0.2 carries a public key: `signature.public_key`
and a delegation's `agent_public_key`. A key that fails step 2 or 3 is invalid,
and so is a delegation naming one.

These four steps are the definition. An implementation uses a maintained curve
library for decoding and scalar multiplication, but "call the library's strict
mode" is not conformance: strict modes differ between libraries, and one that
refuses only small-order points still accepts a mixed-order key. For reference
(checked by recomputation, not normative), the eight small-order encodings are:

```text
0100000000000000000000000000000000000000000000000000000000000000  order 1
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f  order 2
0000000000000000000000000000000000000000000000000000000000000000  order 4
0000000000000000000000000000000000000000000000000000000000000080  order 4
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05  order 8
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85  order 8
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a  order 8
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa  order 8
```

`9599999999999999999999999999999999999999999999999999999999999999` is the base
point plus the order-2 point. It is not in that list, a small-order blocklist
accepts it, and step 3 rejects it.

Honest keys and signatures always pass: `A = [a]B` and `R = [r]B` lie in the
prime-order subgroup. A signer SHOULD verify its own output under these rules
before releasing it. The cost is two extra scalar multiplications per signature.

## Receiver policy, privacy

Trust is unchanged: only an externally supplied exact issuer and key pin yields
`accepted_by_policy`, and a pin is independent of the protocol version. What is
new is that a receiver chooses which versions it accepts; the result already
reports `protocol`. A 0.2 artifact cannot be replayed as 0.1 because the signature
domain differs, but a degenerate key can still produce 0.1 artifacts, so a
receiver that needs Rule B must refuse 0.1 rather than assume it. No field is
added; identifiers, keys, UUIDs and timestamps remain as linkable as in 0.1.

## Vectors

New files `testdata/apostille/core-0.2.json` (known answer) and
`core-0.2-cases.json` (same format as the 0.1 case file); the 0.1 files are frozen.

- Every 0.1 case category regenerated under the 0.2 namespace.
- Identifiers: each value in the table above with its 0.2 verdict, and both sides
  of every boundary: port `1`, `65535`, `65536`, `0`, `443`; label 63 and 64 bytes;
  host 253 and 254; a final host label starting with a digit; `ipv4` with a
  leading zero; each `pchar` and each excluded printable character; dot segments
  (reject) and empty segments, inner and trailing (accept); `nid` of 1, 2, 32
  and 33.
- `ipv6` accepted: no zero group (`2001:db8:1:2:3:4:5:6`); one isolated zero group
  (`2001:db8:0:1:1:1:1:1`); `::`, `::1` and `1::`; the leftmost of two equal runs
  (`2001:db8::1:0:0:1`). Rejected: a run of two or more zeros left uncompressed;
  `::` standing for a single zero group (`2001:db8::1:1:1:1:1`); the shorter or
  the rightmost run compressed; two `::`; uppercase; a leading zero in a group;
  a dotted tail; a zone.
- Ed25519, each under a real signature wherever one can be constructed so that
  only the named rule fails: the eight small-order points as `A` and as `R`;
  **identity `R` on an honest key with the valid signature `S = k·a mod L`**,
  which a cofactorless verifier accepts today and only the identity clause of
  step 3 rejects; non-canonical `A` and `R` (`y >= p`, and `x = 0` with the sign
  bit); a mixed-order `A` with a signature that an RFC 8032 cofactorless verifier
  accepts today (choose `r` until `k` is a multiple of 8); `S = L` and `S + L`.
- Cross-version: a 0.1 envelope in a 0.2 bundle, a 0.2 payload under the 0.1
  signature domain, and a 0.1 signature relabelled 0.2.

## Migration

1. Publish the specification and vectors. Add 0.2 verification to Go and JS beside
   0.1, selected by `bundle.protocol`. The 0.1 path does not change.
2. SDK and CLI gain an explicit signing version. The default stays 0.1. Signing
   fails early when versions would mix: a 0.2 statement or grant needs a 0.2
   delegation and acceptance, so a signer never emits a bundle that the no-mixing
   rule rejects.
3. The hosted service adds 0.2 registration, grant validation and issuance, and
   certifies a 0.2 statement with a 0.2 certificate. Until it does, a 0.2
   submission is refused there and hosted users keep signing 0.1.
4. An agent moves by registering a new 0.2 delegation and acceptance with the same
   keys, then signing 0.2 explicitly.
5. The SDK and CLI default changes to 0.2 only after step 3 is deployed and the
   registrations that use the hosted service have moved, on a date announced in
   advance. Verifier support alone is not the condition: an existing 0.1
   registration plus a default 0.2 statement would be a mixed, rejected bundle.
   0.1 signing stays available behind the explicit option for a stated
   deprecation window.
6. Receivers choose the versions they accept. Existing issuer and key pins keep
   working unchanged.
7. 0.1 artifacts stay verifiable under 0.1 rules indefinitely. Nothing is re-signed.

An issuer whose identifier falls outside Rule A needs a conforming identifier for
0.2, which is a new identifier, so its receivers establish a new pin. No honest
key is affected by Rule B.

## Decisions recorded from review (2026-09-22)

1. **Namespace.** Core 0.2 with the new signature domain, not a named profile on
   0.1 bytes: only a signed version tells a verifier which rules a signer accepted.
2. **No mixing.** Delegation, acceptance, statement, grant and certificate agree
   on the version.
3. **Tightening beyond the first decision.** Adopted: reject dot segments, non-LDH
   or empty host labels, a final host label starting with a digit, port `0`, and a
   URN without both `nid` and `nss`. Not adopted: empty path segments stay valid
   and identifiers are compared as exact bytes.
4. **IPv6.** Hexadecimal canonical form only, with no dotted tail and no zone, and
   `::` only where a run of two or more zero groups exists.
5. **Dependencies.** Accepted: a Go curve library in the root module and a curve
   library vendored into `web/`, each pinned to an exact version with its notice
   in `docs/apostille/NOTICES.md`. Once vendored, the SDK still has no external
   npm runtime dependency, but it does contain third-party code; documentation
   says so rather than "zero dependencies".
6. **Hosted access policy.** Recommended as separate work now: the hosted service
   applies Rule B's key check to login and registration keys under its own access
   policy. Inventory the keys already registered before deploying it, so that an
   affected workspace is found rather than locked out. Offline verification of
   historical 0.1 artifacts keeps the 0.1 rules.

## Implementation notes (not normative)

- Neither `crypto/ed25519` nor WebCrypto exposes point arithmetic, which is why
  Rule B needs a curve library. `script-src 'self'` is kept by vendoring.
- `[L]P` cannot be computed by turning `L` into the library's scalar type. A
  scalar is an integer modulo `L`, so `L` either fails to load or reduces to zero,
  and `[0]P` is the identity for **every** point: the check would pass degenerate
  keys silently. This holds for `filippo.io/edwards25519` `Scalar` and for any
  library that reduces scalars. Compute `[L-1]P + P`, where `L-1` is a canonical
  scalar, or use the library's own torsion-free test. The mixed-order reject
  vector exists to catch exactly this mistake, in every implementation.
  Checked against `filippo.io/edwards25519` v1.1.0: `SetCanonicalBytes(L)` fails,
  `SetUniformBytes` reduces `L` to zero, the zero multiple of the mixed-order
  example above is the identity, and `[L-1]P + P` accepts the base point while
  rejecting that example and all eight small-order points.
- Decode with the library, then enforce step 2 by re-encoding and comparing
  bytes; several decoders accept non-canonical encodings by design.
- The 0.1 path keeps calling the existing verification unchanged.
