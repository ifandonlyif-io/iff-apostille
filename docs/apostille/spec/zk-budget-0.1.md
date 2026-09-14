# Apostille ZK budget profile 0.1 — experimental

Status: local Go SDK and CLI prototype, 2026-09-14. No hosted proving service,
browser ZK verifier, production setup ceremony or external security audit is
provided. This is an independent profile; Core 0.1 signed bytes are unchanged.

Profile: `https://ifandonlyif.io/apostille/profiles/zk-budget/0.1`

Circuit: `budget-16x48-mimc-bls12381-v2`

Scheme: `groth16-bls12-381-gnark-0.16.3`

## Claim and trust

The prover knows all amounts and a nonzero blinding opening a source-signed
commitment to a fixed vector. Each amount is an unsigned 48-bit integer; the
sum of all entries is at most the receiver-selected unsigned 52-bit limit.
There are 1–16 entries; unused slots are constrained to zero. Amounts and the
sum remain hidden. Currency, scope, period, count, source identity, limit and
receiver request are public. All amounts use one agreed currency's minor unit;
no conversion, credit, negative number or rounding is implemented.

The trusted source signs a *canonical blinded commitment manifest* using an
ordinary Apostille Core 0.1 origin statement. The signature is checked outside
the ZK circuit; the commitment opening and budget predicate are checked inside
it. The full canonical source bundle is bound into the proof. This establishes
the relationship to the signed vector without putting Ed25519 verification
inside the arithmetic circuit.

The source key must be independently pinned by the receiving department. The
receiver must also independently pin the verification key and supply its own
exact request. A proof document's embedded key hash or request cannot establish
these policies. Optional issuer/key pins additionally require a valid, current
Core origin certificate; an IFF certificate authenticates origin, not accounts.

Source completeness is limited to the committed vector. Period/scope are source
claims; the circuit does not inspect event timestamps or source record IDs. It
cannot establish that an ERP export included every real transaction, that a
source record is truthful, or that a department used the correct accounting rule.
That requires a separately governed data ingestion/export process.

## Setup and implementation version

Reference dependencies are gnark 0.16.3 and gnark-crypto 0.21.0, BLS12-381
Groth16. `zk-setup --development` runs a single-party random trusted setup for
this fixed circuit. A malicious setup operator retaining the toxic waste can
forge proofs. An independently trusted operator, reviewed circuit and setup
process are prerequisites to relying on its pin. This alpha has no ceremony,
audited enterprise deployment or universally trusted IFF verification key.

The proving key and verification key use the pinned gnark compressed binary
formats. The verification-key SHA-256 is externally supplied. Before decoding,
the reference implementation checks all vector lengths, fixed compressed-point
boundaries, domain cardinality and trailing fields; the 32 MiB file cap alone
would not bound allocations in the generic decoder. Both keys are local setup
artifacts. Neither is accepted from a proof or fetched during verification.

Changing constraints, the field, MiMC parameters, encodings or cryptographic
library serialization requires a new circuit/scheme profile and new setup pins.
Never reuse an existing key merely because it has the same public input count.

Circuit v2 removes the redundant presentation MiMC and its public output: the
reference circuit has **9,867 constraints and 9 public inputs** (excluding ONE),
versus 12,865 and 10 in the unreleased v1 draft. v1 keys and proof documents are
rejected. Because the snapshot commitment domain includes the circuit ID, local
v1 snapshots must also be regenerated and signed again, followed by new requests,
setup and independently distributed pins. Existing Core 0.1 signatures are never
rewritten or reinterpreted.

`InspectCircuit()` / `apostille zk-circuit` independently compiles and hashes the
local constraint-system serialization without running a setup. Compare its
`circuit_sha256` with the setup's `parameters.json` when auditing/reproducing a
build using the same scheme. This fingerprint is descriptive metadata: it does
not establish that a remote verification key was generated from this circuit,
and it never replaces an independently trusted verification-key pin.

The ZK SDK and CLI use separate Go modules. Production's root module does not
depend on gnark and retains gnark-crypto 0.18.1; 0.21.0 is selected only inside
the experimental modules. Build and test these modules separately, without a
shared Go workspace that would merge their dependency selections.

## Data and canonical encoding

JSON follows Core's bounded strict I-JSON/JCS rules: all quantities are strings,
unknown/missing document fields and ambiguous encodings are rejected. A full
presentation is at most 262144 bytes. Field elements are canonical 32-byte
big-endian values encoded as 64 lowercase hex characters, strictly below the
BLS12-381 scalar modulus. Source timestamps use exact UTC whole seconds.

`Snapshot` has exactly `profile`, `snapshot_id`, `scope`, `currency`,
`period_start`, `period_end`, `entries`, `commitment`. The ID is a UUID v4;
scope is 1–128 printable non-space ASCII bytes; currency is three uppercase
ASCII letters (a unit label, with no currency-directory lookup). The period
is nonempty and closed before the source signature time. The source statement
uses media type `application/vnd.iff.apostille.zk-budget-snapshot+json` and
hashes the exact JCS manifest bytes, without a newline.

`PrivateSnapshot` has `snapshot`, `amounts` and `blinding`. The source creates a
fresh cryptographically random nonzero field blinding. This entire file is
private; keep it and the input export inside the originating department.

`Request` has exactly `profile`, `policy_id`, `audience`, `snapshot_sha256`,
`limit_minor`, `nonce`, `issued_at`, `expires_at`. Policy ID uses the scope label
syntax; audience follows Core's exact issuer URI syntax and is never resolved.
The nonce is a fresh UUID v4; validity is half-open, at most 15 minutes (the CLI
creates 5-minute requests). `snapshot_sha256` is SHA-256 of the exact canonical
public Snapshot, and limit is at most `4503599627370495`.

`Document` has exactly `profile`, `circuit_id`, `scheme`,
`verifying_key_sha256`, `snapshot`, `source_bundle`, `request`, `proof`.
The Core source bundle may be producer-only, delegated, or issuer-certified.
Its original artifact is the public Snapshot; private rows never enter it.

## Circuit and proof bytes

MiMC is the gnark-crypto BLS12-381 scalar-field implementation (111 rounds,
seed `seed`). Its inputs are whole field elements, not JSON byte chunks.

For a domain name `kind`, define `D(kind)` as the unsigned big-endian integer
from the first 16 bytes of SHA-256 of UTF-8:

```text
profile + "\n" + circuit_id + "\n" + kind
```

`context_hi`, `context_lo` are the two unsigned 128-bit halves of SHA-256 of
JCS(Snapshot with `commitment` set to the empty string).
The signed commitment is:

```text
MiMC(D("snapshot"), context_hi, context_lo, count, blinding, amount[0..15])
```

The two request words hash JCS(Request); the two source words hash the full
JCS(Core source bundle). Public inputs in order are commitment, limit,
context_hi, context_lo, count, request_hi, request_lo, source_hi, source_lo.
Every hash half is constrained to 128 bits. In particular, request/source words
remain constrained inputs to the Groth16 public witness; changing them invalidates
the proof even when the receiver also changes its expected request. A second
MiMC of these already public values is unnecessary.

One-hot equality constrains count to 1–16. All sixteen amounts are constrained
to 48 bits, padding is zero, and their sum is compared with the 52-bit limit.
The sum is at most `2^52 - 16`, well below the scalar modulus; modular overflow
cannot turn an over-budget vector into an accepted witness.

The proof is canonical unpadded base64url of exactly 192 bytes:
compressed Groth16 `Ar` (G1, 48 bytes), `Bs` (G2, 96 bytes), `Krs` (G1, 48 bytes).
Variable-length Pedersen commitment extensions are forbidden. All points must
be canonical, non-infinity, on curve and in the correct subgroup. Raw-point and
trailing-byte encodings are rejected before the pairing check.

## Verification and privacy boundary

The verifier checks exact profile and setup pin; independently selected request
and its time window; the public snapshot digest; the Core signature, artifact
digest and size; source time and delegation at signing; the source-key policy;
optional issuer policy; and the ZK proof over all reconstructed public inputs.
Errors never include private witness values. Importing the ZK SDK disables
gnark's process-wide logger once at initialization, so compile/prove/verify do
not write progress lines into application JSON output. This affects every gnark
user in the process. An application may opt in using `gnark/logger.Set` during
startup before any concurrent gnark use; never toggle the global logger around
individual operations. The separate solver logger also stays disabled.

Success records the caller-selected evaluation time as UTC RFC3339
`evaluated_at` (SDK preserves subsecond precision). It reports separate dimensions,
including `proof_integrity=valid`,
`predicate=sum_within_limit`, `source_trust=pinned_source_key`,
`dataset_completeness=committed_vector_only`, `content_truth=not_established`,
`current_authorization=unknown`, `replay_protection=caller_required`, and
`privacy_scope=amounts_hidden_metadata_linkable`.
The CLI additionally emits top-level `valid: true`; cryptographic/policy failure
emits `valid: false`, `error: "verification_failed"` and `evaluated_at`. Invalid
arguments or unreadable parameter files exit with an error before evaluation.

The caller must consume request nonces in its workflow if one-time acceptance
is required. This is an offline audit proof, with no shared spending ledger,
revocation service, payment approval or double-spend prevention. Expired proof
requests cannot be accepted at the present time; historical `--at` evaluation
does not authorize present action.

Random proofs do not hide stable snapshot digests, source keys, timestamps or
the public result. Repeated threshold queries can reveal totals. Authorize
queries and minimize metadata. Do not attach ERC-8004 wallet/token identifiers
when cross-department linkage is unwanted. ZK does not protect data already
sent to an external model or compromised proving host. No automatic upload,
public directory entry, anchor or chain transaction is part of this profile.

References: [gnark proof API](https://docs.gnark.consensys.io/HowTo/prove),
[gnark implementation and security limits](https://github.com/Consensys/gnark),
[NIST privacy-enhancing cryptography](https://csrc.nist.gov/projects/pec).
