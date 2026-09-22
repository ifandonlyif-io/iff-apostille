# Apostille 0.1 local CLI

The `apostille` command creates and verifies issuer-neutral Apostille 0.1 artifacts using local files. It does not contact IFF, upload the original artifact, or make any network request.

Install the released module, or build it from the repository root:

```bash
go install github.com/ifandonlyif-io/iff-apostille/cmd/apostille@v0.1.0-alpha.1
# or, from a checkout:
make apostille-build   # writes bin/apostille
```

`go install` fetches the tagged CLI, root and ZK modules from the Go module
proxy and compiles them locally; no binary is downloaded. Prebuilt binaries are
not published.

For the experimental local ZK budget profile, see the [ZK walkthrough](ZK.md).
`zk-setup`, `zk-circuit`, `zk-snapshot`, `zk-request`, `zk-prove`, and `zk-verify` create and
check a real proof over a source-signed blinded commitment. Independent source
and setup pins and a receiver-selected request are required. The single-party
setup is development-only; these commands do not approve payments.

The ZK package disables gnark logging for the whole process at startup so local
proof operations do not spill sensitive material to stdout. An application that
needs gnark logs must opt in through its own startup configuration.

`zk-verify` records the evaluation time as `evaluated_at` after reading its local
inputs and parameters. A successful result has `valid: true`; a cryptographic verification failure writes
`valid: false`, `error: "verification_failed"`, and the same evaluation-time
field. `--at` selects an RFC3339 evaluation time; otherwise the local current
time is used. Both are normalized to UTC whole seconds. Invalid arguments or unreadable
local files fail before evaluation and do not produce a verification result.

## Inspect the experimental ZK circuit

Inspect the locally compiled fixed circuit without creating setup material:

```bash
./bin/apostille zk-circuit
```

The result reports `profile`, `circuit_id`, `scheme`, `circuit_sha256`,
`constraints`, and `public_inputs`. Its circuit fingerprint supports a local
rebuild or audit of the circuit metadata. It does not prove that any verifying
key was generated for that circuit. Continue to obtain and pin
`verifying_key_sha256` from an independent trusted source before proving or
verifying.

## Keys

Generate separate administrator, agent, and issuer keys:

```bash
mkdir -m 0700 .apostille-private
./bin/apostille keygen --out .apostille-private/admin-key.json --role administrator
./bin/apostille keygen --out .apostille-private/agent-key.json --role agent
./bin/apostille keygen --out .apostille-private/issuer-key.json --role local-issuer
```

The repository excludes `.apostille-private/` from Git and Docker build contexts. Each private key file contains `protocol`, `key_id`, `public_key`, and `seed`, plus the optional local `role` label. The command creates it with mode `0600`, refuses to overwrite an existing path, and never writes the seed to stdout. On Unix, every command rejects a private key file readable by the group or other users. Keep production keys in a suitable secret store outside the repository.

The role label is informational. Cryptographic roles are established by the signed artifact kind and its key references.

## Register an agent

Create an administrator delegation and agent proof of possession:

```bash
./bin/apostille delegate \
  --admin-key .apostille-private/admin-key.json \
  --agent-key .apostille-private/agent-key.json \
  --audience https://issuer.example/apostille \
  --days30 \
  --out registration.json
```

The agent ID is generated when `--agent-id` is omitted. Pass a canonical UUID v4 with `--agent-id` to retain an existing agent identity. Delegations last 24 hours by default; `--days30` changes this to 30 days. Generated timestamps use UTC with whole-second precision.

The audience is an exact service or issuer URI. A later registered issuance must use the same URI.

## Sign an original artifact

With a registration:

```bash
./bin/apostille sign \
  --key .apostille-private/agent-key.json \
  --file report.json \
  --registration registration.json \
  --out statement.json
```

For a producer-only statement without an administrator delegation:

```bash
./bin/apostille sign \
  --key .apostille-private/agent-key.json \
  --file report.json \
  --agent-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  --out statement.json
```

The command streams the complete original file through SHA-256 and records the actual number of bytes read. It does not copy the original into the statement. The media type is inferred from the filename extension, with `application/octet-stream` as the fallback.

## Authorize hosted publication

Create a five-minute, single-purpose publication grant:

```bash
./bin/apostille grant \
  --admin-key .apostille-private/admin-key.json \
  --statement statement.json \
  --registration registration.json \
  --audience https://issuer.example/apostille \
  --visibility private \
  --out grant.json
```

Use `--visibility public` only when the administrator explicitly approves public publication. The grant contains a fresh nonce suitable for server-side idempotency. Creating this local file does not publish or submit it.

## Issue locally

Issue a certificate with a local issuer key:

```bash
./bin/apostille issue \
  --key .apostille-private/issuer-key.json \
  --issuer https://issuer.example/apostille \
  --statement statement.json \
  --registration registration.json \
  --out bundle.json
```

Omit `--registration` for a producer-only statement. The output identifies the issuer as `self_asserted_local`: possession of an issuer key does not make it an IFF key or establish third-party trust. `issue` is the local issuer flow; a publication grant is intended for a hosted service to validate under its own authorization and idempotency policy.

## Verify offline

Cryptographically verify the bundle and compare the original file:

```bash
./bin/apostille verify \
  --offline \
  --bundle bundle.json \
  --artifact report.json
```

Pin both the expected issuer and issuer key when trust is required:

```bash
./bin/apostille verify \
  --offline \
  --bundle bundle.json \
  --issuer https://issuer.example/apostille \
  --key-id sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --require-trusted \
  --artifact report.json
```

`--offline` is mandatory. Verification reads only the named local bundle and optional artifact. `--at` accepts an RFC3339 evaluation time; its default is the caller's current time, converted to UTC whole seconds.

After successful bundle parsing and verification, the JSON result has explicit
`valid` and `trusted` fields. Exit code `0` means the signatures and binding
checks passed; it does not mean the issuer is trusted unless `trusted` is `true`.
A cryptographic verification failure writes `{valid:false,error:"verification_failed"}`;
earlier command or file-input errors are reported on stderr. Use
`--require-trusted` when policy acceptance is mandatory.

Exit codes are:

- `0`: cryptographic and binding checks passed; inspect `trusted`.
- `2`: invalid command, input, signature, or bundle.
- `3`: `--require-trusted` was set and its issuer/key or validity policy did not match.
- `4`: the supplied original artifact did not match the signed digest and size.

## Verify a detached ERC-8004 binding

The detached `erc8004-binding` profile 0.1 is verified from a local document;
this command never contacts an RPC, key directory, or hosted service. It does not
alter Core 0.1 bundle verification.

```bash
./bin/apostille verify-erc8004 \
  --binding erc8004-binding.json \
  --issuer https://issuer.example/apostille \
  --key-id sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --require-trusted
```

`--at` supplies an RFC3339 historical evaluation time. The JSON output reports
the issuer's `issuer_checked` snapshot, `freshness`, and `current_ownership` as
`unknown`; it does not claim present ownership, organization identity, or payment
authority. `--require-trusted` requires the exact issuer/key pin and
`freshness: "within_validity"`; an expired document can still be inspected
without that flag, but is not trusted.

JSON protocol inputs are bounded by the core 256 KiB limit. Private key files are separately capped at 4 KiB. Every `--out` path uses exclusive creation and will not replace an existing file.
