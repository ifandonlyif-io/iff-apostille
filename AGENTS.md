# Apostille development rules

Read README.md, SECURITY.md and docs/apostille/spec/core-0.1.md before changing
verification. Keep all existing signed bytes, canonicalization, domain separators,
protocol IDs, digest inputs and key ID derivation unchanged for compatible fixes.
Do not regenerate fixtures to make a failing compatibility test pass.

Offline verification never fetches keys, schemas, status or provider evidence.
Embedded keys prove integrity only; trust requires independent exact issuer/key
pins. Report content/organization truth and current revocation as unproven/unknown.
Keep network operations in explicit clients using the bounded, no-redirect safe
HTTP helper. Never log tokens or query strings.

Keep admin delegation, agent proof of possession, login and publication grants
separate. Do not imply that login or token ownership permits publication/payment.
ERC-8004 and ZK are detached profiles: no changes to Core 0.1 bundle semantics.
ZK is experimental and local, with independently selected setup/source pins and
receiver policy. No hosted proving, automatic publication or chain transaction.

Build/test root, apostille/zkbudget and cmd/apostille separately with GOWORK=off.
Do not add go.work or merge gnark dependencies into the root module. Use
make check and make security. Keep original MIT attribution and dependency notices.
