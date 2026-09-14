# Contributing

Start with a small issue or pull request identifying the component and a
reproducible example. Independent implementations and negative test vectors
are especially useful. Read [SECURITY.md](SECURITY.md) before reporting a bypass.

For a protocol change, describe the exact profile, byte encoding, signature
preimage, receiver trust policy, privacy implications and positive/negative
vectors. An incompatible format needs a new version/domain; never reinterpret
an existing `0.1` signature. Passing a JSON schema is not cryptographic conformance.

Run `make check` and `make security`. Core, CLI and experimental ZK have separate
Go modules; use `GOWORK=off`, never a combined workspace. Keep the shared Go/JS
vectors unchanged for packaging-only changes. Changes to the browser verifier
also need a local browser check with external networking unavailable.

Original contributions are under the repository MIT License. Contribute only
material you have the right to submit, preserve attribution and third-party
notices, and disclose copied/adapted code. No CLA or certification program is
introduced here. See [governance](GOVERNANCE.md) for the alpha decision process.
