# Third-party notices

Original Apostille source, documentation, schemas and synthetic vectors retain
the root MIT License and its original copyright. Nested modules include the same
LICENSE for separate source distribution. Do not change ownership/year merely
as part of repository extraction.

The strict browser JSON parser was adapted within IFF from its MIT-licensed
receipt implementation; see the [public parser source](https://github.com/ifandonlyif-io/iff-x402-transparency/blob/1811f831af78d3bc20ac95415045c04a1b61c89f/browser/service-receipt.mjs).
It has no runtime dependency on receipt formats or an IFF issuer.
The browser core uses platform WebCrypto; the JS package has no
runtime npm dependencies. TypeScript is Apache-2.0 development tooling and is
not included in the runtime tarball.

Go Core uses the Apache-2.0 JSON Canonicalization reference implementation
`github.com/cyberphone/json-canonicalization`
`v0.0.0-20241213102144-19d51d7fe467`. Preserve its
[upstream copyright/license notice](notices/json-canonicalization-LICENSE) and
the [complete Apache-2.0 terms](notices/APACHE-2.0.txt) when redistributing it.

The CLI also imports the experimental ZK module: it is **not** limited to
standard library/Core/JCS. Its runtime dependency graph includes gnark
`v0.16.3`, gnark-crypto `v0.21.0` (Apache-2.0), zerolog `v1.35.1` (MIT) and
their transitive dependencies under their own licenses. Exact versions and
checksums live in each module's go.mod/go.sum; the modules remain isolated.

The root's go-ethereum `v1.17.2` imports are used only in ERC-8004 tests; its
LGPL/GPL licensing is not replaced by this repository's MIT License. Testify is
MIT test tooling. No upstream dependency source is vendored in this source
preview. Dependencies are downloaded through the normal package managers.

Before shipping compiled binaries or vendored sources, inventory the actual
runtime graph for the target platform and include every applicable copyright,
NOTICE and complete license text, including the Go runtime and ZK dependencies.
This file is an inventory guide, not a replacement for upstream license terms
or a completed binary-distribution notice bundle.
