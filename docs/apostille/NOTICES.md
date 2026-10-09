# Third-party notices

Original Apostille source, documentation, schemas and synthetic vectors retain
the root MIT License and its original copyright. Nested modules include the same
LICENSE for separate source distribution. Do not change ownership/year merely
as part of repository extraction.

The strict browser JSON parser was adapted within IFF from its MIT-licensed
receipt implementation; see the [public parser source](https://github.com/ifandonlyif-io/iff-x402-transparency/blob/1811f831af78d3bc20ac95415045c04a1b61c89f/browser/service-receipt.mjs).
It has no runtime dependency on receipt formats or an IFF issuer.
The browser core uses platform WebCrypto for Core 0.1. The JS package has no
external npm runtime dependency, but it contains third-party code: the vendored
Noble files listed below, which implement Core 0.2 strict Ed25519 point checks
and Core 0.3 ML-DSA-65. TypeScript is Apache-2.0 development tooling and is not
included in the runtime tarball.

Go Core uses the Apache-2.0 JSON Canonicalization reference implementation
`github.com/cyberphone/json-canonicalization`
`v0.0.0-20241213102144-19d51d7fe467`. Preserve its
[upstream copyright/license notice](notices/json-canonicalization-LICENSE) and
the [complete Apache-2.0 terms](notices/APACHE-2.0.txt) when redistributing it.

Go Core also uses `filippo.io/edwards25519` `v1.2.0` (BSD-3-Clause, module hash
`h1:crnVqOiS4jqYleHd9vaKZ+HKtHfllngJIiOpNpoJsjo=`, go.mod hash
`h1:xzAOLCNug/yB62zG1bQ8uziwrIqIuxhctzJT18Q77mc=`) for Core 0.2 strict Ed25519
point decoding and arithmetic. Preserve its [copyright and license
notice](notices/edwards25519-LICENSE) when redistributing it. The CLI and the
ZK module import the root module and so carry the same dependency.

Core 0.3 uses the Go standard library `crypto/mldsa` (Go 1.27, BSD-3-Clause, part
of the Go distribution) and has no third-party Go ML-DSA library. The test data
file `testdata/apostille/core-0.3-wycheproof.json` is a subset of the C2SP
Wycheproof ML-DSA-65 verify vectors (Apache-2.0, `github.com/c2sp/wycheproof`
commit `ee7b4f7e611928cbe163dc6f5e54527bfd166f34`, file
`testvectors_v1/mldsa_65_verify_test.json`; see the
[complete Apache-2.0 terms](notices/APACHE-2.0.txt)). It is test data, not part
of any runtime or package.

The browser modules vendor three MIT-licensed packages by Paul Miller
(`noble-curves`, `noble-hashes`, `noble-post-quantum`), published on 2026-08-27:
`@noble/curves` `2.4.0` (the `ed25519.js` entry point, for Core 0.2 point
decoding and arithmetic), `@noble/post-quantum` `0.7.1` (the `ml-dsa.js` entry
point, ML-DSA-65 only, for Core 0.3) and `@noble/hashes` `2.4.0` (only the files
those two import). Preserve their copyright and license notices when
redistributing them: [noble-curves](notices/noble-curves-LICENSE),
[noble-hashes](notices/noble-hashes-LICENSE) and
[noble-post-quantum](notices/noble-post-quantum-LICENSE). The files exist so a
page under `script-src 'self'` can import them without an import map. They are
the exact files of the npm tarballs, whose sha512 `dist.integrity` values are
pinned in `scripts/vendor-noble.mjs`, except that a bare `@noble/<package>/<file>`
import specifier is rewritten to the relative path of the vendored copy. The
script `scripts/vendor-noble.mjs` reproduces them byte for byte from
`npm pack @noble/curves@2.4.0 @noble/hashes@2.4.0 @noble/post-quantum@0.7.1`, and
its `--table` output is the following inventory (`web/vendor/noble/package.json`
only marks the files as ES modules for Node and is not upstream). The Noble
packages have not been independently audited for this use; the Core 0.3 browser
signing disclosure is Phase 4 work.

| Upstream file | Vendored file | Upstream SHA-256 | Vendored SHA-256 |
| --- | --- | --- | --- |
| `@noble/curves@2.4.0/abstract/curve.js` | `web/vendor/noble/curves/abstract/curve.js` | `dbaeee3b41ff47efb76b78e14170fe4dda7c7ecdc387c402f16c5118e0bac356` | `dbaeee3b41ff47efb76b78e14170fe4dda7c7ecdc387c402f16c5118e0bac356` |
| `@noble/curves@2.4.0/abstract/edwards.js` | `web/vendor/noble/curves/abstract/edwards.js` | `f24a9c221a549a8fff259eb8f245ab0dc17679b13c532c3970d91acc4df9fffd` | `f24a9c221a549a8fff259eb8f245ab0dc17679b13c532c3970d91acc4df9fffd` |
| `@noble/curves@2.4.0/abstract/fft.js` | `web/vendor/noble/curves/abstract/fft.js` | `a4b2ff7ca33f4acc85d61f0e83ec3303c3f6b38ecc19b20d0f6462d820e518cf` | `a4b2ff7ca33f4acc85d61f0e83ec3303c3f6b38ecc19b20d0f6462d820e518cf` |
| `@noble/curves@2.4.0/abstract/frost.js` | `web/vendor/noble/curves/abstract/frost.js` | `9a95f1fdf7e17b9d93a16049db675ee2967ed2a04cf59b1bd981d4662acbedf5` | `b13be328575b5e751ad803753c13bda47fef3991368105ebc8abf7fa27187179` |
| `@noble/curves@2.4.0/abstract/hash-to-curve.js` | `web/vendor/noble/curves/abstract/hash-to-curve.js` | `e3c97e7d0827b728b14e3311ed11d8e386d8a70d8fc77e0b9fd2a3090f19d955` | `e3c97e7d0827b728b14e3311ed11d8e386d8a70d8fc77e0b9fd2a3090f19d955` |
| `@noble/curves@2.4.0/abstract/modular.js` | `web/vendor/noble/curves/abstract/modular.js` | `9ced3aa10598277a735e54f7b61d88e929d565da884ba5385f9006ebb3b6aab2` | `9ced3aa10598277a735e54f7b61d88e929d565da884ba5385f9006ebb3b6aab2` |
| `@noble/curves@2.4.0/abstract/montgomery.js` | `web/vendor/noble/curves/abstract/montgomery.js` | `cdafa8816dad5a24475ec51952c5f71fdd5d1b46880ab982694c4f8ff605fc46` | `cdafa8816dad5a24475ec51952c5f71fdd5d1b46880ab982694c4f8ff605fc46` |
| `@noble/curves@2.4.0/abstract/oprf.js` | `web/vendor/noble/curves/abstract/oprf.js` | `2ca36b3e4930092db1f91559410e86975816c036e248067bc65a8055aa1c504c` | `2ca36b3e4930092db1f91559410e86975816c036e248067bc65a8055aa1c504c` |
| `@noble/curves@2.4.0/ed25519.js` | `web/vendor/noble/curves/ed25519.js` | `e13f6c50c36feb0d18bf7986d5f881bcefb5f1f5b16de3cc5ee7693254c7a0b5` | `c2da2a55504457ae152e2e3167131919230c0e705f33f1762e3d11cfa7295bbf` |
| `@noble/curves@2.4.0/utils.js` | `web/vendor/noble/curves/utils.js` | `be9ff86aef76419376e4d66cf01a134f3117f1f8dd62d81f1b79100145503367` | `721216668546d48385b5bca2f28b235ac21186cf12084f63e62e8411aa13ab7e` |
| `@noble/hashes@2.4.0/_md.js` | `web/vendor/noble/hashes/_md.js` | `60cf3010fda89e3e4d3f0e7ff1ce249e9c467f34b4fd41b6fd6101d9f69be763` | `60cf3010fda89e3e4d3f0e7ff1ce249e9c467f34b4fd41b6fd6101d9f69be763` |
| `@noble/hashes@2.4.0/_u64.js` | `web/vendor/noble/hashes/_u64.js` | `b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102` | `b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102` |
| `@noble/hashes@2.4.0/sha2.js` | `web/vendor/noble/hashes/sha2.js` | `471746bba6ec4c6238ca41358d1d3b40b6ff31cf3363f0b4d550c649c1a8e83b` | `471746bba6ec4c6238ca41358d1d3b40b6ff31cf3363f0b4d550c649c1a8e83b` |
| `@noble/hashes@2.4.0/sha3.js` | `web/vendor/noble/hashes/sha3.js` | `9a81e1edb24eae27b335533220167609cfb58008c5690e140ce478acdc669f32` | `9a81e1edb24eae27b335533220167609cfb58008c5690e140ce478acdc669f32` |
| `@noble/hashes@2.4.0/utils.js` | `web/vendor/noble/hashes/utils.js` | `037ad49adb78168b6b699598fd33f85f7877456b1d28b4d032e2a1a16807947c` | `037ad49adb78168b6b699598fd33f85f7877456b1d28b4d032e2a1a16807947c` |
| `@noble/post-quantum@0.7.1/_crystals.js` | `web/vendor/noble/post-quantum/_crystals.js` | `f8a50221e4d2e7e849e8e4f7443ecff2f722581aef592c907ed57a5480c72885` | `0ebd9e698272ad6ff2f05479570f3440c36d96e6ac633c107627fa2ee71ec86a` |
| `@noble/post-quantum@0.7.1/ml-dsa.js` | `web/vendor/noble/post-quantum/ml-dsa.js` | `7c64e733930b115b72bd0585731d8202f1caa819e081cc1e682a19d1fcbcfbda` | `2765f2c3a29739883dcf1f010d95d3da58cc5ecab659866f7fb91ee48444fc0b` |
| `@noble/post-quantum@0.7.1/utils.js` | `web/vendor/noble/post-quantum/utils.js` | `01e9046ea3e45fe7569d3ae2881515d0a9446882d602255ab7627915aa0fd2af` | `081d259b2f9d77537d098e11d13ccad035723f0129651b130e8ecc3031ad9caf` |

The CLI also imports the experimental ZK module: it is **not** limited to
standard library/Core/JCS. Its runtime dependency graph includes gnark
`v0.16.3`, gnark-crypto `v0.21.0` (Apache-2.0), zerolog `v1.35.1` (MIT) and
their transitive dependencies under their own licenses. Exact versions and
checksums live in each module's go.mod/go.sum; the modules remain isolated.

The root's go-ethereum `v1.17.2` imports are used only in ERC-8004 tests; its
LGPL/GPL licensing is not replaced by this repository's MIT License. Testify is
MIT test tooling. Apart from the Noble files above, no upstream dependency
source is vendored in this source preview. Go dependencies are downloaded through
the normal package managers.

Before shipping compiled binaries or vendored sources, inventory the actual
runtime graph for the target platform and include every applicable copyright,
NOTICE and complete license text, including the Go runtime and ZK dependencies.
This file is an inventory guide, not a replacement for upstream license terms
or a completed binary-distribution notice bundle.
