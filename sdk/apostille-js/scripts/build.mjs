import { copyFile, mkdir, readdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const sourceRoot = join(packageRoot, "src");
const distRoot = join(packageRoot, "dist");
const specRoot = join(packageRoot, "spec");

await rm(distRoot, { force: true, recursive: true });
await rm(specRoot, { force: true, recursive: true });
await mkdir(distRoot, { recursive: true });
await mkdir(specRoot, { recursive: true });

for (const entry of await readdir(sourceRoot, { withFileTypes: true })) {
  if (entry.isFile() && (entry.name.endsWith(".mjs") || entry.name.endsWith(".d.ts"))) {
    await copyFile(join(sourceRoot, entry.name), join(distRoot, entry.name));
  }
}

await copyFile(join(repositoryRoot, "web/apostille-core.mjs"), join(distRoot, "apostille-core.mjs"));
await copyFile(join(repositoryRoot, "web/apostille-erc8004.mjs"), join(distRoot, "apostille-erc8004.mjs"));
await copyFile(join(repositoryRoot, "web/apostille-json.mjs"), join(distRoot, "apostille-json.mjs"));
await copyFile(join(repositoryRoot, "web/apostille-http.mjs"), join(distRoot, "apostille-http.mjs"));
for (const name of ["apostille-profile.mjs", "apostille-identifier.mjs", "apostille-ed25519.mjs", "apostille-mldsa.mjs"]) {
  await copyFile(join(repositoryRoot, "web", name), join(distRoot, name));
}
// The vendored Noble files (scripts/vendor-noble.mjs, docs/apostille/NOTICES.md): the exact import closure of the
// Ed25519 and ML-DSA entry points. The package has no external npm runtime dependency but contains this code, so
// the licence texts travel with it.
const vendored = [
  "curves/abstract/curve.js",
  "curves/abstract/edwards.js",
  "curves/abstract/fft.js",
  "curves/abstract/frost.js",
  "curves/abstract/hash-to-curve.js",
  "curves/abstract/modular.js",
  "curves/abstract/montgomery.js",
  "curves/abstract/oprf.js",
  "curves/ed25519.js",
  "curves/utils.js",
  "hashes/_md.js",
  "hashes/_u64.js",
  "hashes/sha2.js",
  "hashes/sha3.js",
  "hashes/utils.js",
  "post-quantum/_crystals.js",
  "post-quantum/ml-dsa.js",
  "post-quantum/utils.js",
  "package.json",
];
for (const name of vendored) {
  await mkdir(dirname(join(distRoot, "vendor/noble", name)), { recursive: true });
  await copyFile(join(repositoryRoot, "web/vendor/noble", name), join(distRoot, "vendor/noble", name));
}
for (const name of ["curves", "hashes", "post-quantum"]) {
  await copyFile(join(repositoryRoot, "docs/apostille/notices", `noble-${name}-LICENSE`), join(distRoot, "vendor/noble", `LICENSE-noble-${name}`));
}
await copyFile(join(repositoryRoot, "LICENSE"), join(packageRoot, "LICENSE"));
await copyFile(join(repositoryRoot, "docs/apostille/spec/core-0.1.md"), join(specRoot, "core-0.1.md"));
await copyFile(join(repositoryRoot, "docs/apostille/spec/erc8004-binding-0.1.md"), join(specRoot, "erc8004-binding-0.1.md"));
await copyFile(join(repositoryRoot, "docs/apostille/spec/erc8004-binding-0.3.md"), join(specRoot, "erc8004-binding-0.3.md"));
await copyFile(join(repositoryRoot, "testdata/apostille/erc8004-binding-0.3.json"), join(specRoot, "vectors-erc8004-0.3.json"));
await copyFile(join(repositoryRoot, "web/apostille-0.1.schema.json"), join(specRoot, "schema.json"));
await copyFile(join(repositoryRoot, "web/apostille-0.2.schema.json"), join(specRoot, "schema-0.2.json"));
await copyFile(join(repositoryRoot, "web/apostille-0.3.schema.json"), join(specRoot, "schema-0.3.json"));
await copyFile(join(repositoryRoot, "testdata/apostille/core-0.1.json"), join(specRoot, "vectors.json"));
await copyFile(join(repositoryRoot, "testdata/apostille/core-0.2.json"), join(specRoot, "vectors-0.2.json"));
await copyFile(join(repositoryRoot, "testdata/apostille/core-0.3.json"), join(specRoot, "vectors-0.3.json"));
// Test inputs only: the case files and the hedged known answer are large and are not in the package "files" list.
await copyFile(join(repositoryRoot, "testdata/apostille/core-0.1-cases.json"), join(specRoot, "vector-cases.json"));
await copyFile(join(repositoryRoot, "testdata/apostille/core-0.2-cases.json"), join(specRoot, "vector-cases-0.2.json"));
await copyFile(join(repositoryRoot, "testdata/apostille/core-0.3-cases.json"), join(specRoot, "vector-cases-0.3.json"));
await copyFile(join(repositoryRoot, "testdata/apostille/core-0.3-hedged.json"), join(specRoot, "vectors-0.3-hedged.json"));
