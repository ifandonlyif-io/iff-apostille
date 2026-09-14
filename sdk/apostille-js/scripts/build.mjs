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
await copyFile(join(repositoryRoot, "LICENSE"), join(packageRoot, "LICENSE"));
await copyFile(join(repositoryRoot, "docs/apostille/spec/core-0.1.md"), join(specRoot, "core-0.1.md"));
await copyFile(join(repositoryRoot, "docs/apostille/spec/erc8004-binding-0.1.md"), join(specRoot, "erc8004-binding-0.1.md"));
await copyFile(join(repositoryRoot, "web/apostille-0.1.schema.json"), join(specRoot, "schema.json"));
await copyFile(join(repositoryRoot, "testdata/apostille/core-0.1.json"), join(specRoot, "vectors.json"));
