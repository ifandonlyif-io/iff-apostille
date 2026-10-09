#!/usr/bin/env node
// Vendors the exact @noble files the browser modules import, so a page under
// `script-src 'self'` (no import map, no bundler) can load them.
//
//   mkdir "$(mktemp -d)" && cd that-dir && npm pack @noble/curves@2.4.0 @noble/hashes@2.4.0 @noble/post-quantum@0.7.1
//   node scripts/vendor-noble.mjs <that-dir>           write web/vendor/noble and the license texts
//   node scripts/vendor-noble.mjs <that-dir> --check   compare the tree on disk, write nothing
//   node scripts/vendor-noble.mjs <that-dir> --table   print the NOTICES.md file table
//
// The tarballs are untrusted data: each is checked against the registry
// `dist.integrity` pinned below before a byte of it is used, and the tar
// stream is read in memory by this script. Nothing in it is executed, and no
// path from inside it decides where anything is written. The only change made
// to an upstream file is rewriting a bare `@noble/<pkg>/<file>` import
// specifier to the relative path of the vendored copy, so re-running this
// script reproduces identical bytes.
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VENDOR = "web/vendor/noble";
const NOTICES = "docs/apostille/notices";

// name, version and sha512 SRI come from the npm registry (`npm view <pkg>@<version> dist.integrity`).
const PACKAGES = {
    "@noble/curves": { dir: "curves", version: "2.4.0", integrity: "sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==", entry: ["ed25519.js"], license: "noble-curves-LICENSE" },
    "@noble/hashes": { dir: "hashes", version: "2.4.0", integrity: "sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==", entry: [], license: "noble-hashes-LICENSE" },
    "@noble/post-quantum": { dir: "post-quantum", version: "0.7.1", integrity: "sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q==", entry: ["ml-dsa.js"], license: "noble-post-quantum-LICENSE" },
};
// The closure of the entry points, pinned: the script recomputes the closure
// from the upstream files and refuses to run if it differs from this list.
const FILES = [
    "@noble/curves/abstract/curve.js", "@noble/curves/abstract/edwards.js", "@noble/curves/abstract/fft.js",
    "@noble/curves/abstract/frost.js", "@noble/curves/abstract/hash-to-curve.js", "@noble/curves/abstract/modular.js",
    "@noble/curves/abstract/montgomery.js", "@noble/curves/abstract/oprf.js", "@noble/curves/ed25519.js", "@noble/curves/utils.js",
    "@noble/hashes/_md.js", "@noble/hashes/_u64.js", "@noble/hashes/sha2.js", "@noble/hashes/sha3.js", "@noble/hashes/utils.js",
    "@noble/post-quantum/_crystals.js", "@noble/post-quantum/ml-dsa.js", "@noble/post-quantum/utils.js",
];

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const octal = (field) => parseInt(Buffer.from(field).toString("latin1").replace(/\0.*$/s, "").trim() || "0", 8);
const text = (field) => Buffer.from(field).toString("utf8").replace(/\0.*$/s, "");

// Minimal ustar reader: returns Map(path -> bytes) for regular files only.
function untar(tar) {
    const files = new Map();
    let longName = null, paxPath = null;
    for (let at = 0; at + 512 <= tar.length;) {
        const block = tar.subarray(at, at + 512);
        if (block.every((byte) => byte === 0)) break;
        const size = octal(block.subarray(124, 136)), type = String.fromCharCode(block[156] || 48);
        const body = tar.subarray(at + 512, at + 512 + size);
        at += 512 + Math.ceil(size / 512) * 512;
        if (type === "L") { longName = text(body); continue; }
        if (type === "x") {
            for (const line of Buffer.from(body).toString("utf8").split("\n")) { const m = /^\d+ path=(.*)$/.exec(line); if (m) paxPath = m[1]; }
            continue;
        }
        const prefix = text(block.subarray(345, 500)), name = longName ?? paxPath ?? (prefix ? `${prefix}/${text(block.subarray(0, 100))}` : text(block.subarray(0, 100)));
        longName = paxPath = null;
        if (type === "0" || type === "\0") files.set(name, Buffer.from(body));
    }
    return files;
}

const specifier = /^((?:import|export)\b[^;]*?\bfrom\s*|import\s*)(["'])([^"']+)\2/gm;
function importsOf(source) { return [...source.matchAll(specifier)].map((m) => m[3]); }

// Upstream path of an import found in `from` ("@noble/<pkg>/<file>"), or null for a relative one outside any package.
function target(from, spec) {
    if (spec.startsWith(".")) { const [, pkg, file] = /^(@noble\/[^/]+)\/(.+)$/.exec(from); return `${pkg}/${posix.normalize(posix.join(posix.dirname(file), spec))}`; }
    const m = /^(@noble\/(?:curves|hashes|post-quantum))\/(.+)$/.exec(spec);
    if (!m) throw new Error(`unexpected import specifier ${spec} in ${from}`);
    return spec;
}

function vendoredPath(upstream) { const [, pkg, file] = /^(@noble\/[^/]+)\/(.+)$/.exec(upstream); return `${PACKAGES[pkg].dir}/${file}`; }

function rewrite(upstream, source) {
    const base = posix.dirname(vendoredPath(upstream));
    const out = source.replace(specifier, (whole, head, quote, spec) => {
        if (spec.startsWith(".")) return whole;
        const want = vendoredPath(target(upstream, spec));
        let rel = posix.relative(base, want);
        if (!rel.startsWith(".")) rel = `./${rel}`;
        return `${head}${quote}${rel}${quote}`;
    });
    for (const spec of importsOf(out)) if (!spec.startsWith(".")) throw new Error(`bare specifier left in ${upstream}: ${spec}`);
    return out;
}

async function load(dir) {
    const archives = {};
    for (const [name, info] of Object.entries(PACKAGES)) {
        const file = join(dir, `${name.slice(1).replace("/", "-")}-${info.version}.tgz`);
        const bytes = await readFile(file);
        const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
        if (integrity !== info.integrity) throw new Error(`${file}: integrity ${integrity} does not match the pinned ${info.integrity}`);
        archives[name] = untar(gunzipSync(bytes));
    }
    return archives;
}

function fetchFile(archives, upstream) {
    const [, pkg, file] = /^(@noble\/[^/]+)\/(.+)$/.exec(upstream);
    const bytes = archives[pkg].get(`package/${file}`);
    if (!bytes) throw new Error(`${upstream} is not in the ${pkg} tarball`);
    return bytes;
}

function closure(archives) {
    const seen = new Set(), queue = Object.entries(PACKAGES).flatMap(([name, info]) => info.entry.map((file) => `${name}/${file}`));
    while (queue.length) {
        const upstream = queue.pop();
        if (seen.has(upstream)) continue;
        seen.add(upstream);
        for (const spec of importsOf(fetchFile(archives, upstream).toString("utf8"))) queue.push(target(upstream, spec));
    }
    return [...seen].sort();
}

const [dir, mode = "write"] = process.argv.slice(2);
if (!dir || !["write", "--check", "--table"].includes(mode)) { console.error("usage: vendor-noble.mjs <tarball-dir> [--check|--table]"); process.exit(2); }
const archives = await load(resolve(dir));
const found = closure(archives);
if (JSON.stringify(found) !== JSON.stringify([...FILES].sort())) throw new Error(`import closure changed:\n${found.join("\n")}`);

const outputs = new Map(); // repo-relative path -> bytes
const rows = [];
for (const upstream of FILES) {
    const original = fetchFile(archives, upstream), vendored = Buffer.from(rewrite(upstream, original.toString("utf8")), "utf8");
    outputs.set(`${VENDOR}/${vendoredPath(upstream)}`, vendored);
    rows.push({ upstream: upstream.replace(/^@noble\/[^/]+\//, (m) => `${m.slice(0, -1)}@${PACKAGES[m.slice(0, -1)].version}/`), vendored: `${VENDOR}/${vendoredPath(upstream)}`, upstreamSHA256: sha256(original), vendoredSHA256: sha256(vendored) });
}
// Node needs to know these .js files are modules; browsers ignore the file.
outputs.set(`${VENDOR}/package.json`, Buffer.from('{\n  "type": "module"\n}\n'));
for (const [name, info] of Object.entries(PACKAGES)) {
    const license = archives[name].get("package/LICENSE");
    if (!license) throw new Error(`${name} has no LICENSE`);
    outputs.set(`${NOTICES}/${info.license}`, license);
}

if (mode === "--table") {
    console.log("| Upstream file | Vendored file | Upstream SHA-256 | Vendored SHA-256 |\n| --- | --- | --- | --- |");
    for (const row of rows) console.log(`| \`${row.upstream}\` | \`${row.vendored}\` | \`${row.upstreamSHA256}\` | \`${row.vendoredSHA256}\` |`);
} else {
    let stale = 0;
    for (const [path, bytes] of outputs) {
        const file = join(root, path);
        if (mode === "--check") {
            const current = await readFile(file).catch(() => null);
            if (!current || !current.equals(bytes)) { stale++; console.error(`differs: ${path}`); }
            continue;
        }
        await mkdir(dirname(file), { recursive: true });
        await writeFile(file, bytes);
    }
    if (stale) { console.error(`${stale} file(s) differ from the pinned upstream release`); process.exit(1); }
    console.log(`${mode === "--check" ? "verified" : "wrote"} ${outputs.size} files from ${Object.keys(PACKAGES).map((n) => `${n}@${PACKAGES[n].version}`).join(", ")}`);
}
