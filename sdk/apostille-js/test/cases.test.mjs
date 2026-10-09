import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as core from "../dist/index.mjs";

// Language-neutral conformance cases shared with the Go implementation
// (apostille/conformance_cases_test.go, TestConformanceCases) and with
// web/apostille-cases.test.mjs, for every Core version. This exercises the
// BUILT package, so the runner is duplicated here rather than imported from
// the web test.
const versions = [
    { version: "0.1", protocol: core.PROTOCOL, file: "vector-cases.json", issuer: core.validIssuer },
    { version: "0.2", protocol: core.PROTOCOL_02, file: "vector-cases-0.2.json", issuer: core.validIssuer02 },
    { version: "0.3", protocol: core.PROTOCOL_03, file: "vector-cases-0.3.json", issuer: core.validIssuer02 },
];

function caseBytes(c) {
    const hasB64 = Object.hasOwn(c, "input_b64"), hasGen = Object.hasOwn(c, "input_gen");
    assert.notEqual(hasB64, hasGen, "case must have exactly one of input_b64/input_gen");
    if (hasB64) return Buffer.from(c.input_b64, "base64url");
    const repeat = Buffer.from(c.input_gen.repeat_b64, "base64url");
    return Buffer.alloc(repeat.length * c.input_gen.count).fill(repeat);
}

for (const { version, protocol, file: name, issuer } of versions) {
    const file = JSON.parse(await readFile(new URL(`../spec/${name}`, import.meta.url), "utf8"));

    test(`${version} case file guards`, () => {
        assert.equal(file.protocol, protocol);
        assert.equal(file.format, 1);
        assert.ok(file.bundle_cases.length > 0, "bundle_cases must be non-empty");
        assert.ok(file.strict_json_cases.length > 0, "strict_json_cases must be non-empty");
        assert.ok(file.issuer_cases.length > 0, "issuer_cases must be non-empty");
        const bundleNames = new Set();
        for (const c of file.bundle_cases) {
            assert.equal(bundleNames.has(c.name), false, `duplicate bundle case name: ${c.name}`);
            bundleNames.add(c.name);
        }
        const strictNames = new Set();
        for (const c of file.strict_json_cases) {
            assert.equal(strictNames.has(c.name), false, `duplicate strict_json case name: ${c.name}`);
            strictNames.add(c.name);
        }
    });

    // One test() per section, failures collected and asserted once at the end,
    // so a single run reports EVERY diverging case rather than stopping at the
    // first (each failure entry always leads with the case name).
    test(`${version} bundle_cases`, async () => {
        const failures = [];
        for (const c of file.bundle_cases) {
            try {
                const bytes = caseBytes(c);
                const run = async () => {
                    const text = core.decodeBytes(bytes);
                    return core.verifyBundle(text, { issuer: c.options.issuer, keyIDs: c.options.key_ids, at: c.options.at });
                };
                if (c.expect.result === "reject") {
                    await assert.rejects(run());
                } else if (c.expect.result === "accept") {
                    const result = await run();
                    for (const key of Object.keys(c.expect.verification)) {
                        if (key === "statement") continue;
                        assert.equal(result[key], c.expect.verification[key], `${c.name}: ${key}`);
                    }
                    if (Object.hasOwn(c, "artifact_b64")) {
                        const artifactBytes = Buffer.from(c.artifact_b64, "base64url");
                        assert.equal(await core.verifyArtifact(result, artifactBytes), c.expect.artifact_match, `${c.name}: artifact_match`);
                    }
                } else {
                    throw new Error(`unknown expect.result ${c.expect.result}`);
                }
            } catch (err) {
                failures.push(`${c.name}: ${err.message}`);
            }
        }
        assert.deepEqual(failures, []);
    });

    test(`${version} strict_json_cases`, () => {
        const failures = [];
        for (const c of file.strict_json_cases) {
            try {
                const bytes = caseBytes(c);
                if (c.expect === "reject") {
                    assert.throws(() => core.parseStrict(core.decodeBytes(bytes)));
                } else if (c.expect === "accept") {
                    const got = Buffer.from(new TextEncoder().encode(core.canonical(core.parseStrict(core.decodeBytes(bytes)))));
                    const want = Buffer.from(c.canonical_b64, "base64url");
                    assert.deepEqual(got, want, `${c.name}: canonical mismatch`);
                } else {
                    throw new Error(`unknown expect ${c.expect}`);
                }
            } catch (err) {
                failures.push(`${c.name}: ${err.message}`);
            }
        }
        assert.deepEqual(failures, []);
    });

    test(`${version} issuer_cases`, () => {
        const failures = [];
        for (const c of file.issuer_cases) {
            try {
                assert.equal(issuer(c.value), c.expect === "accept", JSON.stringify(c.value));
            } catch (err) {
                failures.push(`${JSON.stringify(c.value)}: ${err.message}`);
            }
        }
        assert.deepEqual(failures, []);
    });
}

test("known-answer bundles of every version, deterministic and hedged, verify in the built package", async () => {
    for (const name of ["vectors.json", "vectors-0.2.json", "vectors-0.3.json", "vectors-0.3-hedged.json"]) {
        const vector = JSON.parse(await readFile(new URL(`../spec/${name}`, import.meta.url), "utf8"));
        const result = await core.verifyBundle(vector.bundle);
        assert.equal(result.artifact_integrity, "valid", name);
        assert.equal(result.protocol, vector.bundle.protocol, name);
    }
});

test("the built package signs and verifies every version without a network", async (t) => {
    t.mock.method(globalThis, "fetch", () => { throw new Error("offline SDK made a network request"); });
    for (const [protocol, algorithm] of [[core.PROTOCOL, "Ed25519"], [core.PROTOCOL_02, "Ed25519"], [core.PROTOCOL_03, "ML-DSA-65"]]) {
        const generate = async () => core.importKeyFile(await core.generateKeyFile({ algorithm }));
        const [admin, agent, issuerSigner] = [await generate(), await generate(), await generate()], issuer = "https://issuer.example/apostille";
        const registration = await core.createRegistration(admin, agent, issuer, 30, protocol);
        const statement = await core.createStatement(new TextEncoder().encode("built package\n"), "text/plain", agent, registration);
        const bundle = await core.issueBundle({ protocol, statement, ...registration, certificate: null }, issuerSigner, issuer);
        const result = await core.verifyBundle(bundle, { issuer, keyIDs: [issuerSigner.keyID], at: new Date(), acceptedProtocols: [protocol] });
        assert.equal(result.protocol, protocol);
        assert.equal(result.issuer_trust, "accepted_by_policy");
    }
});
