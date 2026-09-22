import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PROTOCOL, decodeBytes, parseStrict, canonical, validIssuer, verifyBundle, verifyArtifact } from './apostille-core.mjs';

// Language-neutral conformance cases shared with the Go implementation
// (apostille/conformance_cases_test.go, TestConformanceCases). This file is
// an independent consumer: bytes are decoded with Node's own base64url
// decoder, never apostille-core.mjs's unb64, so the harness cannot share a
// bug with the code it is checking.
const file = JSON.parse(await readFile(new URL('../testdata/apostille/core-0.1-cases.json', import.meta.url), 'utf8'));

function caseBytes(c) {
  const hasB64 = Object.hasOwn(c, 'input_b64'), hasGen = Object.hasOwn(c, 'input_gen');
  assert.notEqual(hasB64, hasGen, 'case must have exactly one of input_b64/input_gen');
  if (hasB64) return Buffer.from(c.input_b64, 'base64url');
  const repeat = Buffer.from(c.input_gen.repeat_b64, 'base64url');
  return Buffer.alloc(repeat.length * c.input_gen.count).fill(repeat);
}

test('case file guards', () => {
  assert.equal(file.protocol, PROTOCOL);
  assert.equal(file.format, 1);
  assert.ok(file.bundle_cases.length > 0, 'bundle_cases must be non-empty');
  assert.ok(file.strict_json_cases.length > 0, 'strict_json_cases must be non-empty');
  assert.ok(file.issuer_cases.length > 0, 'issuer_cases must be non-empty');
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
test('bundle_cases', async () => {
  const failures = [];
  for (const c of file.bundle_cases) {
    try {
      const bytes = caseBytes(c);
      const run = async () => {
        const text = decodeBytes(bytes);
        return verifyBundle(text, { issuer: c.options.issuer, keyIDs: c.options.key_ids, at: c.options.at });
      };
      if (c.expect.result === 'reject') {
        await assert.rejects(run());
      } else if (c.expect.result === 'accept') {
        const result = await run();
        for (const key of Object.keys(c.expect.verification)) {
          if (key === 'statement') continue;
          assert.equal(result[key], c.expect.verification[key], `${c.name}: ${key}`);
        }
        if (Object.hasOwn(c, 'artifact_b64')) {
          const artifactBytes = Buffer.from(c.artifact_b64, 'base64url');
          assert.equal(await verifyArtifact(result, artifactBytes), c.expect.artifact_match, `${c.name}: artifact_match`);
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

test('strict_json_cases', () => {
  const failures = [];
  for (const c of file.strict_json_cases) {
    try {
      const bytes = caseBytes(c);
      if (c.expect === 'reject') {
        assert.throws(() => parseStrict(decodeBytes(bytes)));
      } else if (c.expect === 'accept') {
        const got = Buffer.from(new TextEncoder().encode(canonical(parseStrict(decodeBytes(bytes)))));
        const want = Buffer.from(c.canonical_b64, 'base64url');
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

test('issuer_cases', () => {
  const failures = [];
  for (const c of file.issuer_cases) {
    try {
      assert.equal(validIssuer(c.value), c.expect === 'accept', JSON.stringify(c.value));
    } catch (err) {
      failures.push(`${JSON.stringify(c.value)}: ${err.message}`);
    }
  }
  assert.deepEqual(failures, []);
});
