import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PROTOCOL, b64, unb64, hash, decodeBytes, parseStrict, canonical, verifyBundle, verifyEnvelope, verifyArtifact, generateKeyFile, importKeyFile, sign, header, envelopeDigest, createRegistration, createStatement, createGrant, signLogin } from './apostille-core.mjs';
const vector = JSON.parse(await readFile(new URL('../testdata/apostille/core-0.1.json', import.meta.url), 'utf8'));
const bytes = (s) => new TextEncoder().encode(s);
const opts = { issuer: vector.issuer, keyIDs: [vector.issuer_key_id], at: vector.evaluation_time };

test('Go vector verifies with independently supplied trust and original bytes', async () => {
  const result = await verifyBundle(JSON.stringify(vector.bundle), opts);
  assert.equal(result.artifact_integrity, 'valid');
  assert.equal(result.issuer_trust, 'accepted_by_policy');
  assert.equal(result.organization_binding, 'unproven');
  assert.equal(result.authorization_policy, 'current_revocation_unknown');
  assert.equal(result.freshness, 'valid_at_evaluation_time');
  assert.equal(await verifyArtifact(result, bytes(vector.artifact)), true);
  assert.equal(await verifyArtifact(result, bytes('changed')), false);
});
test('embedded key never establishes issuer trust or current status', async () => {
  assert.equal((await verifyBundle(vector.bundle)).issuer_trust, 'unknown');
  assert.equal((await verifyBundle(vector.bundle)).freshness, 'unknown');
  for (const policy of [{issuer: vector.issuer}, {keyIDs: opts.keyIDs}, {...opts, issuer: 'https://another.example/apostille'}, {...opts, keyIDs: ['sha256:'+'0'.repeat(64)]}]) {
    assert.equal((await verifyBundle(vector.bundle, policy)).issuer_trust, 'untrusted');
  }
  assert.equal((await verifyBundle(vector.bundle, {...opts, at: '2030-01-01T00:00:00Z'})).freshness, 'expired');
});
test('reject tamper, graft, unknown fields, missing attachments and bad encodings', async () => {
  for (const mutate of [
    b => { b.statement.payload_sha256 = '0'.repeat(64); },
    b => { b.certificate.signature.public_key = b.statement.signature.public_key; },
    b => { b.statement.signature.value += '='; },
    b => { b.acceptance = null; },
    b => { b.extra = true; },
    b => { delete b.certificate; },
    b => { b.statement.payload = b64(bytes('{"kind":"origin-statement","kind":"origin-statement"}')); },
  ]) { const b = structuredClone(vector.bundle); mutate(b); await assert.rejects(verifyBundle(b, opts)); }
});
test('strict I-JSON and JCS profile rejects ambiguous or oversized inputs', () => {
  for (const raw of ['{"a":true,"a":false}', '{"n":1}', '{"x":"\\ud800"}', '[true,]', '{}{}', ' '.repeat(262145), '['.repeat(26)+'null'+']'.repeat(26)]) assert.throws(() => parseStrict(raw));
  assert.equal(canonical(parseStrict('{"z":"中","😀":"x","a":"\\n"}')), '{"a":"\\n","z":"中","😀":"x"}');
});
test('UTF-8 decoding preserves BOM for strict rejection without changing string contents', () => {
  assert.throws(() => parseStrict(decodeBytes(bytes('\ufeff{"value":"test"}'))));
  assert.throws(() => decodeBytes(new Uint8Array([0xff])));
  const text = '{"value":"\ufeff互通"}';
  assert.equal(canonical(parseStrict(decodeBytes(bytes(text)))), text);
});
test('key import checks seed metadata and accepts CLI role without changing signature', async () => {
  const key = await generateKeyFile();
  const signer = await importKeyFile({...key, role: 'agent'});
  assert.equal(signer.keyID, key.key_id);
  await assert.rejects(importKeyFile({...key, key_id: 'sha256:'+'0'.repeat(64)}));
  await assert.rejects(importKeyFile({...key, role: {authority: true}}));
  await assert.rejects(importKeyFile({...key, extra: true}));
});
test('browser signing binds delegation, source, publication audience and purpose', async () => {
  const admin = await importKeyFile(await generateKeyFile()), agent = await importKeyFile(await generateKeyFile());
  const reg = await createRegistration(admin, agent, vector.issuer);
  const statement = await createStatement(bytes('local record'), 'text/plain', agent, reg);
  const grant = await createGrant(statement, reg, admin, vector.issuer, 'private');
  const p = await verifyEnvelope(grant, 'publication-grant');
  assert.equal(p.statement_sha256, await envelopeDigest(statement));
  assert.equal(p.delegation_sha256, await envelopeDigest(reg.delegation));
  assert.equal(p.visibility, 'private');
  assert.equal(p.purpose, 'issue_origin_certificate');
  const producer = await verifyBundle({protocol: PROTOCOL, statement, ...reg, certificate:null});
  assert.equal(producer.certificate_scope, 'producer_only');
  assert.equal(producer.issuer_trust, 'unknown');
  await assert.rejects(signLogin('arbitrary signature', admin, vector.issuer));
  await assert.rejects(verifyEnvelope(grant, 'origin-statement'));
});
test('issuer identifiers reject ambiguous URLs consistently with Go', async () => {
  const signer = await importKeyFile(await generateKeyFile());
  const payload = JSON.parse(new TextDecoder().decode(unb64(vector.bundle.certificate.payload)));
  for (const issuer of ['https://Issuer.example/a', 'https://issuer.example:443/a', 'https://issuer.example:0444/a', 'https://issuer.example/a%20b', 'https://issuer.example/a\\b', 'https://issuer.example/a?', 'urn:test#', 'http://issuer.example', 'https://user@issuer.example/a']) {
    await assert.rejects(sign('origin-certificate', {...payload, ...header('origin-certificate', signer, new Date(), issuer), expires_at:'2030-01-01T00:00:00Z'}, signer), issuer);
  }
});
