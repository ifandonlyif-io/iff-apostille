import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import * as core from './apostille-core.mjs';
import { PROTOCOL, PROTOCOL_02, PROTOCOL_03, KNOWN_PROTOCOLS, b64, unb64, hash, verifyBundle, verifyEnvelope, generateKeyFile, importKeyFile, sign, header, createRegistration, createStatement, createProducerStatement, createGrant, issueBundle, envelopeDigest, signLogin, signLogin03, verifyLogin03 } from './apostille-core.mjs';
import { PROFILES, profileFor, acceptsProtocol } from './apostille-profile.mjs';
import { strictPoint, verifyStrict } from './apostille-ed25519.mjs';
import { MLDSA65, mldsaKeys, signMLDSA, verifyMLDSA } from './apostille-mldsa.mjs';
import { ed25519 } from './vendor/noble/curves/ed25519.js';
import { ml_dsa65 } from './vendor/noble/post-quantum/ml-dsa.js';

const data = async (name) => JSON.parse(await readFile(new URL(`../testdata/apostille/${name}`, import.meta.url), 'utf8'));
const [vector01, vector02, vector03, hedged, wycheproof, cases02, cases03] = await Promise.all(['core-0.1.json', 'core-0.2.json', 'core-0.3.json', 'core-0.3-hedged.json', 'core-0.3-wycheproof.json', 'core-0.2-cases.json', 'core-0.3-cases.json'].map(data));
const bytes = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const fromB64 = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const sha256 = (b) => createHash('sha256').update(b).digest();
const concat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
const rejectsWith = async (promise, pattern) => assert.rejects(promise, pattern);
const P = ed25519.Point;
const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
const signingInput = (version, kind, payload) => concat(bytes(`iff-apostille/${kind}/${version}\n`), sha256(payload));
// Public fixture seeds: 32 repeated bytes (administrator 1, agent 2, issuer 3), the same bytes the Go generator uses.
async function fixtureSigner(protocol, n) {
  const seed = new Uint8Array(32).fill(n), publicKey = b64(protocol === PROTOCOL_03 ? mldsaKeys(seed).publicKey : ed25519.getPublicKey(seed));
  return importKeyFile({ protocol: protocol === PROTOCOL_03 ? PROTOCOL_03 : PROTOCOL, seed: b64(seed), public_key: publicKey, key_id: await core.fingerprint(publicKey, protocol) });
}
const SMALL_ORDER = ['0100000000000000000000000000000000000000000000000000000000000000', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000080', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'];

// ---------------------------------------------------------------------------
// Version dispatch (contract C1)
// ---------------------------------------------------------------------------

test('profile table mirrors the Go profiles', () => {
  assert.deepEqual(KNOWN_PROTOCOLS, [PROTOCOL, PROTOCOL_02, PROTOCOL_03]);
  assert.deepEqual(PROFILES.map((p) => [p.domain, p.algorithm, p.publicKeySize, p.signatureSize, p.encodedPublicKeyLength, p.encodedSignatureLength]), [
    ['0.1', 'Ed25519', 32, 64, 43, 86], ['0.2', 'Ed25519', 32, 64, 43, 86], ['0.3', 'ML-DSA-65', 1952, 3309, 2603, 4412]]);
  assert.equal(profileFor(PROTOCOL_03).protocol, PROTOCOL_03);
  for (const unknown of ['https://ifandonlyif.io/apostille/spec/never-defined', '', undefined, null, 3, PROTOCOL + ' ']) assert.equal(profileFor(unknown), undefined);
  assert.ok(Object.isFrozen(PROFILES) && PROFILES.every(Object.isFrozen));
});

test('acceptedProtocols: undefined accepts every known version, any array only its members', async () => {
  assert.equal(acceptsProtocol(undefined, PROTOCOL_03), true);
  assert.equal(acceptsProtocol(null, PROTOCOL_03), true);
  assert.equal(acceptsProtocol([], PROTOCOL), false);
  assert.equal(acceptsProtocol([PROTOCOL_02], PROTOCOL_02), true);
  assert.equal(acceptsProtocol([PROTOCOL_02], PROTOCOL_03), false);
  assert.throws(() => acceptsProtocol('all', PROTOCOL), /Invalid accepted protocols/);
  for (const [vector, protocol] of [[vector01, PROTOCOL], [vector02, PROTOCOL_02], [vector03, PROTOCOL_03]]) {
    assert.equal((await verifyBundle(vector.bundle)).protocol, protocol, 'the result reports the bundle version');
    assert.equal((await verifyBundle(vector.bundle, { acceptedProtocols: KNOWN_PROTOCOLS })).protocol, protocol);
    await rejectsWith(verifyBundle(vector.bundle, { acceptedProtocols: [] }), /not accepted/);
    await rejectsWith(verifyBundle(vector.bundle, { acceptedProtocols: KNOWN_PROTOCOLS.filter((p) => p !== protocol) }), /not accepted/);
    await rejectsWith(verifyEnvelope(vector.bundle.statement, 'origin-statement', { acceptedProtocols: [] }), /not accepted/);
    await rejectsWith(verifyBundle(vector.bundle, { acceptedProtocols: 'all' }), /Invalid accepted protocols/);
  }
});

test('Go known-answer vectors of every version verify with pinned trust and original bytes', async () => {
  for (const vector of [vector01, vector02, vector03, hedged]) {
    const result = await verifyBundle(JSON.stringify(vector.bundle), vector.issuer ? { issuer: vector.issuer, keyIDs: [vector.issuer_key_id], at: vector.evaluation_time } : {});
    assert.equal(result.artifact_integrity, 'valid');
    assert.equal(result.protocol, vector.bundle.protocol);
    if (vector.issuer) assert.equal(result.issuer_trust, 'accepted_by_policy');
    assert.equal(await core.verifyArtifact(result, bytes('hello\n')), true);
  }
});

test('a bundle carries one version: mixed, relabelled and unknown envelopes fail before any signature work', async () => {
  const [b01, b02, b03] = [vector01, vector02, vector03].map((v) => v.bundle);
  const swap = (bundle, field, from) => ({ ...bundle, [field]: from[field] });
  for (const field of ['statement', 'delegation', 'acceptance', 'certificate']) {
    await rejectsWith(verifyBundle(swap(b02, field, b01)), /mixes protocol versions/);
    await rejectsWith(verifyBundle(swap(b03, field, b02)), /mixes protocol versions/);
    await rejectsWith(verifyBundle(swap(b01, field, b03)), /mixes protocol versions/);
  }
  await rejectsWith(verifyBundle({ ...b02, protocol: PROTOCOL }), /mixes protocol versions/);
  await rejectsWith(verifyBundle({ ...b01, protocol: 'https://ifandonlyif.io/apostille/spec/never-defined' }), /Unsupported bundle/);
  const unknownEnvelope = structuredClone(b01); unknownEnvelope.certificate.protocol = 'https://ifandonlyif.io/apostille/spec/never-defined';
  await rejectsWith(verifyBundle(unknownEnvelope), /Unsupported protocol, algorithm or artifact kind/, '0.1 error text is unchanged');
  await rejectsWith(verifyBundle({ ...b02, delegation: b02.delegation, acceptance: b01.acceptance }), /mixes protocol versions/);
  // Registration, too: delegation and acceptance carry one version.
  await rejectsWith(core.verifyRegistration({ delegation: b02.delegation, acceptance: b01.acceptance }), /different protocol versions/);
});

// ---------------------------------------------------------------------------
// Identifier grammar (contract C4)
// ---------------------------------------------------------------------------

test('0.2 identifier grammar: the specification examples', () => {
  const accepted = ['https://issuer.example/apostille', 'https://issuer.example:8443/a', 'https://127.0.0.1/a', 'https://[::1]/a', 'https://issuer.example/a!b', 'https://issuer.example/a(b)', 'urn:example:private-issuer', 'urn:example:a/b', 'https://a.example/', 'https://a.example/x/', 'https://a.example//x', 'https://[2001:db8:1:2:3:4:5:6]/', 'https://[2001:db8:0:1:1:1:1:1]/', 'https://[::]/', 'https://[1::]/', 'https://[2001:db8::1:0:0:1]/', 'https://ifandonlyif.io/apostille'];
  const rejected = ['HTTPS://issuer.example/a', 'URN:example:x', 'urn:EXAMPLE:x', 'https://Issuer.example/a', 'https://issuer.example:443/a', 'https://issuer.example:0/a', 'https://issuer.example:08443/a', 'https://issuer.example./a', 'https://issuer_example/a', 'https://-issuer.example/a', 'https://issuer.9x/a', 'https://issuer.example/a|b', 'https://issuer.example/a[b]', 'https://issuer.example/a/../b', 'https://issuer.example/./a', 'https://issuer.example/a%20b', 'https://user@issuer.example/a', 'urn:x', 'urn:example:x y', 'https://127.1/a', 'https://256.1.1.1/a', 'https://1.2.3.4.5/a', 'https://2130706433/a', 'https://0x7f.0.0.1/a', 'https://[2001:db8::1:1:1:1:1]/a', 'https://[2001:db8:0:0:1:1:1:1]/a', 'https://[2001:db8:1::0:0:1]/a', 'https://[2001:DB8::1]/a', 'https://[2001:0db8::1]/a', 'https://[::ffff:1.2.3.4]/a', 'https://[fe80::1%eth0]/a', 'https://é.example/a', 'https://issuer.example/a b', '', 'https://', 'urn:', 'http://issuer.example/a', `https://${'a'.repeat(250)}/`];
  for (const value of accepted) assert.equal(core.validIssuer02(value), true, value);
  for (const value of rejected) assert.equal(core.validIssuer02(value), false, value);
  for (const value of [undefined, null, 5, {}, ['https://a.example/']]) assert.equal(core.validIssuer02(value), false);
  // 0.1 keeps its URL-parser rule unchanged, which the grammar replaces only for 0.2 and 0.3.
  assert.equal(core.validIssuer('https://issuer.example/a|b'), true);
  assert.equal(core.validIssuer02('https://issuer.example/a|b'), false);
});

test('the identifier validator uses no URL parser or regular-expression shortcut', async () => {
  const source = await readFile(new URL('./apostille-identifier.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source.replace(/\/\/.*$/gm, ''), /new URL|URL\.|URLPattern/);
});

// ---------------------------------------------------------------------------
// Strict Ed25519 (contract C3)
// ---------------------------------------------------------------------------

test('strict Ed25519: subgroup membership is [L-1]P + P, proven against the library torsion test and the mixed-order vector', () => {
  // The library cannot be asked for [L]P: that is why the check is [L-1]P + P.
  assert.throws(() => P.BASE.multiplyUnsafe(L), RangeError);
  // The specification's mixed-order example: base point plus the order-2 point.
  const order2 = P.fromBytes(fromHex(SMALL_ORDER[1])), mixed = P.BASE.add(order2);
  assert.equal(hex(mixed.toBytes()), '9599999999999999999999999999999999999999999999999999999999999999');
  assert.equal(mixed.isSmallOrder(), false, 'a small-order blocklist accepts the mixed-order point');
  assert.equal(mixed.isTorsionFree(), false);
  assert.throws(() => strictPoint(mixed.toBytes()), /prime-order subgroup/);
  assert.equal(mixed.multiplyUnsafe(L - 1n).add(mixed).is0(), false, '[L-1]P + P is not the identity for it');
  // The eight small-order points: the identity fails the identity rule, the rest the subgroup rule.
  SMALL_ORDER.forEach((encoding, i) => assert.throws(() => strictPoint(fromHex(encoding)), i === 0 ? /identity/ : (i === 2 || i === 3) ? /decode|canonical|subgroup/ : /subgroup/, encoding));
  // Population: honest keys, honest keys plus each torsion point, and the torsion points themselves.
  // strictPoint accepts exactly the non-identity points the library calls torsion-free.
  const torsion = [P.ZERO, ...SMALL_ORDER.map(fromHex).flatMap((e) => { try { return [P.fromBytes(e, true)]; } catch { return []; } })];
  let rejectedMixed = 0, accepted = 0;
  for (let i = 0; i < 12; i++) {
    const honest = P.fromBytes(ed25519.getPublicKey(crypto.getRandomValues(new Uint8Array(32))));
    for (const t of torsion) {
      const point = honest.add(t), encoding = point.toBytes();
      const strict = (() => { try { strictPoint(encoding); return true; } catch { return false; } })();
      assert.equal(strict, !point.is0() && point.isTorsionFree(), hex(encoding));
      if (strict) accepted++; else rejectedMixed++;
    }
  }
  assert.ok(accepted >= 12 && rejectedMixed >= 12 * 7, `accepted ${accepted}, rejected ${rejectedMixed}`);
});

test('strict Ed25519: the mixed-order vectors are signatures a cofactorless verifier accepts, so only the subgroup rule rejects them', async () => {
  for (const name of ['reject/ed25519-mixed-order-key-base-plus-order-2', 'reject/ed25519-mixed-order-key-fixture-key-plus-order-2', 'reject/ed25519-mixed-order-key-fixture-key-plus-order-8']) {
    const bundle = JSON.parse(Buffer.from(cases02.bundle_cases.find((c) => c.name === name).input_b64, 'base64url')), e = bundle.statement;
    const key = unb64(e.signature.public_key), signature = unb64(e.signature.value), input = signingInput('0.2', e.kind, unb64(e.payload));
    assert.equal(P.fromBytes(key).isSmallOrder(), false, `${name}: not small order`);
    assert.equal(P.fromBytes(key).isTorsionFree(), false, `${name}: mixed order`);
    const webcrypto = await crypto.subtle.importKey('raw', key, 'Ed25519', false, ['verify']);
    assert.equal(await crypto.subtle.verify('Ed25519', webcrypto, signature, input), true, `${name}: WebCrypto (cofactorless) accepts`);
    assert.throws(() => verifyStrict(key, input, signature), /public key: point is not in the prime-order subgroup/, name);
  }
});

test('strict Ed25519: honest signatures verify, every deviation fails, and the equation agrees with WebCrypto', async () => {
  for (let i = 0; i < 25; i++) {
    const seed = crypto.getRandomValues(new Uint8Array(32)), message = crypto.getRandomValues(new Uint8Array(i * 7));
    const key = ed25519.getPublicKey(seed), signature = ed25519.sign(message, seed);
    verifyStrict(key, message, signature);
    const webcrypto = await crypto.subtle.importKey('raw', key, 'Ed25519', false, ['verify']);
    assert.equal(await crypto.subtle.verify('Ed25519', webcrypto, signature, message), true);
    const flipped = Uint8Array.from(signature); flipped[40] ^= 1;
    assert.throws(() => verifyStrict(key, message, flipped), /Invalid source signature|invalid source signature/);
    assert.throws(() => verifyStrict(key, concat(message, [0]), signature), /equation/);
    // S + L is the same point equation but not a canonical scalar.
    const s = BigInt('0x' + hex(signature.slice(32).reverse())) + L, padded = Uint8Array.from(signature);
    padded.set(Uint8Array.from(Buffer.from(s.toString(16).padStart(64, '0'), 'hex')).reverse(), 32);
    assert.throws(() => verifyStrict(key, message, padded), /S is not below the group order/);
  }
  assert.throws(() => verifyStrict(new Uint8Array(31), new Uint8Array(), new Uint8Array(64)), /wrong key or signature size/);
  assert.throws(() => verifyStrict(new Uint8Array(32), new Uint8Array(), new Uint8Array(63)), /wrong key or signature size/);
});

test('strict Ed25519: identity R with S = k*a is rejected on an honest key although the cofactorless equation holds', async () => {
  const c = cases02.bundle_cases.find((x) => x.name === 'reject/ed25519-identity-r-valid-s-honest-key');
  const e = JSON.parse(Buffer.from(c.input_b64, 'base64url')).statement;
  const key = unb64(e.signature.public_key), signature = unb64(e.signature.value), input = signingInput('0.2', e.kind, unb64(e.payload));
  assert.equal(hex(signature.slice(0, 32)), SMALL_ORDER[0]);
  const webcrypto = await crypto.subtle.importKey('raw', key, 'Ed25519', false, ['verify']);
  assert.equal(await crypto.subtle.verify('Ed25519', webcrypto, signature, input), true);
  assert.throws(() => verifyStrict(key, input, signature), /R: point is the identity/);
});

test('0.2 vector and fixture keys: every key a 0.2 artifact carries passes the key check', async () => {
  for (const key of [vector02.admin_public_key, vector02.agent_public_key, vector02.bundle.certificate.signature.public_key]) core.fingerprint(key, PROTOCOL_02) && strictPoint(unb64(key));
  const bundle = structuredClone(vector02.bundle);
  assert.equal((await verifyBundle(bundle)).protocol, PROTOCOL_02);
});

// ---------------------------------------------------------------------------
// ML-DSA-65 (contract C6'): the proofs required before the library is relied on
// ---------------------------------------------------------------------------

test('ML-DSA proof (a): noble keygen from the 32-byte seed gives Go\'s public keys for the fixture seeds', () => {
  const published = [vector03.admin_public_key, vector03.agent_public_key, vector03.bundle.certificate.signature.public_key];
  [1, 2, 3].forEach((n, i) => {
    const keys = mldsaKeys(new Uint8Array(32).fill(n));
    assert.equal(b64(keys.publicKey), published[i], `seed ${n}`);
    assert.equal(keys.publicKey.length, 1952);
    assert.equal(hex(ml_dsa65.getPublicKey(keys.secretKey)), hex(keys.publicKey));
  });
  // The hedged fixture reuses the same public keys.
  assert.equal(hedged.bundle.delegation.signature.public_key, vector03.admin_public_key);
  assert.throws(() => mldsaKeys(new Uint8Array(31)), /32 bytes/);
});

test('ML-DSA proof (b): Go deterministic and hedged signatures verify in JS, and the deterministic ones are reproduced byte for byte', async () => {
  const signerFor = { 'origin-statement': 2, 'agent-delegation': 1, 'agent-acceptance': 2, 'origin-certificate': 3 };
  for (const [label, vector] of [['deterministic', vector03], ['hedged', hedged]]) {
    for (const field of ['statement', 'delegation', 'acceptance', 'certificate']) {
      const e = vector.bundle[field];
      assert.equal((await verifyEnvelope(e)).kind, e.kind, `${label} ${field} verifies`);
      const sig = unb64(e.signature.value), input = signingInput('0.3', e.kind, unb64(e.payload)), keys = mldsaKeys(new Uint8Array(32).fill(signerFor[e.kind]));
      assert.equal(verifyMLDSA(unb64(e.signature.public_key), input, sig), true);
      // FIPS 204 deterministic variant (rnd = 32 zero bytes) over the same input, empty context.
      const again = ml_dsa65.sign(input, keys.secretKey, { context: new Uint8Array(0), extraEntropy: false });
      if (label === 'deterministic') assert.equal(hex(again), hex(sig), `${field}: JS reproduces Go's deterministic signature`);
      else assert.notEqual(hex(again), hex(sig), `${field}: the hedged signature is a different valid signature`);
    }
  }
});

test('ML-DSA proof (c): every Wycheproof case and every constructed malformed, HashML-DSA and non-empty-context case is rejected by the verifier itself', async () => {
  assert.equal(wycheproof.tests.length, 13);
  for (const tc of wycheproof.tests) {
    const pk = fromB64(tc.public_key_b64), sig = fromB64(tc.signature_b64), msg = fromB64(tc.message_b64);
    assert.equal(pk.length, 1952); assert.equal(sig.length, 3309);
    assert.equal(ml_dsa65.verify(sig, msg, pk, { context: new Uint8Array(0) }), false, `tcId ${tc.tc_id} (library)`);
    assert.equal(verifyMLDSA(pk, msg, sig), false, `tcId ${tc.tc_id}`);
  }
  // Bundle cases: the rejection comes from the signature check, not from an earlier incidental rule.
  const names = cases03.bundle_cases.map((c) => c.name).filter((n) => /wycheproof|ml-dsa-malformed|hashml-dsa|signature-with-context|signed-under-0\.[12]-domain|signature-bit-flipped/.test(n));
  assert.ok(names.length >= 13 + 7 + 2 + 2 + 3, `${names.length} cases selected`);
  for (const name of names) {
    const c = cases03.bundle_cases.find((x) => x.name === name);
    await rejectsWith(verifyBundle(Buffer.from(c.input_b64, 'base64url').toString('utf8')), /^Error: Invalid source signature\.$/, name);
  }
});

test('ML-DSA proof (d): the default context is empty and passing it explicitly is identical', () => {
  const keys = mldsaKeys(new Uint8Array(32).fill(7)), message = bytes('context check'), empty = new Uint8Array(0);
  const implicit = ml_dsa65.sign(message, keys.secretKey, { extraEntropy: false });
  const explicit = ml_dsa65.sign(message, keys.secretKey, { context: empty, extraEntropy: false });
  assert.equal(hex(implicit), hex(explicit));
  assert.equal(ml_dsa65.verify(implicit, message, keys.publicKey), true);
  assert.equal(ml_dsa65.verify(implicit, message, keys.publicKey, { context: empty }), true);
  assert.equal(verifyMLDSA(keys.publicKey, message, implicit), true);
  // M' = 0x00 || 0x00 || M: the library's internal interface signs exactly that, with the same result.
  const mPrime = concat([0, 0], message);
  assert.equal(hex(ml_dsa65.internal.sign(mPrime, keys.secretKey, { extraEntropy: false })), hex(implicit));
  // A non-empty context is a different message, so it verifies only with that context.
  const withContext = ml_dsa65.sign(message, keys.secretKey, { context: bytes('ctx'), extraEntropy: false });
  assert.equal(verifyMLDSA(keys.publicKey, message, withContext), false);
  assert.equal(ml_dsa65.verify(withContext, message, keys.publicKey, { context: bytes('ctx') }), true);
  // Production signing is hedged: two signatures of one message differ, and both verify.
  const [one, two] = [signMLDSA(keys.secretKey, message), signMLDSA(keys.secretKey, message)];
  assert.notEqual(hex(one), hex(two));
  assert.equal(verifyMLDSA(keys.publicKey, message, one) && verifyMLDSA(keys.publicKey, message, two), true);
  assert.equal(MLDSA65.signatureSize, 3309);
});

test('0.3 envelopes: exact key and signature lengths, tags and algorithm strings', async () => {
  const e = vector03.bundle.statement, fresh = () => structuredClone(e);
  for (const [field, mutate] of [['public_key', (v) => v.slice(0, -1)], ['public_key', (v) => v + 'A'], ['value', (v) => v.slice(0, -1)], ['value', (v) => v + 'A'], ['value', (v) => v + '=']]) {
    const copy = fresh(); copy.signature[field] = mutate(copy.signature[field]);
    await rejectsWith(verifyEnvelope(copy), /Invalid key or signature encoding/);
  }
  const copy = fresh(); copy.signature.public_key = vector02.agent_public_key; await rejectsWith(verifyEnvelope(copy), /Invalid key or signature encoding/);
  for (const algorithm of ['ml-dsa-65', 'MLDSA65', 'ML-DSA-65 ', 'Ed25519', 'ML-DSA-44', 'ML-DSA-87', '']) {
    const c = fresh(); c.signature.algorithm = algorithm; await rejectsWith(verifyEnvelope(c), /Unsupported protocol, algorithm/, algorithm);
  }
  const ed = structuredClone(vector02.bundle.statement); ed.signature.algorithm = 'ML-DSA-65'; await rejectsWith(verifyEnvelope(ed), /Unsupported protocol, algorithm/);
});

// ---------------------------------------------------------------------------
// Signing forms (contract C2/C2')
// ---------------------------------------------------------------------------

const audience = 'https://issuer.example/apostille';
for (const [version, protocol] of [['0.1', PROTOCOL], ['0.2', PROTOCOL_02], ['0.3', PROTOCOL_03]]) {
  test(`${version} signing forms: registration, statement, grant and issuance verify, and the result reports ${version}`, async () => {
    const file = { algorithm: protocol === PROTOCOL_03 ? 'ML-DSA-65' : 'Ed25519' };
    const admin = await importKeyFile(await generateKeyFile(file)), agent = await importKeyFile(await generateKeyFile(file)), issuerSigner = await importKeyFile(await generateKeyFile(file));
    assert.equal(admin.algorithm, protocol === PROTOCOL_03 ? 'ML-DSA-65' : 'Ed25519');
    const reg = await createRegistration(admin, agent, audience, 30, protocol);
    const statement = await createStatement(bytes('versioned record'), 'text/plain', agent, reg);
    assert.equal(statement.protocol, protocol);
    const grant = await createGrant(statement, reg, admin, audience, 'private');
    assert.equal((await verifyEnvelope(grant, 'publication-grant')).statement_sha256, await envelopeDigest(statement));
    const producer = await createProducerStatement(bytes('producer record'), 'text/plain', agent, crypto.randomUUID(), protocol);
    assert.equal((await verifyBundle({ protocol, statement: producer, delegation: null, acceptance: null, certificate: null })).protocol, protocol);
    const issued = await issueBundle({ protocol, statement, ...reg, certificate: null }, issuerSigner, audience);
    assert.equal(issued.certificate.protocol, protocol);
    assert.equal(issued.certificate.signature.algorithm, protocol === PROTOCOL_03 ? 'ML-DSA-65' : 'Ed25519');
    const result = await verifyBundle(issued, { issuer: audience, keyIDs: [issuerSigner.keyID], at: new Date(), acceptedProtocols: [protocol] });
    assert.equal(result.protocol, protocol);
    assert.equal(result.issuer_trust, 'accepted_by_policy');
    assert.equal(result.agent_binding, 'admin_key_delegation');
    await rejectsWith(verifyBundle(issued, { acceptedProtocols: KNOWN_PROTOCOLS.filter((p) => p !== protocol) }), /not accepted/);
  });
}

test('signing refuses a key of the wrong algorithm, a mixed binding and a bad version before any work', async () => {
  const ed = await importKeyFile(await generateKeyFile({ algorithm: "Ed25519" })), ml = await importKeyFile(await generateKeyFile({ algorithm: 'ML-DSA-65' }));
  const edAgent = await importKeyFile(await generateKeyFile({ algorithm: "Ed25519" })), mlAgent = await importKeyFile(await generateKeyFile({ algorithm: 'ML-DSA-65' }));
  await rejectsWith(createRegistration(ed, edAgent, audience, 30, PROTOCOL_03), /algorithm/);
  await rejectsWith(createRegistration(ml, mlAgent, audience, 30, PROTOCOL_02), /algorithm/);
  await rejectsWith(createRegistration(ed, mlAgent, audience, 30, PROTOCOL), /algorithm/);
  await rejectsWith(createRegistration(ed, edAgent, audience, 30, 'https://ifandonlyif.io/apostille/spec/never-defined'), /Unsupported protocol/);
  await rejectsWith(createProducerStatement(bytes('x'), 'text/plain', ed, crypto.randomUUID(), PROTOCOL_03), /algorithm/);
  assert.throws(() => header('origin-statement', ed, new Date(), undefined, 'nope'), /Unsupported protocol/);
  await rejectsWith(sign('agent-acceptance', { ...header('agent-acceptance', ml, new Date(), undefined, PROTOCOL), agent_id: crypto.randomUUID(), delegation_sha256: '0'.repeat(64) }, ml, PROTOCOL), /algorithm/, 'a 0.3 signer does not sign 0.1');
  await rejectsWith(sign('agent-acceptance', { ...header('agent-acceptance', ed), agent_id: crypto.randomUUID(), delegation_sha256: '0'.repeat(64) }, ed, PROTOCOL_03), /algorithm/, 'an Ed25519 signer does not sign 0.3');
  // No mixing at signing time: a statement or grant refuses a registration of another version.
  const reg02 = await createRegistration(ed, edAgent, audience, 30, PROTOCOL_02), reg01 = await createRegistration(ed, edAgent, audience);
  await rejectsWith(createStatement(bytes('x'), 'text/plain', edAgent, reg02, PROTOCOL), /one protocol version/);
  const statement02 = await createStatement(bytes('x'), 'text/plain', edAgent, reg02);
  await rejectsWith(createGrant(statement02, reg01, ed, audience, 'private'), /one protocol version/);
  await rejectsWith(createGrant(statement02, reg02, ed, audience, 'private', PROTOCOL_03), /one protocol version/);
  // Issuance never certifies a source of another version.
  const issued = await issueBundle({ protocol: PROTOCOL_02, statement: statement02, ...reg02, certificate: null }, ed, audience);
  assert.equal(issued.certificate.protocol, PROTOCOL_02);
  await rejectsWith(issueBundle({ protocol: PROTOCOL_02, statement: statement02, ...reg02, certificate: null }, ml, audience), /algorithm/);
});

// ---------------------------------------------------------------------------
// Post-quantum defaults: a signer's natural version
// ---------------------------------------------------------------------------

test('new key files are ML-DSA-65 by default and signing without a protocol uses the signer\'s natural version', async () => {
  const file = await generateKeyFile();
  assert.equal(file.protocol, PROTOCOL_03);
  assert.equal((await generateKeyFile({})).protocol, PROTOCOL_03);
  assert.equal((await generateKeyFile({ algorithm: 'Ed25519' })).protocol, PROTOCOL);
  const ml = await importKeyFile(file), mlAgent = await importKeyFile(await generateKeyFile());
  const ed = await importKeyFile(await generateKeyFile({ algorithm: 'Ed25519' })), edAgent = await importKeyFile(await generateKeyFile({ algorithm: 'Ed25519' }));
  assert.equal(core.naturalProtocol(ml), PROTOCOL_03);
  assert.equal(core.naturalProtocol(ed), PROTOCOL);
  assert.equal(core.naturalProtocol({ key: ed.key, keyID: ed.keyID, publicKey: ed.publicKey }), PROTOCOL, 'an untagged signer is Ed25519');
  assert.equal(header('origin-statement', ml).protocol, PROTOCOL_03);
  assert.equal(header('origin-statement', ed).protocol, PROTOCOL);
  for (const [admin, agent, protocol, algorithm] of [[ml, mlAgent, PROTOCOL_03, 'ML-DSA-65'], [ed, edAgent, PROTOCOL, 'Ed25519']]) {
    const reg = await createRegistration(admin, agent, audience);
    assert.equal(reg.delegation.protocol, protocol); assert.equal(reg.acceptance.signature.algorithm, algorithm);
    const statement = await createStatement(bytes('natural'), 'text/plain', agent, reg);
    assert.equal(statement.protocol, protocol);
    assert.equal((await createGrant(statement, reg, admin, audience, 'private')).protocol, protocol);
    const producer = await createProducerStatement(bytes('natural'), 'text/plain', agent, crypto.randomUUID());
    assert.equal(producer.protocol, protocol);
    const issued = await issueBundle({ protocol, statement, ...reg, certificate: null }, agent, audience);
    assert.equal(issued.certificate.protocol, protocol);
    assert.equal((await verifyBundle(issued)).protocol, protocol);
  }
  await rejectsWith(createRegistration(ml, edAgent, audience), /algorithm/, 'mixed algorithms are refused, not silently downgraded');
  await rejectsWith(createRegistration(ed, mlAgent, audience), /algorithm/);
});

test('0.2 signing checks the signer key under the strict rules and the 0.2 identifier grammar', async () => {
  const admin = await importKeyFile(await generateKeyFile({ algorithm: "Ed25519" })), agent = await importKeyFile(await generateKeyFile({ algorithm: "Ed25519" }));
  await rejectsWith(createRegistration(admin, agent, 'https://issuer.example/a%20b', 30, PROTOCOL_02), /Invalid delegation/);
  await rejectsWith(createRegistration(admin, agent, 'https://Issuer.example/a', 30, PROTOCOL_02), /Invalid delegation/);
  // A signer whose public key is a small-order point cannot release a signature.
  const bad = { ...agent, publicKey: b64(fromHex(SMALL_ORDER[1])), keyID: await core.fingerprint(b64(fromHex(SMALL_ORDER[1]))) };
  await rejectsWith(sign('agent-acceptance', { ...header('agent-acceptance', bad, new Date(), core.keyIdentity(bad.keyID), PROTOCOL_02), agent_id: crypto.randomUUID(), delegation_sha256: '0'.repeat(64) }, bad, PROTOCOL_02), /small-order|prime-order subgroup|Invalid source signature/i);
  // Each version applies its own identifier rule: 0.1 (URL parser) still accepts a bare '|', the 0.2 grammar does not.
  const reg = await createRegistration(admin, agent, 'https://issuer.example/a!b', 30, PROTOCOL_02);
  assert.equal((await core.verifyRegistration(reg, 'https://issuer.example/a!b')).service_audience, 'https://issuer.example/a!b');
  await createRegistration(admin, agent, 'https://issuer.example/a|b', 30, PROTOCOL);
  await rejectsWith(createRegistration(admin, agent, 'https://issuer.example/a|b', 30, PROTOCOL_02), /Invalid delegation/);
});

// ---------------------------------------------------------------------------
// Key files (contract C3')
// ---------------------------------------------------------------------------

test('key files: 0.1 is Ed25519, 0.3 is ML-DSA-65, 0.2 and anything else is refused', async () => {
  const ed = await generateKeyFile({ algorithm: "Ed25519" }), ml = await generateKeyFile({ algorithm: 'ML-DSA-65' });
  assert.equal(ed.protocol, PROTOCOL); assert.equal(ml.protocol, PROTOCOL_03);
  assert.equal(ed.public_key.length, 43); assert.equal(ml.public_key.length, 2603); assert.equal(ml.seed.length, 43);
  assert.equal(JSON.stringify({ ...ml, role: 'admin' }).length < core.MAX_KEY_FILE_BYTES, true);
  const edSigner = await importKeyFile({ ...ed, role: 'agent' }), mlSigner = await importKeyFile({ ...ml, role: 'admin' });
  assert.equal(edSigner.algorithm, 'Ed25519'); assert.equal(mlSigner.algorithm, 'ML-DSA-65');
  assert.equal(mlSigner.keyID, ml.key_id); assert.equal(mlSigner.publicKey, ml.public_key);
  assert.equal(JSON.stringify(Object.keys(await generateKeyFile({ algorithm: 'Ed25519' }))), JSON.stringify(Object.keys(ed)));
  await rejectsWith(generateKeyFile({ algorithm: 'ML-DSA-44' }), /Unsupported key algorithm/);
  await rejectsWith(importKeyFile({ ...ed, protocol: PROTOCOL_02 }), /Unsupported key file/);
  await rejectsWith(importKeyFile({ ...ml, protocol: PROTOCOL_02 }), /Unsupported key file/);
  await rejectsWith(importKeyFile({ ...ml, protocol: 'https://ifandonlyif.io/apostille/spec/never-defined' }), /Unsupported key file/);
  // An Ed25519 seed placed in a 0.3 file (and the reverse) derives another public key and is refused.
  await rejectsWith(importKeyFile({ ...ml, seed: ed.seed }), /fingerprint mismatch/);
  await rejectsWith(importKeyFile({ ...ed, protocol: PROTOCOL_03 }), /fingerprint mismatch/);
  await rejectsWith(importKeyFile({ ...ed, seed: ml.seed }), /fingerprint mismatch/);
  await rejectsWith(importKeyFile({ ...ml, key_id: 'sha256:' + '0'.repeat(64) }), /fingerprint mismatch/);
  await rejectsWith(importKeyFile({ ...ml, public_key: ed.public_key }), /fingerprint mismatch/);
  // Wrong length (42, 44 and 86 characters), a noncanonical last character, the standard alphabet and the empty string.
  for (const seed of [ml.seed.slice(0, -1), ml.seed + 'A', ml.seed.slice(0, -1) + 'B', '+'.repeat(21) + '/'.repeat(21) + 'A', b64(new Uint8Array(64)), '']) {
    await rejectsWith(importKeyFile({ ...ml, seed }), /seed|base64url|Noncanonical/i, seed);
  }
  for (const role of ['a'.repeat(65), 'a\nb', 'a\rb', 'a\0b', 7, { authority: true }]) await rejectsWith(importKeyFile({ ...ml, role }), /role|Invalid key file/);
  await importKeyFile({ ...ml, role: 'a'.repeat(64) });
  await rejectsWith(importKeyFile({ ...ml, extra: true }), /Missing or unsupported field/);
  // The 4 KiB input limit: the file text, or an object's compact form.
  await importKeyFile(JSON.stringify(ml));
  await rejectsWith(importKeyFile(JSON.stringify({ ...ml, role: 'a'.repeat(64) }) + ' '.repeat(core.MAX_KEY_FILE_BYTES)), /too large/);
  await rejectsWith(importKeyFile({ ...ml, role: 'a'.repeat(5000) }), /too large/);
  const seed = new Uint8Array(32).fill(5), pub = b64(mldsaKeys(seed).publicKey);
  assert.equal((await importKeyFile({ protocol: PROTOCOL_03, seed: b64(seed), public_key: pub, key_id: `sha256:${hex(sha256(unb64(pub)))}` })).publicKey, pub);
});

test('a signer keeps its seed-derived key: signing is hedged and deterministic keygen is stable', async () => {
  const file = await generateKeyFile({ algorithm: 'ML-DSA-65' }), a = await importKeyFile(file), b = await importKeyFile(file);
  assert.equal(a.publicKey, b.publicKey);
  const payload = { ...header('agent-acceptance', a, new Date(), core.keyIdentity(a.keyID), PROTOCOL_03), agent_id: crypto.randomUUID(), delegation_sha256: '1'.repeat(64) };
  const [one, two] = [await sign('agent-acceptance', payload, a, PROTOCOL_03), await sign('agent-acceptance', payload, a, PROTOCOL_03)];
  assert.notEqual(one.signature.value, two.signature.value);
  assert.equal(one.signature.value.length, 4412);
  await verifyEnvelope(one); await verifyEnvelope(two);
});

// ---------------------------------------------------------------------------
// Login 0.3
// ---------------------------------------------------------------------------

test('0.3 login challenge: prefix, 4096-byte bound, purpose separation and key type', async () => {
  const ml = await importKeyFile(await generateKeyFile({ algorithm: 'ML-DSA-65' })), ed = await importKeyFile(await generateKeyFile({ algorithm: "Ed25519" }));
  const message = `${core.LOGIN_PREFIX_03}issuer:${audience}\nkey_id:${ml.keyID}\nchallenge:${crypto.randomUUID()}\nexpires_at:2030-01-01T00:00:00Z\npurpose:register_or_login`;
  const signature = await signLogin03(message, ml);
  assert.equal(signature.length, 4412);
  assert.equal(verifyLogin03(ml.publicKey, message, signature), true);
  assert.equal(verifyLogin03(ml.publicKey, message + ' ', signature), false);
  assert.equal(verifyLogin03(ed.publicKey, message, signature), false);
  assert.equal(verifyLogin03(ml.publicKey, message, signature.slice(1)), false);
  assert.equal(verifyLogin03(ml.publicKey, message, undefined), false);
  assert.equal(verifyLogin03(undefined, message, signature), false);
  const exactly = core.LOGIN_PREFIX_03 + 'a'.repeat(4096 - core.LOGIN_PREFIX_03.length);
  assert.equal(verifyLogin03(ml.publicKey, exactly, await signLogin03(exactly, ml)), true);
  await rejectsWith(signLogin03(exactly + 'a', ml), /Invalid login challenge/);
  await rejectsWith(signLogin03('iff-apostille/login/0.1\nx', ml), /Invalid login challenge/);
  await rejectsWith(signLogin03(message, ed), /ML-DSA-65 key/);
  await rejectsWith(signLogin03(core.LOGIN_PREFIX_03 + '\ud800', ml), /Invalid login challenge/, 'a lone surrogate has no UTF-8 bytes');
  // The 0.1 login stays Ed25519 and refuses a 0.3 key; neither signature substitutes for the other or for a grant.
  await rejectsWith(signLogin(message, ml, audience), /Invalid login challenge/);
  assert.equal(verifyLogin03(ml.publicKey, `iff-apostille/login/0.1\n${message}`, signature), false);
  const reg = await createRegistration(ml, await importKeyFile(await generateKeyFile({ algorithm: 'ML-DSA-65' })), audience, 30, PROTOCOL_03);
  const input = signingInput('0.3', 'agent-delegation', unb64(reg.delegation.payload));
  assert.equal(verifyMLDSA(ml.publicKeyBytes ?? unb64(ml.publicKey), input, unb64(signature)), false, 'a login signature is not a signature over any artifact input');
});

// ---------------------------------------------------------------------------
// Vendored library provenance
// ---------------------------------------------------------------------------

test('vendored noble files match the SHA-256 values recorded in NOTICES.md', async () => {
  const notices = await readFile(new URL('../docs/apostille/NOTICES.md', import.meta.url), 'utf8');
  const rows = [...notices.matchAll(/^\| `(@noble\/[^`]+)` \| `(web\/vendor\/noble\/[^`]+)` \| `([0-9a-f]{64})` \| `([0-9a-f]{64})` \|$/gm)];
  assert.equal(rows.length, 18);
  for (const [, upstream, path, upstreamHash, vendoredHash] of rows) {
    const file = await readFile(new URL(`../${path}`, import.meta.url));
    assert.equal(createHash('sha256').update(file).digest('hex'), vendoredHash, path);
    assert.match(upstream, /^@noble\/(curves@2\.4\.0|hashes@2\.4\.0|post-quantum@0\.7\.1)\//);
    assert.match(upstreamHash, /^[0-9a-f]{64}$/);
    // Only a bare @noble import specifier was rewritten: no vendored file imports a bare module.
    assert.doesNotMatch(file.toString('utf8'), /^(?:import|export)\b[^;]*?\bfrom\s*['"][^./]/m, path);
  }
});
