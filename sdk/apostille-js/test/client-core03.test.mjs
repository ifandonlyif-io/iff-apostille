import test from "node:test";
import assert from "node:assert/strict";
import * as core from "../dist/index.mjs";
import { ApostilleClient, ApostilleAPIError } from "../dist/client.mjs";

const issuer = "https://issuer.example/apostille";
const baseURL = "https://issuer.example/api/apostille/v1";
const bytes = (value) => new TextEncoder().encode(value);
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const ed = async () => core.importKeyFile(await core.generateKeyFile({ algorithm: "Ed25519" }));
const ml = async () => core.importKeyFile(await core.generateKeyFile({ algorithm: "ML-DSA-65" }));
const code = (expected) => (error) => error instanceof ApostilleAPIError && error.code === expected;

const directory = (protocol, signer, algorithm) => ({ protocol, issuer, keys: [{ key_id: signer.keyID, public_key: signer.publicKey, algorithm }], trust: "online_bootstrap_only" });
const message = (prefix, key, id, expires) => `${prefix}\nissuer:${issuer}\nkey_id:${key.keyID}\nchallenge:${id}\nexpires_at:${expires}\npurpose:register_or_login`;

test("status exposes protocols and tolerates their absence", async () => {
    const full = new ApostilleClient({ baseURL, issuer, fetch: async () => json({ protocol: core.PROTOCOL, protocols: [core.PROTOCOL, core.PROTOCOL_03], issuer, enabled: true, features: ["ml_dsa_65_keys"], planned: [] }) });
    assert.deepEqual((await full.status()).protocols, [core.PROTOCOL, core.PROTOCOL_03]);
    const old = new ApostilleClient({ baseURL, issuer, fetch: async () => json({ protocol: core.PROTOCOL, issuer, enabled: true, features: [], planned: [] }) });
    assert.equal((await old.status()).protocols, undefined);
    const bad = new ApostilleClient({ baseURL, issuer, fetch: async () => json({ protocol: core.PROTOCOL, protocols: "0.3", issuer, enabled: true }) });
    await assert.rejects(bad.status(), code("invalid_response"));
});

test("keysFor(0.3) requests the escaped protocol and validates the directory", async () => {
    const key = await ml(); let seen;
    const client = new ApostilleClient({ baseURL, issuer, fetch: async (url) => { seen = url; return json(directory(core.PROTOCOL_03, key, "ML-DSA-65")); } });
    const out = await client.keysFor(core.PROTOCOL_03);
    assert.equal(seen, `${baseURL}/keys?protocol=${encodeURIComponent(core.PROTOCOL_03)}`);
    assert.equal(out.keys[0].public_key.length, 2603);
    assert.equal(out.keys[0].key_id, key.keyID);
});

test("keysFor(0.1) is the plain directory route", async () => {
    const key = await ed(); const urls = [];
    const client = new ApostilleClient({ baseURL, issuer, fetch: async (url) => { urls.push(url); return json(directory(core.PROTOCOL, key, "Ed25519")); } });
    assert.deepEqual(await client.keysFor(core.PROTOCOL), await client.keys());
    assert.deepEqual(urls, [`${baseURL}/keys`, `${baseURL}/keys`]);
});

test("keysFor rejects every invalid directory", async () => {
    const key = await ml(), other = await ml(), edKey = await ed();
    const good = () => directory(core.PROTOCOL_03, key, "ML-DSA-65");
    const cases = {
        "wrong protocol echo": (d) => { d.protocol = core.PROTOCOL; },
        "0.2 echo": (d) => { d.protocol = core.PROTOCOL_02; },
        "wrong issuer": (d) => { d.issuer = "https://other.example/apostille"; },
        "wrong algorithm": (d) => { d.keys[0].algorithm = "Ed25519"; },
        "short key": (d) => { d.keys[0].public_key = d.keys[0].public_key.slice(0, 2602); },
        "long key": (d) => { d.keys[0].public_key += "A"; },
        "ed25519 key": (d) => { d.keys[0] = { key_id: edKey.keyID, public_key: edKey.publicKey, algorithm: "ML-DSA-65" }; },
        "fingerprint": (d) => { d.keys[0].key_id = other.keyID; },
        "missing keys": (d) => { delete d.keys; },
        "null key": (d) => { d.keys[0] = null; },
    };
    for (const [name, mutate] of Object.entries(cases)) {
        const dir = good(); mutate(dir);
        const client = new ApostilleClient({ baseURL, issuer, fetch: async () => json(dir) });
        await assert.rejects(client.keysFor(core.PROTOCOL_03), code("invalid_key_directory"), name);
    }
});

test("keysFor surfaces the 400 for 0.2 and refuses unknown versions without a request", async () => {
    let calls = 0;
    const client = new ApostilleClient({ baseURL, issuer, fetch: async () => { calls++; return json({ code: "unsupported_protocol_version" }, 400); } });
    await assert.rejects(client.keysFor(core.PROTOCOL_02), (e) => e.status === 400 && e.code === "unsupported_protocol_version");
    assert.equal(calls, 1);
    for (const protocol of ["", "https://ifandonlyif.io/apostille/spec/0.4", core.PROTOCOL_03.toUpperCase(), undefined]) {
        await assert.rejects(client.keysFor(protocol), code("unsupported_protocol_version"));
    }
    assert.equal(calls, 1);
});

function loginFetch(signer, prefix, tamper = (m) => m) {
    const state = { verified: 0 };
    state.fetch = async (url, options) => {
        const input = JSON.parse(options.body);
        if (url.endsWith("/auth/challenges")) {
            assert.equal(input.public_key, signer.publicKey);
            state.id = crypto.randomUUID(); state.expires = core.timestamp(new Date(Date.now() + 300000));
            state.message = tamper(message(prefix, signer, state.id, state.expires));
            return json({ challenge_id: state.id, message: state.message, expires_at: state.expires, issuer }, 201);
        }
        state.verified++;
        assert.equal(input.message, state.message);
        const valid = signer.algorithm === "ML-DSA-65" ? core.verifyLogin03(signer.publicKey, input.message, input.signature) : input.signature.length === 86;
        if (!valid) return json({ code: "invalid_signature" }, 401);
        return json({ access_token: "session-token", token_type: "Bearer", expires_in: 900, workspace: { admin_key_id: signer.keyID, admin_public_key: signer.publicKey } });
    };
    return state;
}

test("login works for Ed25519 (0.1 message) and ML-DSA-65 (0.3 message, 4412-char signature)", async () => {
    for (const [signer, prefix] of [[await ed(), "iff-apostille/login/0.1"], [await ml(), "iff-apostille/login/0.3"]]) {
        const state = loginFetch(signer, prefix);
        let signatureLength = 0;
        const client = new ApostilleClient({ baseURL, issuer, fetch: async (url, options) => {
            if (url.endsWith("/auth/verify")) signatureLength = JSON.parse(options.body).signature.length;
            return state.fetch(url, options);
        } });
        const result = await client.login(signer);
        assert.equal(result.workspace.admin_key_id, signer.keyID);
        assert.equal(signatureLength, signer.algorithm === "ML-DSA-65" ? 4412 : 86);
        assert.equal(state.verified, 1);
    }
});

test("a challenge needs the prefix of the key's algorithm and the exact message", async () => {
    const mlKey = await ml(), edKey = await ed();
    const cases = {
        "ml-dsa key with the 0.1 prefix": [mlKey, "iff-apostille/login/0.1"],
        "ed25519 key with the 0.3 prefix": [edKey, "iff-apostille/login/0.3"],
        "extra line": [mlKey, "iff-apostille/login/0.3", (m) => m + "\nextra:1"],
        "another key": [mlKey, "iff-apostille/login/0.3", (m) => m.replace(mlKey.keyID, edKey.keyID)],
        "another issuer": [mlKey, "iff-apostille/login/0.3", (m) => m.replace(issuer, "https://other.example/apostille")],
    };
    for (const [name, [signer, prefix, tamper]] of Object.entries(cases)) {
        const state = loginFetch(signer, prefix, tamper);
        const client = new ApostilleClient({ baseURL, issuer, fetch: state.fetch });
        await assert.rejects(client.createChallenge(signer.publicKey), code("invalid_challenge"), name);
        await assert.rejects(client.login(signer), code("invalid_challenge"), name);
        assert.equal(state.verified, 0, `${name}: no proof is sent`);
    }
});

test("createChallenge rejects a malformed key before any request", async () => {
    let calls = 0;
    const client = new ApostilleClient({ baseURL, issuer, fetch: async () => { calls++; return json({}); } });
    const key = await ml();
    for (const bad of ["", "short", key.publicKey + "A", key.publicKey.slice(0, 2602)]) await assert.rejects(client.createChallenge(bad));
    assert.equal(calls, 0);
});

async function core03() {
    const admin = await ml(), agent = await ml(), hosted = await ml();
    const reg = await core.createRegistration(admin, agent, issuer, 30, core.PROTOCOL_03);
    const statement = await core.createStatement(bytes("local original"), "text/plain", agent, reg);
    const grant = await core.createGrant(statement, reg, admin, issuer, "private");
    return { admin, agent, hosted, reg, statement, grant };
}
const certify = (f, input, signer = f.hosted) => core.issueBundle({ protocol: core.PROTOCOL_03, statement: input, delegation: f.reg.delegation, acceptance: f.reg.acceptance, certificate: null }, signer, issuer);
const submissionClient = (bundle, trustedKeyIDs = []) => new ApostilleClient({ baseURL, issuer, trustedKeyIDs, accessToken: "test", fetch: async () => json({ id: crypto.randomUUID(), is_public: false, bundle: await bundle() }, 201) });

test("a 0.3 submission accepts a 0.3 certificate from the pinned hosted ML-DSA issuer", async () => {
    const f = await core03();
    const certified = await certify(f, f.statement);
    const record = await submissionClient(() => certified, [f.hosted.keyID]).submit(f.statement, f.grant);
    assert.equal(record.bundle.protocol, core.PROTOCOL_03);
    assert.equal(record.bundle.certificate.signature.algorithm, "ML-DSA-65");
    await submissionClient(() => certified).submit(f.statement, f.grant);
    await assert.rejects(submissionClient(() => certified, [f.admin.keyID]).submit(f.statement, f.grant), code("invalid_certificate_response"));
});

test("a submission rejects a bundle of another protocol version or statement", async () => {
    const f = await core03();
    const admin01 = await ed(), agent01 = await ed(), hosted01 = await ed();
    const reg01 = await core.createRegistration(admin01, agent01, issuer);
    const statement01 = await core.createStatement(bytes("local original"), "text/plain", agent01, reg01);
    const grant01 = await core.createGrant(statement01, reg01, admin01, issuer, "private");
    const bundle01 = await core.issueBundle({ protocol: core.PROTOCOL, statement: statement01, ...reg01, certificate: null }, hosted01, issuer);
    await assert.rejects(submissionClient(() => bundle01).submit(f.statement, f.grant), code("invalid_certificate_response"));
    await assert.rejects(submissionClient(async () => certify(f, f.statement)).submit(statement01, grant01), code("invalid_certificate_response"));
    assert.equal((await submissionClient(() => bundle01).submit(statement01, grant01)).bundle.protocol, core.PROTOCOL);
    const other = await core03();
    await assert.rejects(submissionClient(async () => certify(other, other.statement, other.hosted)).submit(f.statement, f.grant), code("invalid_certificate_response"));
});

test("getBundle verifies a 0.3 certificate against the pinned ML-DSA issuer", async () => {
    const f = await core03();
    const certified = await certify(f, f.statement);
    const client = new ApostilleClient({ baseURL, issuer, trustedKeyIDs: [f.hosted.keyID], accessToken: "test", fetch: async () => json(certified) });
    const fetched = await client.getBundle(crypto.randomUUID());
    assert.equal(fetched.verification.protocol, core.PROTOCOL_03);
    assert.equal(fetched.verification.issuer_trust, "accepted_by_policy");
});

test("keysFor(0.2) applies the strict Ed25519 key check", async () => {
    // The identity point decodes and has a valid key ID, but Core 0.2 rejects it.
    const identity = new Uint8Array(32); identity[0] = 1;
    const publicKey = core.b64(identity);
    const keyID = await core.fingerprint(publicKey);
    const client = new ApostilleClient({ baseURL, issuer, fetch: async () => json({ protocol: core.PROTOCOL_02, issuer, keys: [{ key_id: keyID, public_key: publicKey, algorithm: "Ed25519" }], trust: "online_bootstrap_only" }) });
    await assert.rejects(client.keysFor(core.PROTOCOL_02), code("invalid_key_directory"));
    const honest = await ed();
    const ok = new ApostilleClient({ baseURL, issuer, fetch: async () => json(directory(core.PROTOCOL_02, honest, "Ed25519")) });
    assert.equal((await ok.keysFor(core.PROTOCOL_02)).keys[0].key_id, honest.keyID);
});

test("a grant of another version is refused before any request", async () => {
    const f = await core03();
    const admin01 = await ed();
    const delegation = await core.envelopeDigest(f.reg.delegation);
    const payload = { ...core.header("publication-grant", admin01, new Date(), undefined, core.PROTOCOL), statement_sha256: await core.envelopeDigest(f.statement), delegation_sha256: delegation, service_audience: issuer, visibility: "private", purpose: "issue_origin_certificate", expires_at: core.timestamp(Date.now() + 300000), nonce: crypto.randomUUID() };
    const grant01 = await core.sign("publication-grant", payload, admin01, core.PROTOCOL);
    let calls = 0;
    const client = new ApostilleClient({ baseURL, issuer, accessToken: "test", fetch: async () => { calls++; return json({}); } });
    await assert.rejects(client.submit(f.statement, grant01), code("invalid_publication_grant"));
    assert.equal(calls, 0);
});

test("an old server: ignored query and a refused ML-DSA-65 challenge, with no fallback", async () => {
    const hosted = await ed(), admin = await ml(); const paths = [];
    const client = new ApostilleClient({ baseURL, issuer, fetch: async (url) => {
        const path = new URL(url).pathname; paths.push(path);
        if (path.endsWith("/keys")) return json(directory(core.PROTOCOL, hosted, "Ed25519"));
        if (path.endsWith("/status")) return json({ protocol: core.PROTOCOL, issuer, enabled: true, features: [], planned: [] });
        return json({ code: "invalid_public_key" }, 400);
    } });
    assert.equal((await client.status()).protocols, undefined);
    await assert.rejects(client.keysFor(core.PROTOCOL_03), code("invalid_key_directory"));
    await assert.rejects(client.login(admin), code("invalid_public_key"));
    assert.equal(paths.at(-1), "/api/apostille/v1/auth/challenges");
});

test("a server with Core 0.3 disabled refuses the 0.3 directory and challenge", async () => {
    const admin = await ml(); let verifyCalls = 0;
    const client = new ApostilleClient({ baseURL, issuer, fetch: async (url) => {
        const path = new URL(url).pathname;
        if (path.endsWith("/status")) return json({ protocol: core.PROTOCOL, protocols: [core.PROTOCOL], issuer, enabled: true, features: [], planned: [] });
        if (path.endsWith("/keys")) return json({ code: "unsupported_protocol_version" }, 400);
        if (path.endsWith("/auth/challenges")) return json({ code: "unsupported_key_algorithm" }, 400);
        verifyCalls++; return json({ code: "unexpected" }, 500);
    } });
    assert.deepEqual((await client.status()).protocols, [core.PROTOCOL]);
    await assert.rejects(client.keysFor(core.PROTOCOL_03), code("unsupported_protocol_version"));
    await assert.rejects(client.login(admin), code("unsupported_key_algorithm"));
    assert.equal(verifyCalls, 0);
});

test("a historical 0.1 bundle is not limited by an ML-DSA-65 session", async () => {
    const admin01 = await ed(), agent01 = await ed(), hosted01 = await ed(), hosted03 = await ml();
    const reg01 = await core.createRegistration(admin01, agent01, issuer);
    const statement01 = await core.createStatement(bytes("historical"), "text/plain", agent01, reg01);
    const bundle01 = await core.issueBundle({ protocol: core.PROTOCOL, statement: statement01, ...reg01, certificate: null }, hosted01, issuer);
    const client = new ApostilleClient({ baseURL, issuer, trustedKeyIDs: [hosted01.keyID, hosted03.keyID], accessToken: "ml-dsa-session", fetch: async () => json(bundle01) });
    const fetched = await client.getBundle(crypto.randomUUID());
    assert.equal(fetched.verification.protocol, core.PROTOCOL);
    assert.equal(fetched.verification.issuer_trust, "accepted_by_policy");
});
