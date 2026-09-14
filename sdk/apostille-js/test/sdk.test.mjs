import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as core from "../dist/index.mjs";
import { ApostilleClient, ApostilleAPIError } from "../dist/client.mjs";

const issuer = "https://issuer.example/apostille";
const baseURL = "https://issuer.example/api/apostille/v1";
const bytes = (value) => new TextEncoder().encode(value);
const json = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json", ...headers } });
const signer = async () => core.importKeyFile(await core.generateKeyFile());
function gate() { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; }
function challenge(key, claimedIssuer = issuer) {
    const challenge_id = crypto.randomUUID(), expires_at = core.timestamp(new Date(Date.now() + 300000));
    return { issuer: claimedIssuer, challenge_id, expires_at, message: `iff-apostille/login/0.1\nissuer:${claimedIssuer}\nkey_id:${key.keyID}\nchallenge:${challenge_id}\nexpires_at:${expires_at}\npurpose:register_or_login` };
}

async function erc8004Document(bindingSigner, registration, request, ownerSignature, issuedAt = new Date()) {
    const issued = new Date(issuedAt); issued.setMilliseconds(0);
    const ts = (date) => core.timestamp(date);
    const payload = {
        protocol: core.ERC8004_PROTOCOL, kind: "erc8004-binding", issuer,
        issuer_key_id: bindingSigner.keyID, issued_at: ts(issued), request,
        owner_signature: ownerSignature, block_number: "123", block_hash: `0x${"12".repeat(32)}`,
        block_timestamp: ts(new Date(issued.getTime() - 30000)),
        expires_at: ts(new Date(issued.getTime() + 3600000)), check: "owner_of_eoa",
    };
    const raw = bytes(core.canonical(payload));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
    const domain = bytes("iff-apostille/erc8004-binding/snapshot/0.1\n"), input = new Uint8Array(domain.length + digest.length);
    input.set(domain); input.set(digest, domain.length);
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", bindingSigner.key, input));
    return { protocol: core.ERC8004_PROTOCOL, binding: {
        protocol: core.ERC8004_PROTOCOL, kind: "erc8004-binding", payload: core.b64(raw), payload_sha256: await core.hash(raw),
        signature: { algorithm: "Ed25519", key_id: bindingSigner.keyID, public_key: bindingSigner.publicKey, value: core.b64(signature) },
    }, ...registration };
}

test("the default package entry signs, issues and verifies without any fetch", async (t) => {
    t.mock.method(globalThis, "fetch", () => { throw new Error("offline SDK made a network request"); });
    assert.equal(Object.hasOwn(core, "ApostilleClient"), false);
    const producer = await signer(), issuerSigner = await signer();
    const artifact = bytes("private bot record\n");
    const statement = await core.createProducerStatement(artifact, "text/plain", producer, crypto.randomUUID());
    const bundle = await core.issueBundle({ protocol: core.PROTOCOL, statement, delegation: null, acceptance: null, certificate: null }, issuerSigner, issuer);
    const unknown = await core.verifyBundle(bundle);
    assert.equal(unknown.issuer_trust, "unknown");
    const pinned = await core.verifyBundle(bundle, { issuer, keyIDs: [issuerSigner.keyID], at: new Date() });
    assert.equal(pinned.issuer_trust, "accepted_by_policy");
    assert.equal(pinned.authorization_policy, "current_revocation_unknown");
    assert.equal(await core.verifyArtifact(pinned, artifact), true);
    await assert.rejects(core.issueBundle(bundle, issuerSigner, issuer));
    const vector = JSON.parse(await readFile(new URL("../spec/vectors.json", import.meta.url), "utf8"));
    assert.equal((await core.verifyBundle(vector.bundle)).artifact_integrity, "valid");
});

test("configuration is explicit and constructor/import perform no I/O", () => {
    let calls = 0;
    const fetch = () => { calls++; throw new Error("unexpected request"); };
    new ApostilleClient({ baseURL, issuer, fetch });
    for (const bad of ["http://issuer.example/api/apostille/v1", "https://user:secret@issuer.example/api/apostille/v1", baseURL + "?secret", baseURL + "#", "https://issuer.example/a/../api/apostille/v1"]) {
        assert.throws(() => new ApostilleClient({ baseURL: bad, issuer, fetch }));
    }
    assert.throws(() => new ApostilleClient({ baseURL: "http://127.0.0.1:8080/api/apostille/v1", issuer }));
    new ApostilleClient({ baseURL: "http://127.0.0.1:8080/api/apostille/v1", issuer, allowInsecureLocalhost: true });
    assert.equal(calls, 0);
});

test("fetch is invoked with the global receiver for native and injected implementations", async (t) => {
    const response = () => json({ protocol: core.PROTOCOL, issuer, enabled: true, features: [], planned: [] });
    let nativeCalls = 0;
    t.mock.method(globalThis, "fetch", async function () {
        assert.equal(this, globalThis);
        nativeCalls++;
        return response();
    });
    const nativeClient = new ApostilleClient({ baseURL, issuer });
    assert.equal((await nativeClient.status()).issuer, issuer);
    assert.equal(nativeCalls, 1);

    let injectedCalls = 0;
    const injectedClient = new ApostilleClient({ baseURL, issuer, fetch: async function () {
        assert.equal(this, globalThis);
        injectedCalls++;
        return response();
    } });
    assert.equal((await injectedClient.status()).protocol, core.PROTOCOL);
    assert.equal(injectedCalls, 1);
});

test("redirects fail closed and public requests never carry a session", async () => {
    let calls = 0;
    const client = new ApostilleClient({ baseURL, issuer, accessToken: "secret-token", fetch: async (url, options) => {
        calls++;
        assert.equal(options.redirect, "error"); assert.equal(options.credentials, "omit");
        assert.equal(options.headers.Authorization, undefined);
        return new Response(null, { status: 307, headers: { Location: "https://another.example" } });
    } });
    await assert.rejects(client.status(), (e) => e instanceof ApostilleAPIError && e.code === "redirect_rejected");
    assert.equal(calls, 1);
});

test("errors preserve status and retry-after without response secrets or automatic retries", async () => {
    let calls = 0;
    const client = new ApostilleClient({ baseURL, issuer, accessToken: "test", fetch: async () => {
        calls++; return json({ error: true, code: "daily_submission_limit", message: "private response secret" }, 429, { "Retry-After": "30" });
    } });
    await assert.rejects(client.me(), (e) => e.status === 429 && e.retryAfter === "30" && !e.message.includes("private response secret"));
    assert.equal(calls, 1);
    const network = new ApostilleClient({ baseURL, issuer, fetch: async () => { throw new Error("private transport secret"); } });
    await assert.rejects(network.status(), (e) => e.code === "network_error" && !e.message.includes("private transport secret"));
});

test("both declared and streaming response sizes are bounded", async () => {
    for (const declared of [false, true]) {
        let canceled = false;
        const stream = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(1 << 20)); }, cancel() { canceled = true; } });
        const client = new ApostilleClient({ baseURL, issuer, fetch: async () => new Response(stream, { headers: declared ? { "Content-Length": String(9 << 20) } : {} }) });
        await assert.rejects(client.status(), (e) => e.code === "response_too_large");
        assert.equal(canceled, true);
    }
});

test("timeout covers response reading", async () => {
    const client = new ApostilleClient({ baseURL, issuer, timeoutMs: 10, fetch: async (url, options) => new Response(new ReadableStream({ start(controller) { options.signal.addEventListener("abort", () => controller.error(new Error("aborted"))); } })) });
    await assert.rejects(client.status(), (e) => e.code === "request_timeout");
});

test("login rejects a challenge from another issuer before sending a proof", async () => {
    const admin = await signer(); let calls = 0;
    const client = new ApostilleClient({ baseURL, issuer, fetch: async () => { calls++; return json(challenge(admin, "https://other.example/apostille")); } });
    await assert.rejects(client.login(admin), (e) => e.code === "invalid_challenge");
    assert.equal(calls, 1);
});

test("login signing rejects altered purpose, extra lines and expired challenges before WebCrypto", async (t) => {
    const admin = await signer(), valid = challenge(admin);
    const expired = core.timestamp(new Date(Date.now() - 1000));
    const sign = t.mock.method(crypto.subtle, "sign");
    for (const message of [
        valid.message.replace("purpose:register_or_login", "purpose:publish"),
        valid.message + "\npermission:publish",
        valid.message.replace(valid.expires_at, expired),
    ]) await assert.rejects(core.signLogin(message, admin, issuer), /login challenge/i);
    assert.equal(sign.mock.callCount(), 0);
    const signature = await core.signLogin(valid.message, admin, issuer);
    const publicKey = await crypto.subtle.importKey("raw", core.unb64(admin.publicKey), "Ed25519", false, ["verify"]);
    assert.equal(await crypto.subtle.verify("Ed25519", publicKey, core.unb64(signature), bytes(valid.message)), true);
});

test("hosted login rejects noncanonical challenge timestamps before signing", async (t) => {
    const admin = await signer(), data = challenge(admin);
    const noncanonical = data.expires_at.replace("Z", ".000Z");
    data.message = data.message.replace(data.expires_at, noncanonical);
    data.expires_at = noncanonical;
    const sign = t.mock.method(crypto.subtle, "sign");
    const client = new ApostilleClient({ baseURL, issuer, fetch: async () => json(data) });
    await assert.rejects(client.login(admin), (e) => e instanceof ApostilleAPIError && e.code === "invalid_challenge");
    assert.equal(sign.mock.callCount(), 0);
});

test("clearing a session while login is pending cannot restore its token", async () => {
    const admin = await signer(), entered = gate(), release = gate();
    const client = new ApostilleClient({ baseURL, issuer, fetch: async (url) => {
        if (url.endsWith("/auth/challenges")) return json(challenge(admin));
        entered.resolve(); await release.promise;
        return json({ access_token: "old-session", token_type: "Bearer", expires_in: 900, workspace: { admin_key_id: admin.keyID, admin_public_key: admin.publicKey } });
    } });
    const pending = client.login(admin);
    await entered.promise; client.clearSession(); release.resolve();
    await assert.rejects(pending, (e) => e.code === "session_changed");
    await assert.rejects(client.me(), (e) => e.code === "authentication_required");
});

test("submit requires the exact audience/grant and sends no original data or private keys", async () => {
    const admin = await signer(), agent = await signer(), certifier = await signer();
    const reg = await core.createRegistration(admin, agent, issuer);
    const original = "THIS PRIVATE ORIGINAL MUST NEVER BE UPLOADED";
    const statement = await core.createStatement(bytes(original), "text/plain", agent, reg);
    const grant = await core.createGrant(statement, reg, admin, issuer, "private");
    let calls = 0;
    const client = new ApostilleClient({ baseURL, issuer, accessToken: "test", fetch: async (url, options) => {
        calls++;
        assert.equal(url, baseURL + "/submissions");
        assert.equal(options.body.includes(original), false); assert.equal(options.body.includes('"seed"'), false);
        const input = JSON.parse(options.body);
        assert.deepEqual(Object.keys(input).sort(), ["grant", "statement"]);
        const bundle = await core.issueBundle({ protocol: core.PROTOCOL, statement: input.statement, ...reg, certificate: null }, certifier, issuer);
        return json({ id: crypto.randomUUID(), is_public: false, bundle }, 201);
    } });
    const wrong = await core.createGrant(statement, reg, admin, "https://wrong.example/apostille", "private");
    await assert.rejects(client.submit(statement, wrong), (e) => e.code === "invalid_publication_grant");
    assert.equal(calls, 0);
    const record = await client.submit(statement, grant);
    assert.equal(record.is_public, false); assert.equal(calls, 1);
    assert.equal((await core.verifyBundle(record.bundle)).issuer_trust, "unknown");
    await assert.rejects(client.submit({ ...statement, seed: "private" }, grant));
    assert.equal(calls, 1);
});

test("fetched certificates enforce configured issuer and return verification", async () => {
    const producer = await signer(), certifier = await signer();
    const statement = await core.createProducerStatement(bytes("downloaded record"), "text/plain", producer, crypto.randomUUID());
    const source = {protocol:core.PROTOCOL, statement, delegation:null, acceptance:null, certificate:null};
    for (const publicRecord of [false, true]) {
        const wrong = await core.issueBundle(source, certifier, "https://other.example/apostille");
        const id = crypto.randomUUID();
        const client = new ApostilleClient({baseURL, issuer, accessToken:"test", fetch:async()=>json(publicRecord ? {public_id:id,bundle:wrong} : wrong)});
        await assert.rejects(publicRecord ? client.getPublicCertificate(id) : client.getBundle(id), e => e instanceof ApostilleAPIError && e.code === "invalid_certificate_response");
    }
});

test("download verification exposes trust and enforces independent key pins", async () => {
    const producer = await signer(), certifier = await signer();
    const original = bytes("downloaded record");
    const statement = await core.createProducerStatement(original, "text/plain", producer, crypto.randomUUID());
    const bundle = await core.issueBundle({protocol:core.PROTOCOL,statement,delegation:null,acceptance:null,certificate:null},certifier,issuer);
    for(const publicRecord of [false,true]) for(const trustedKeyIDs of [[],[certifier.keyID],[producer.keyID]]) {
        const id = crypto.randomUUID();
        const client = new ApostilleClient({baseURL,issuer,trustedKeyIDs,accessToken:"test",fetch:async()=>json(publicRecord?{public_id:id,bundle}:bundle)});
        const pending=publicRecord?client.getPublicCertificate(id):client.getBundle(id);
        if(trustedKeyIDs[0]===producer.keyID){await assert.rejects(pending,e=>e.code==="invalid_certificate_response");continue;}
        const fetched=await pending;
        assert.equal(core.canonical(fetched.bundle),core.canonical(bundle));
        assert.equal(fetched.verification.issuer_trust,trustedKeyIDs.length?"accepted_by_policy":"untrusted");
        assert.equal(fetched.verification.freshness,"valid_at_evaluation_time");
        assert.equal(await core.verifyArtifact(fetched.verification,original),true);
    }
});

test("SDK issuer configuration uses the core canonical issuer rules", () => {
    assert.throws(() => new ApostilleClient({baseURL, issuer:"https://a.b/x<y"}), error => error instanceof ApostilleAPIError && error.code === "invalid_issuer" && /issuer/.test(error.message));
});

test("URN and HTTPS issuers reject the same ambiguous characters", () => {
    for (const value of ["urn:example:x%2Fy", "urn:example:x\\y", "https://example.com/x%2Fy", "https://example.com/x\\y"]) {
        assert.equal(core.validIssuer(value),false,value);
        assert.throws(()=>new ApostilleClient({baseURL,issuer:value}),e=>e.code==="invalid_issuer");
    }
});

test("ERC-8004 client verifies the exact private binding response and configured pin", async () => {
    const admin = await signer(), agent = await signer(), bindingSigner = await signer();
    const registration = await core.createRegistration(admin, agent, issuer);
    const request = await core.createERC8004Request(admin, registration, {
        chain_id: "8453", registry_address: "0x1111111111111111111111111111111111111111",
        erc8004_agent_id: "42", owner_address: "0x2222222222222222222222222222222222222222",
    }, issuer);
    const ownerSignature = `0x${"34".repeat(65)}`;
    const agentID = (await core.verifyRegistration(registration)).agent_id;
    const document = await erc8004Document(bindingSigner, registration, request, ownerSignature);
    const initialCheck = await core.verifyERC8004Binding(document);
    const record = { id: crypto.randomUUID(), agent_id: agentID, document, created_at: initialCheck.checked_at, expires_at: initialCheck.expires_at };
    const calls = [];
    const client = new ApostilleClient({ baseURL, issuer, trustedKeyIDs: [bindingSigner.keyID], accessToken: "token", fetch: async (url, options) => {
        calls.push({ url, options });
        if (url.endsWith("/erc8004/config")) return json({ profile: core.ERC8004_PROTOCOL, enabled: true, networks: [{ chain_id: "8453", registry_address: "0x1111111111111111111111111111111111111111" }], max_binding_age_seconds: 3600, wallet_support: "eoa_only" });
        return json(record, options.method === "POST" ? 201 : 200);
    } });
    assert.equal((await client.erc8004Config()).enabled, true);
    const created = await client.createERC8004Binding(agentID, request, ownerSignature);
    assert.equal(created.verification.issuer_trust, "pinned");
    assert.equal(created.verification.current_ownership, "unknown");
    assert.equal((await client.getERC8004Binding(agentID)).document.binding.payload_sha256, document.binding.payload_sha256);
    const post = calls.find(({ options }) => options.method === "POST");
    assert.equal(new Headers(post.options.headers).get("Authorization"), "Bearer token");
    assert.deepEqual(JSON.parse(post.options.body), { request, owner_signature: ownerSignature });
});

test("ERC-8004 client rejects confused responses and nonmatching configured pins", async () => {
    const admin = await signer(), agent = await signer(), bindingSigner = await signer();
    const registration = await core.createRegistration(admin, agent, issuer);
    const request = await core.createERC8004Request(admin, registration, {
        chain_id: "1", registry_address: "0x1111111111111111111111111111111111111111",
        erc8004_agent_id: "0", owner_address: "0x2222222222222222222222222222222222222222",
    }, issuer);
    const agentID = (await core.verifyRegistration(registration)).agent_id;
    const submitted = `0x${"56".repeat(65)}`, other = `0x${"78".repeat(65)}`;
    const document = await erc8004Document(bindingSigner, registration, request, other);
    const initialCheck = await core.verifyERC8004Binding(document);
    const response = { id: crypto.randomUUID(), agent_id: agentID, document, created_at: initialCheck.checked_at, expires_at: initialCheck.expires_at };
    for (const trustedKeyIDs of [[], ["sha256:" + "0".repeat(64)]]) {
        const client = new ApostilleClient({ baseURL, issuer, trustedKeyIDs, accessToken: "token", fetch: async () => json(response, 201) });
        await assert.rejects(client.createERC8004Binding(agentID, request, submitted), (error) => error.code === "invalid_binding_response");
    }
});

test("ERC-8004 client permits an expired request to reach the server's identical-retry lookup", async (t) => {
    const admin = await signer(), agent = await signer(), bindingSigner = await signer();
    const registration = await core.createRegistration(admin, agent, issuer);
    const request = await core.createERC8004Request(admin, registration, {
        chain_id: "8453", registry_address: "0x1111111111111111111111111111111111111111",
        erc8004_agent_id: "9", owner_address: "0x2222222222222222222222222222222222222222",
    }, issuer);
    const ownerSignature = `0x${"9a".repeat(65)}`, agentID = (await core.verifyRegistration(registration)).agent_id;
    const document = await erc8004Document(bindingSigner, registration, request, ownerSignature, new Date(Date.now() + 60000));
    const checked = await core.verifyERC8004Binding(document);
    const record = { id: crypto.randomUUID(), agent_id: agentID, document, created_at: checked.checked_at, expires_at: checked.expires_at };
    let calls = 0;
    t.mock.method(Date, "now", () => new Date(checked.checked_at).getTime() + 10 * 60000);
    const client = new ApostilleClient({ baseURL, issuer, accessToken: "token", fetch: async () => { calls++; return json(record); } });
    const replay = await client.createERC8004Binding(agentID, request, ownerSignature);
    assert.equal(replay.id, record.id);
    assert.equal(calls, 1, "the server decides whether the expired request is an identical replay");
});
