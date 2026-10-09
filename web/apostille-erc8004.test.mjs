import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
    PROTOCOL,
    PROTOCOL_03,
    b64,
    canonical,
    createRegistration,
    envelopeDigest,
    generateKeyFile,
    hash,
    importKeyFile,
    unb64,
} from "./apostille-core.mjs";
import {
    ERC8004_PROTOCOL,
    ERC8004_PROTOCOL_03,
    KNOWN_ERC8004_PROFILES,
    createERC8004Request,
    erc8004OwnerMessage,
    verifyERC8004Binding,
} from "./apostille-erc8004.mjs";
import { signMLDSA } from "./apostille-mldsa.mjs";

const encoder = new TextEncoder();
const issuer = "https://issuer.example/apostille";
const now = new Date(Date.now() + 2000);
now.setMilliseconds(0);
const iso = (offset) => new Date(now.getTime() + offset).toISOString().replace(/\.\d{3}Z$/, "Z");
const identity = {
    chain_id: "8453",
    registry_address: "0x1111111111111111111111111111111111111111",
    erc8004_agent_id: "42",
    owner_address: "0x2222222222222222222222222222222222222222",
};
// The two binding profiles every shared test runs under.
const PROFILES = [
    { name: "0.1", protocol: ERC8004_PROTOCOL, core: PROTOCOL, algorithm: "Ed25519", domain: "0.1" },
    { name: "0.3", protocol: ERC8004_PROTOCOL_03, core: PROTOCOL_03, algorithm: "ML-DSA-65", domain: "0.3" },
];
const signer = async (profile) => importKeyFile(await generateKeyFile({ algorithm: profile.algorithm }));

// Signs raw bytes of kind ("request" | "snapshot") under the binding profile named by `domain`.
async function rawSign(key, domain, label, raw) {
    const prefix = encoder.encode(`iff-apostille/erc8004-binding/${label}/${domain}\n`);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
    const input = new Uint8Array(prefix.length + digest.length);
    input.set(prefix); input.set(digest, prefix.length);
    return key.algorithm === "ML-DSA-65" ? signMLDSA(key.key, input) : new Uint8Array(await crypto.subtle.sign("Ed25519", key.key, input));
}

async function envelope(profile, kind, label, key, payload, { domain = profile.domain, protocol = profile.protocol } = {}) {
    const raw = encoder.encode(canonical(payload));
    return {
        protocol,
        kind,
        payload: b64(raw),
        payload_sha256: await hash(raw),
        signature: { algorithm: key.algorithm ?? "Ed25519", key_id: key.keyID, public_key: key.publicKey, value: b64(await rawSign(key, domain, label, raw)) },
    };
}

async function snapshot(profile, bindingSigner, registration, request, overrides = {}, options = {}) {
    const payload = {
        protocol: profile.protocol,
        kind: "erc8004-binding",
        issuer,
        issuer_key_id: bindingSigner.keyID,
        issued_at: iso(60000),
        request,
        owner_signature: `0x${"11".repeat(65)}`,
        block_number: "12345678",
        block_hash: `0x${"ab".repeat(32)}`,
        block_timestamp: iso(30000),
        expires_at: iso(3660000),
        check: "owner_of_eoa",
        ...overrides,
    };
    return { protocol: profile.protocol, binding: await envelope(profile, "erc8004-binding", "snapshot", bindingSigner, payload, options), ...registration };
}

async function fixture(profile) {
    const admin = await signer(profile), agent = await signer(profile), bindingSigner = await signer(profile);
    const registration = await createRegistration(admin, agent, issuer, 30);
    assert.equal(registration.delegation.protocol, profile.core);
    const request = await createERC8004Request(admin, registration, identity, issuer, now);
    return { admin, agent, bindingSigner, registration, request, document: await snapshot(profile, bindingSigner, registration, request) };
}

test("binding profile identifiers", () => {
    assert.equal(ERC8004_PROTOCOL, "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.1");
    assert.equal(ERC8004_PROTOCOL_03, "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.3");
    assert.deepEqual(KNOWN_ERC8004_PROFILES, [ERC8004_PROTOCOL, ERC8004_PROTOCOL_03]);
});

for (const profile of PROFILES) {
    test(`${profile.name}: request signs the exact private identity tuple and reconstructs owner consent`, async () => {
        const { admin, request } = await fixture(profile);
        const message = await erc8004OwnerMessage(request);
        assert.equal(request.protocol, profile.protocol);
        assert.equal(request.signature.algorithm, profile.algorithm);
        assert.match(message, new RegExp(`^iff-apostille/erc8004-binding/owner/${profile.domain.replace(".", "\\.")}\\nissuer:${issuer}`));
        assert.match(message, new RegExp(`\\nadmin_key_id:${admin.keyID}\\n`));
        assert.match(message, new RegExp(`\\nchain_id:${identity.chain_id}\\nregistry_address:${identity.registry_address}`));
        assert.match(message, new RegExp(`\\nrequest_sha256:${await envelopeDigest(request)}$`));
        assert.equal(message.endsWith("\n"), false);
    });

    test(`${profile.name}: offline verification reports only the profile's bounded dimensions`, async () => {
        const { bindingSigner, document } = await fixture(profile);
        const checked = await verifyERC8004Binding(document, { issuer, trustedKeyIDs: [bindingSigner.keyID], now: new Date(now.getTime() + 1800000) });
        assert.deepEqual(Object.keys(checked).sort(), [
            "artifact_integrity", "checked_at", "current_ownership", "expires_at", "freshness", "issuer", "issuer_key_id",
            "issuer_trust", "organization_binding", "payment_authority", "protocol", "provider_evidence", "request",
        ]);
        assert.equal(checked.protocol, profile.protocol);
        assert.equal(checked.artifact_integrity, "valid");
        assert.equal(checked.issuer_trust, "pinned");
        assert.equal(checked.provider_evidence, "issuer_checked");
        assert.equal(checked.current_ownership, "unknown");
        assert.equal(checked.organization_binding, "unproven");
        assert.equal(checked.payment_authority, "not_established");
        assert.equal(checked.freshness, "within_validity");
        assert.deepEqual({
            chain_id: checked.request.chain_id,
            registry_address: checked.request.registry_address,
            erc8004_agent_id: checked.request.erc8004_agent_id,
            owner_address: checked.request.owner_address,
        }, identity);
        assert.equal((await verifyERC8004Binding(document, { issuer, trustedKeyIDs: ["sha256:" + "0".repeat(64)] })).issuer_trust, "unknown");
        assert.equal((await verifyERC8004Binding(document, { now: new Date(now.getTime() + 3660000) })).freshness, "expired");
        assert.equal((await verifyERC8004Binding(document, { now: new Date(now.getTime() - 60000) })).freshness, "not_yet_valid");
        assert.equal((await verifyERC8004Binding(document)).freshness, "not_checked");
    });

    test(`${profile.name}: verification rejects altered tuples, envelopes, registration, issuer and time claims`, async () => {
        const { bindingSigner, registration, request, document } = await fixture(profile);
        await assert.rejects(verifyERC8004Binding(document, { issuer: "https://other.example/apostille" }), /issuer mismatch/);
        const changedRegistration = await createRegistration(await signer(profile), await signer(profile), issuer, 30);
        await assert.rejects(verifyERC8004Binding({ ...document, ...changedRegistration }), /registration|digest|administrator|proof/i);
        const badHash = await snapshot(profile, bindingSigner, registration, request, { block_hash: `0x${"0".repeat(64)}` });
        await assert.rejects(verifyERC8004Binding(badHash), /block hash/i);
        const stale = await snapshot(profile, bindingSigner, registration, request, { block_timestamp: iso(-3541000) });
        await assert.rejects(verifyERC8004Binding(stale), /observation time/i);
        const altered = structuredClone(document);
        altered.binding.payload_sha256 = "0".repeat(64);
        await assert.rejects(verifyERC8004Binding(altered), /digest mismatch/i);
    });

    test(`${profile.name}: identity quantities and addresses use strict uint256 and lowercase nonzero syntax`, async () => {
        const admin = await signer(profile), agent = await signer(profile), registration = await createRegistration(admin, agent, issuer, 30);
        for (const [field, value] of [
            ["chain_id", "0"],
            ["chain_id", "01"],
            ["chain_id", (1n << 256n).toString()],
            ["erc8004_agent_id", "01"],
            ["erc8004_agent_id", (1n << 256n).toString()],
            ["registry_address", "0x" + "0".repeat(40)],
            ["owner_address", "0x" + "AA".repeat(20)],
        ]) {
            await assert.rejects(createERC8004Request(admin, registration, { ...identity, [field]: value }, issuer, now), /Invalid|uint256|address/);
        }
        const maximum = (1n << 256n) - 1n;
        const valid = await createERC8004Request(admin, registration, { ...identity, erc8004_agent_id: maximum.toString() }, issuer, now);
        assert.match(await erc8004OwnerMessage(valid), new RegExp(`erc8004_agent_id:${maximum}`));
    });

    test(`${profile.name}: cross-domain, BOM and tampered signatures are rejected`, async () => {
        const { admin, bindingSigner, registration, request, document } = await fixture(profile);
        const payload = unb64(document.binding.payload);
        for (const modified of [new Uint8Array([0xef, 0xbb, 0xbf, ...payload]), new Uint8Array([0x20, ...payload])]) {
            const changed = structuredClone(document);
            changed.binding.payload = b64(modified);
            changed.binding.payload_sha256 = await hash(modified);
            changed.binding.signature.value = b64(await rawSign(bindingSigner, profile.domain, "snapshot", modified));
            await assert.rejects(verifyERC8004Binding(changed));
        }
        // Request and snapshot domains are not interchangeable.
        const swapped = structuredClone(document);
        swapped.binding.signature.value = b64(await rawSign(bindingSigner, profile.domain, "request", payload));
        await assert.rejects(verifyERC8004Binding(swapped), /signature/i);
        const swappedRequest = structuredClone(request);
        swappedRequest.signature.value = b64(await rawSign(admin, profile.domain, "snapshot", unb64(request.payload)));
        await assert.rejects(erc8004OwnerMessage(swappedRequest), /signature/i);
        // A snapshot over a request signed in a wrong request domain is rejected.
        const badRequest = await envelope(profile, "erc8004-binding-request", "request", admin, JSON.parse(new TextDecoder().decode(unb64(request.payload))), { domain: profile.domain === "0.1" ? "0.3" : "0.1" });
        await assert.rejects(verifyERC8004Binding(await snapshot(profile, bindingSigner, registration, badRequest)), /signature/i);
    });
}

test("a request takes the profile of the registration's Core version and refuses a signer of another algorithm", async () => {
    const [edProfile, mlProfile] = PROFILES;
    const mlAdmin = await signer(mlProfile), mlAgent = await signer(mlProfile), edAdmin = await signer(edProfile), edAgent = await signer(edProfile);
    const mlRegistration = await createRegistration(mlAdmin, mlAgent, issuer, 30), edRegistration = await createRegistration(edAdmin, edAgent, issuer, 30);
    await assert.rejects(createERC8004Request(edAdmin, mlRegistration, identity, issuer, now), /Invalid administrator signer/);
    await assert.rejects(createERC8004Request(mlAdmin, edRegistration, identity, issuer, now), /Invalid administrator signer/);
    const registration02 = await createRegistration(edAdmin, edAgent, issuer, 30, "https://ifandonlyif.io/apostille/spec/0.2");
    await assert.rejects(createERC8004Request(edAdmin, registration02, identity, issuer, now), /No ERC-8004 binding profile/);
});

test("0.3: a 0.3 document never mixes with 0.1 material, in either direction", async () => {
    const [edProfile, mlProfile] = PROFILES;
    const ed = await fixture(edProfile), ml = await fixture(mlProfile);
    await verifyERC8004Binding(ed.document);
    await verifyERC8004Binding(ml.document);
    // 0.1 request inside a 0.3 snapshot, and the reverse.
    await assert.rejects(verifyERC8004Binding(await snapshot(mlProfile, ml.bindingSigner, ml.registration, ed.request)), /Core version|another binding profile|registration/i);
    await assert.rejects(verifyERC8004Binding(await snapshot(edProfile, ed.bindingSigner, ed.registration, ml.request)), /Core version|another binding profile|registration/i);
    // A Core 0.1 registration under a 0.3 request, and the reverse.
    await assert.rejects(verifyERC8004Binding({ ...ml.document, ...ed.registration }), /Core version|registration/i);
    await assert.rejects(verifyERC8004Binding({ ...ed.document, ...ml.registration }), /Core version|registration/i);
    await assert.rejects(verifyERC8004Binding({ ...ml.document, acceptance: ed.registration.acceptance }), /protocol|Core version/i);
    // Document and snapshot profiles must agree.
    await assert.rejects(verifyERC8004Binding({ ...ml.document, protocol: ERC8004_PROTOCOL }), /another profile|Unsupported/i);
    await assert.rejects(verifyERC8004Binding({ ...ml.document, binding: ed.document.binding }), /another profile/i);
    await assert.rejects(verifyERC8004Binding({ ...ed.document, protocol: ERC8004_PROTOCOL_03 }), /another profile/i);
    await assert.rejects(verifyERC8004Binding({ ...ml.document, protocol: "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.2" }), /Unsupported/);
});

test("0.3: an Ed25519 signature or key in a 0.3 document, wrong sizes and encodings are rejected", async () => {
    const [edProfile, mlProfile] = PROFILES;
    const ed = await fixture(edProfile), ml = await fixture(mlProfile);
    // The 0.1 snapshot relabelled as 0.3, algorithm and all.
    const relabelled = structuredClone(ed.document);
    relabelled.protocol = ERC8004_PROTOCOL_03; relabelled.binding.protocol = ERC8004_PROTOCOL_03;
    await assert.rejects(verifyERC8004Binding(relabelled));
    // An Ed25519 key signing under the 0.3 label and domain.
    const payload = JSON.parse(new TextDecoder().decode(unb64(ml.document.binding.payload)));
    payload.issuer_key_id = ed.bindingSigner.keyID;
    for (const algorithm of ["Ed25519", "ML-DSA-65"]) {
        const forged = await envelope(mlProfile, "erc8004-binding", "snapshot", ed.bindingSigner, payload);
        forged.signature.algorithm = algorithm;
        await assert.rejects(verifyERC8004Binding({ ...ml.document, binding: forged }));
    }
    const key = ml.request.signature.public_key, sig = ml.request.signature.value;
    assert.equal(key.length, 2603); assert.equal(sig.length, 4412);
    for (const change of [
        (e) => { e.signature.value = sig.slice(0, -4); },
        (e) => { e.signature.value = `${sig}AAAA`; },
        (e) => { e.signature.value = `${sig}=`; },
        (e) => { e.signature.public_key = key.slice(0, -4); },
        (e) => { e.signature.public_key = `${key}AAAA`; },
        (e) => { e.signature.public_key = ed.admin.publicKey; e.signature.key_id = ed.admin.keyID; },
        (e) => { e.signature.key_id = ml.bindingSigner.keyID; },
        (e) => { e.signature.algorithm = "ml-dsa-65"; },
        (e) => { e.signature.value = (sig[0] === "A" ? "B" : "A") + sig.slice(1); },
    ]) {
        const e = structuredClone(ml.request);
        change(e);
        await assert.rejects(erc8004OwnerMessage(e));
    }
    // A payload protocol differing from its envelope.
    const inner = JSON.parse(new TextDecoder().decode(unb64(ml.request.payload)));
    inner.protocol = ERC8004_PROTOCOL;
    await assert.rejects(erc8004OwnerMessage(await envelope(mlProfile, "erc8004-binding-request", "request", ml.admin, inner)));
});

test("0.3: the owner consent text differs from 0.1 only in its first line", async () => {
    const [edProfile, mlProfile] = PROFILES;
    const { request } = await fixture(mlProfile);
    const lines = (await erc8004OwnerMessage(request)).split("\n");
    assert.equal(lines[0], "iff-apostille/erc8004-binding/owner/0.3");
    assert.equal(lines.length, 15);
    assert.equal((await erc8004OwnerMessage((await fixture(edProfile)).request)).split("\n")[0], "iff-apostille/erc8004-binding/owner/0.1");
});

test("0.3: the Go known-answer document verifies, with the pinned issuer", async () => {
    const vector = JSON.parse(await readFile(new URL("../testdata/apostille/erc8004-binding-0.3.json", import.meta.url), "utf8"));
    assert.equal(vector.profile, ERC8004_PROTOCOL_03);
    assert.equal(vector.document.protocol, ERC8004_PROTOCOL_03);
    const checked = await verifyERC8004Binding(vector.document, { issuer: vector.issuer, trustedKeyIDs: [vector.issuer_key_id], now: vector.evaluation_time });
    assert.equal(checked.protocol, ERC8004_PROTOCOL_03);
    assert.equal(checked.issuer_trust, "pinned");
    assert.equal(checked.freshness, "within_validity");
    assert.equal(checked.request.owner_address, vector.owner_address);
    const bindingPayload = JSON.parse(new TextDecoder().decode(unb64(vector.document.binding.payload)));
    assert.equal(await erc8004OwnerMessage(bindingPayload.request), vector.owner_message);
    // Altering any identity field of the Go document breaks it.
    const altered = structuredClone(vector.document);
    altered.binding.payload_sha256 = "0".repeat(64);
    await assert.rejects(verifyERC8004Binding(altered), /digest mismatch/i);
    // The vector is Core 0.3 throughout: an issuer pin of another key is not "pinned".
    assert.equal((await verifyERC8004Binding(vector.document, { issuer: vector.issuer, trustedKeyIDs: [vector.document.delegation.signature.key_id] })).issuer_trust, "unknown");
});
