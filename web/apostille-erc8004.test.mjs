import test from "node:test";
import assert from "node:assert/strict";
import {
    b64,
    canonical,
    createRegistration,
    envelopeDigest,
    generateKeyFile,
    hash,
    importKeyFile,
} from "./apostille-core.mjs";
import {
    ERC8004_PROTOCOL,
    createERC8004Request,
    erc8004OwnerMessage,
    verifyERC8004Binding,
} from "./apostille-erc8004.mjs";

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
const signer = async () => importKeyFile(await generateKeyFile());

async function snapshot(bindingSigner, registration, request, overrides = {}) {
    const payload = {
        protocol: ERC8004_PROTOCOL,
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
    const raw = encoder.encode(canonical(payload));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
    const domain = encoder.encode("iff-apostille/erc8004-binding/snapshot/0.1\n");
    const input = new Uint8Array(domain.length + digest.length);
    input.set(domain); input.set(digest, domain.length);
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", bindingSigner.key, input));
    const binding = {
        protocol: ERC8004_PROTOCOL,
        kind: "erc8004-binding",
        payload: b64(raw),
        payload_sha256: await hash(raw),
        signature: { algorithm: "Ed25519", key_id: bindingSigner.keyID, public_key: bindingSigner.publicKey, value: b64(signature) },
    };
    return { protocol: ERC8004_PROTOCOL, binding, ...registration };
}

async function fixture() {
    const admin = await signer(), agent = await signer(), bindingSigner = await signer();
    const registration = await createRegistration(admin, agent, issuer, 30);
    const request = await createERC8004Request(admin, registration, identity, issuer, now);
    return { admin, agent, bindingSigner, registration, request, document: await snapshot(bindingSigner, registration, request) };
}

test("request signs the exact private identity tuple and reconstructs owner consent", async () => {
    const { admin, request } = await fixture();
    const message = await erc8004OwnerMessage(request);
    assert.equal(request.protocol, ERC8004_PROTOCOL);
    assert.match(message, new RegExp(`^iff-apostille/erc8004-binding/owner/0\\.1\\nissuer:${issuer}`));
    assert.match(message, new RegExp(`\\nadmin_key_id:${admin.keyID}\\n`));
    assert.match(message, new RegExp(`\\nchain_id:${identity.chain_id}\\nregistry_address:${identity.registry_address}`));
    assert.match(message, new RegExp(`\\nrequest_sha256:${await envelopeDigest(request)}$`));
    assert.equal(message.endsWith("\n"), false);
});

test("offline verification reports only the profile's bounded dimensions", async () => {
    const { bindingSigner, document } = await fixture();
    const checked = await verifyERC8004Binding(document, { issuer, trustedKeyIDs: [bindingSigner.keyID], now: new Date(now.getTime() + 1800000) });
    assert.deepEqual(Object.keys(checked).sort(), [
        "artifact_integrity", "checked_at", "current_ownership", "expires_at", "freshness", "issuer", "issuer_key_id",
        "issuer_trust", "organization_binding", "payment_authority", "protocol", "provider_evidence", "request",
    ]);
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

test("verification rejects altered tuples, envelopes, registration, issuer and time claims", async () => {
    const { bindingSigner, registration, request, document } = await fixture();
    await assert.rejects(verifyERC8004Binding(document, { issuer: "https://other.example/apostille" }), /issuer mismatch/);
    const changedRegistration = await createRegistration(await signer(), await signer(), issuer, 30);
    await assert.rejects(verifyERC8004Binding({ ...document, ...changedRegistration }), /registration|digest|administrator|proof/i);
    const badHash = await snapshot(bindingSigner, registration, request, { block_hash: `0x${"0".repeat(64)}` });
    await assert.rejects(verifyERC8004Binding(badHash), /block hash/i);
    const stale = await snapshot(bindingSigner, registration, request, { block_timestamp: iso(-3541000) });
    await assert.rejects(verifyERC8004Binding(stale), /observation time/i);
    const altered = structuredClone(document);
    altered.binding.payload_sha256 = "0".repeat(64);
    await assert.rejects(verifyERC8004Binding(altered), /digest mismatch/i);
});

test("identity quantities and addresses use strict uint256 and lowercase nonzero syntax", async () => {
    const admin = await signer(), agent = await signer(), registration = await createRegistration(admin, agent, issuer, 30);
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
