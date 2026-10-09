import {
    MAX_INPUT_BYTES,
    b64,
    canonical,
    decodeBytes,
    envelopeDigest,
    fingerprint,
    hash,
    keyIdentity,
    parseStrict,
    timestamp,
    unb64,
    verifyRegistration,
} from "./apostille-core.mjs";
import { ALGORITHM_03, PROTOCOL, PROTOCOL_03, profileFor } from "./apostille-profile.mjs";
import { signMLDSA } from "./apostille-mldsa.mjs";

// Binding profiles. A binding profile differs from another only in this table,
// mirroring apostille/erc8004.go: its identifier, the domain closing its
// signature inputs and owner text, and the Core profile whose signatures, sizes,
// verifier and identifier grammar it uses and whose registrations it binds.
export const ERC8004_PROTOCOL = "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.1";
export const ERC8004_PROTOCOL_03 = "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.3";
const BINDING_PROFILES = Object.freeze([
    Object.freeze({ protocol: ERC8004_PROTOCOL, domain: "0.1", core: profileFor(PROTOCOL) }),
    Object.freeze({ protocol: ERC8004_PROTOCOL_03, domain: "0.3", core: profileFor(PROTOCOL_03) }),
]);
// Every binding profile identifier this implementation verifies and signs, oldest first.
export const KNOWN_ERC8004_PROFILES = Object.freeze(BINDING_PROFILES.map((p) => p.protocol));
const bindingProfileFor = (protocol) => typeof protocol === "string" ? BINDING_PROFILES.find((p) => p.protocol === protocol) : undefined;
// The binding profile of a registration's Core protocol; there is none for Core 0.2.
const bindingProfileForCore = (protocol) => BINDING_PROFILES.find((p) => p.core.protocol === protocol);
const REQUEST_KIND = "erc8004-binding-request";
const BINDING_KIND = "erc8004-binding";
const encoder = new TextEncoder();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/;
const OWNER_SIGNATURE = /^0x[0-9a-f]{130}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const QUANTITY = /^(0|[1-9][0-9]{0,77})$/;
const POSITIVE_QUANTITY = /^[1-9][0-9]{0,77}$/;
const UINT256_MAX = (1n << 256n) - 1n;
const HEADER = ["protocol", "kind", "issuer", "issuer_key_id", "issued_at"];
const REQUEST_FIELDS = ["agent_id", "agent_key_id", "delegation_sha256", "service_audience", "chain_id", "registry_address", "erc8004_agent_id", "owner_address", "nonce", "expires_at", "purpose"];
const BINDING_FIELDS = ["request", "owner_signature", "block_number", "block_hash", "block_timestamp", "expires_at", "check"];

function need(condition, message) { if (!condition) throw new Error(message); }
function exact(value, keys, message = "Missing or unsupported field.") {
    need(value && typeof value === "object" && !Array.isArray(value), message);
    need(Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)), message);
}
function milliseconds(value) {
    need(typeof value === "string" && TIME.test(value) && Number.isFinite(Date.parse(value)) && timestamp(new Date(value)) === value, "Expected a UTC timestamp in seconds.");
    return Date.parse(value);
}
function quantity(value, positive = false) {
    need(typeof value === "string" && (positive ? POSITIVE_QUANTITY : QUANTITY).test(value), "Invalid uint256 quantity.");
    const parsed = BigInt(value);
    need(parsed <= UINT256_MAX, "Invalid uint256 quantity.");
    return value;
}
function address(value) {
    need(typeof value === "string" && ADDRESS.test(value) && value !== "0x0000000000000000000000000000000000000000", "Invalid EVM address.");
    return value;
}
function instant(value) {
    const date = value === Date ? new Date() : new Date(value);
    need(Number.isFinite(date.getTime()), "Invalid evaluation time.");
    return new Date(milliseconds(timestamp(date)));
}
async function signatureInput(prof, kind, raw) {
    const label = kind === REQUEST_KIND ? "request" : "snapshot";
    const domain = encoder.encode(`iff-apostille/erc8004-binding/${label}/${prof.domain}\n`);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
    const input = new Uint8Array(domain.length + digest.length);
    input.set(domain); input.set(digest, domain.length);
    return input;
}
function validateIdentity(identity) {
    exact(identity, ["chain_id", "registry_address", "erc8004_agent_id", "owner_address"], "Invalid ERC-8004 identity.");
    validateIdentityFields(identity);
    return identity;
}
function validateIdentityFields(identity) {
    quantity(identity.chain_id, true);
    quantity(identity.erc8004_agent_id);
    address(identity.registry_address);
    address(identity.owner_address);
}
function validateRequestPayload(prof, payload) {
    exact(payload, [...HEADER, ...REQUEST_FIELDS]);
    need(payload.protocol === prof.protocol && payload.kind === REQUEST_KIND, "Invalid ERC-8004 request header.");
    need(KEY_ID.test(payload.issuer_key_id) && payload.issuer === keyIdentity(payload.issuer_key_id), "Invalid ERC-8004 request issuer.");
    need(UUID.test(payload.agent_id) && KEY_ID.test(payload.agent_key_id) && DIGEST.test(payload.delegation_sha256), "Invalid ERC-8004 agent binding.");
    need(prof.core.validIssuer(payload.service_audience), "Invalid ERC-8004 service audience.");
    validateIdentityFields(payload);
    need(UUID.test(payload.nonce) && payload.purpose === "link_identity_private", "Invalid ERC-8004 request consent.");
    const issued = milliseconds(payload.issued_at), expires = milliseconds(payload.expires_at);
    need(expires > issued && expires - issued <= 300000, "Invalid ERC-8004 request validity.");
    return payload;
}
function validateBindingPayload(prof, payload) {
    exact(payload, [...HEADER, ...BINDING_FIELDS]);
    need(payload.protocol === prof.protocol && payload.kind === BINDING_KIND && prof.core.validIssuer(payload.issuer) && KEY_ID.test(payload.issuer_key_id), "Invalid ERC-8004 snapshot header.");
    need(OWNER_SIGNATURE.test(payload.owner_signature), "Invalid ERC-8004 owner signature.");
    quantity(payload.block_number);
    need(typeof payload.block_hash === "string" && BLOCK_HASH.test(payload.block_hash) && payload.block_hash !== `0x${"0".repeat(64)}`, "Invalid ERC-8004 block hash.");
    need(payload.check === "owner_of_eoa", "Unsupported ERC-8004 ownership check.");
    const issued = milliseconds(payload.issued_at), expires = milliseconds(payload.expires_at), block = milliseconds(payload.block_timestamp);
    need(expires > issued && expires - issued <= 3600000, "Invalid ERC-8004 snapshot validity.");
    need(block <= issued + 120000 && issued - block <= 3600000, "Invalid ERC-8004 block observation time.");
    return payload;
}
// Verifies one envelope under the binding profile its protocol names; returns that profile and the payload.
async function verifyProfileEnvelope(envelope, kind) {
    exact(envelope, ["protocol", "kind", "payload", "payload_sha256", "signature"]);
    exact(envelope.signature, ["algorithm", "key_id", "public_key", "value"]);
    const prof = bindingProfileFor(envelope.protocol), core = prof?.core;
    need(prof && envelope.kind === kind && envelope.signature.algorithm === core.algorithm, "Unsupported ERC-8004 envelope.");
    need(typeof envelope.payload === "string" && envelope.payload.length <= MAX_INPUT_BYTES && typeof envelope.signature.public_key === "string" && envelope.signature.public_key.length <= core.publicKeyFieldLimit && typeof envelope.signature.value === "string" && envelope.signature.value.length <= core.signatureFieldLimit, "ERC-8004 envelope exceeds size limit.");
    const raw = unb64(envelope.payload);
    need(raw.length > 0 && raw.length <= MAX_INPUT_BYTES, "Invalid ERC-8004 payload size.");
    const payload = parseStrict(decodeBytes(raw)), expected = encoder.encode(canonical(payload));
    need(expected.length === raw.length && expected.every((byte, index) => byte === raw[index]), "ERC-8004 payload is not canonical.");
    need(await hash(raw) === envelope.payload_sha256, "ERC-8004 payload digest mismatch.");
    need(envelope.signature.public_key.length === core.encodedPublicKeyLength && envelope.signature.value.length === core.encodedSignatureLength, "Invalid ERC-8004 signing key.");
    const publicKey = unb64(envelope.signature.public_key), signature = unb64(envelope.signature.value);
    need(publicKey.length === core.publicKeySize && signature.length === core.signatureSize && await fingerprint(envelope.signature.public_key, core.protocol) === envelope.signature.key_id, "Invalid ERC-8004 signing key.");
    core.checkKey(publicKey);
    await core.verify(publicKey, await signatureInput(prof, kind, raw), signature).catch(() => { throw new Error("Invalid ERC-8004 signature."); });
    need(payload.issuer_key_id === envelope.signature.key_id, "ERC-8004 signed key ID mismatch.");
    return { prof, payload: kind === REQUEST_KIND ? validateRequestPayload(prof, payload) : validateBindingPayload(prof, payload) };
}
async function signRequest(prof, payload, signer) {
    validateRequestPayload(prof, payload);
    need(payload.issuer_key_id === signer.keyID, "Signed key ID does not match administrator.");
    const raw = encoder.encode(canonical(payload)), input = await signatureInput(prof, REQUEST_KIND, raw);
    const value = signer.algorithm === ALGORITHM_03 ? signMLDSA(signer.key, input) : new Uint8Array(await crypto.subtle.sign("Ed25519", signer.key, input));
    // As core-0.2.md recommends, check the signer's own key and signature before releasing them.
    const publicKey = unb64(signer.publicKey); prof.core.checkKey(publicKey); await prof.core.verify(publicKey, input, value);
    return {
        protocol: prof.protocol,
        kind: REQUEST_KIND,
        payload: b64(raw),
        payload_sha256: await hash(raw),
        signature: { algorithm: prof.core.algorithm, key_id: signer.keyID, public_key: signer.publicKey, value: b64(value) },
    };
}
// A registration of another Core version than the profile's is refused before any signature is checked.
function checkRegistration(prof, registration) {
    need(registration?.delegation?.protocol === prof.core.protocol && registration?.acceptance?.protocol === prof.core.protocol, "Registration Core version does not match the ERC-8004 binding profile.");
}

// The binding profile is that of the registration's Core version (Core 0.1 selects binding 0.1,
// Core 0.3 selects 0.3); the administrator's key must be of its algorithm.
export async function createERC8004Request(admin, registration, identity, audience, now = Date) {
    const prof = bindingProfileForCore(registration?.delegation?.protocol);
    need(prof, "No ERC-8004 binding profile for this registration's Core version.");
    need(admin && KEY_ID.test(admin.keyID) && typeof admin.publicKey === "string" && admin.key && (admin.algorithm ?? "Ed25519") === prof.core.algorithm, "Invalid administrator signer.");
    need(prof.core.validIssuer(audience), "Invalid ERC-8004 service audience.");
    checkRegistration(prof, registration);
    const at = instant(now);
    const delegation = await verifyRegistration(registration, audience, at);
    need(delegation.issuer_key_id === admin.keyID, "Administrator does not own registration.");
    validateIdentity(identity);
    return signRequest(prof, {
        protocol: prof.protocol,
        kind: REQUEST_KIND,
        issuer: keyIdentity(admin.keyID),
        issuer_key_id: admin.keyID,
        issued_at: timestamp(at),
        agent_id: delegation.agent_id,
        agent_key_id: delegation.agent_key_id,
        delegation_sha256: await envelopeDigest(registration.delegation),
        service_audience: audience,
        chain_id: identity.chain_id,
        registry_address: identity.registry_address,
        erc8004_agent_id: identity.erc8004_agent_id,
        owner_address: identity.owner_address,
        nonce: crypto.randomUUID(),
        expires_at: timestamp(new Date(at.getTime() + 300000)),
        purpose: "link_identity_private",
    }, admin);
}

export async function erc8004OwnerMessage(request) {
    const { prof, payload } = await verifyProfileEnvelope(request, REQUEST_KIND);
    return [
        `iff-apostille/erc8004-binding/owner/${prof.domain}`,
        `issuer:${payload.service_audience}`,
        `admin_key_id:${payload.issuer_key_id}`,
        `agent_id:${payload.agent_id}`,
        `agent_key_id:${payload.agent_key_id}`,
        `delegation_sha256:${payload.delegation_sha256}`,
        `chain_id:${payload.chain_id}`,
        `registry_address:${payload.registry_address}`,
        `erc8004_agent_id:${payload.erc8004_agent_id}`,
        `owner_address:${payload.owner_address}`,
        `nonce:${payload.nonce}`,
        `issued_at:${payload.issued_at}`,
        `expires_at:${payload.expires_at}`,
        "purpose:link_identity_private",
        `request_sha256:${await envelopeDigest(request)}`,
    ].join("\n");
}

export async function verifyERC8004Binding(document, { issuer = "", trustedKeyIDs = [], now = null } = {}) {
    const input = typeof document === "string" ? parseStrict(document) : document;
    exact(input, ["protocol", "binding", "delegation", "acceptance"], "Invalid ERC-8004 binding document.");
    const prof = bindingProfileFor(input.protocol);
    need(prof, "Unsupported ERC-8004 binding document.");
    need(typeof issuer === "string" && (!issuer || prof.core.validIssuer(issuer)), "Invalid expected issuer.");
    need(Array.isArray(trustedKeyIDs) && trustedKeyIDs.every((key) => typeof key === "string" && KEY_ID.test(key)), "Invalid trusted key IDs.");
    // The snapshot, the request inside it, the delegation and the acceptance belong to this one profile.
    const { prof: bindingProf, payload: binding } = await verifyProfileEnvelope(input.binding, BINDING_KIND);
    need(bindingProf === prof, "ERC-8004 binding envelope belongs to another profile.");
    const { prof: requestProf, payload: request } = await verifyProfileEnvelope(binding.request, REQUEST_KIND);
    need(requestProf === prof, "ERC-8004 request belongs to another binding profile.");
    checkRegistration(prof, input);
    need(binding.issuer === request.service_audience, "ERC-8004 service audience mismatch.");
    if (issuer) need(binding.issuer === issuer, "ERC-8004 issuer mismatch.");
    const atSnapshot = new Date(milliseconds(binding.issued_at));
    const delegation = await verifyRegistration({ delegation: input.delegation, acceptance: input.acceptance }, binding.issuer, atSnapshot);
    need(request.agent_id === delegation.agent_id && request.agent_key_id === delegation.agent_key_id, "ERC-8004 agent registration mismatch.");
    need(request.delegation_sha256 === await envelopeDigest(input.delegation), "ERC-8004 delegation digest mismatch.");
    need(request.issuer_key_id === input.delegation.signature.key_id && request.issuer === keyIdentity(request.issuer_key_id), "ERC-8004 administrator mismatch.");
    const requestIssued = milliseconds(request.issued_at), requestExpires = milliseconds(request.expires_at), snapshotIssued = milliseconds(binding.issued_at);
    need(requestIssued <= snapshotIssued + 120000 && requestExpires > snapshotIssued, "ERC-8004 request was not active at snapshot issuance.");
    need(milliseconds(binding.expires_at) <= milliseconds(delegation.expires_at), "ERC-8004 snapshot exceeds delegation validity.");
    let freshness = "not_checked";
    if (now !== null && now !== undefined) {
        const evaluated = instant(now).getTime();
        freshness = evaluated < snapshotIssued ? "not_yet_valid" : evaluated >= milliseconds(binding.expires_at) ? "expired" : "within_validity";
    }
    return {
        protocol: prof.protocol,
        artifact_integrity: "valid",
        issuer_trust: issuer && trustedKeyIDs.includes(binding.issuer_key_id) ? "pinned" : "unknown",
        freshness,
        provider_evidence: "issuer_checked",
        current_ownership: "unknown",
        organization_binding: "unproven",
        payment_authority: "not_established",
        issuer: binding.issuer,
        issuer_key_id: binding.issuer_key_id,
        checked_at: binding.issued_at,
        expires_at: binding.expires_at,
        request,
    };
}
