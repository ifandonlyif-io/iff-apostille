import { parseStrict, canonical } from "./apostille-json.mjs";
import { ALGORITHM, ALGORITHM_03, KNOWN_PROTOCOLS, PROTOCOL, PROTOCOL_02, PROTOCOL_03, acceptsProtocol, profileFor, validIssuer } from "./apostille-profile.mjs";
import { validIssuer02 } from "./apostille-identifier.mjs";
import { mldsaKeys, signMLDSA, verifyMLDSA } from "./apostille-mldsa.mjs";
export { parseStrict, canonical, ALGORITHM, ALGORITHM_03, KNOWN_PROTOCOLS, PROTOCOL, PROTOCOL_02, PROTOCOL_03, validIssuer, validIssuer02 };
export const MAX_INPUT_BYTES = 256 * 1024;
// A private key file is at most 4 KiB (a Core 0.3 file is about 2.9 KB).
export const MAX_KEY_FILE_BYTES = 4096;
export const LOGIN_PREFIX_03 = "iff-apostille/login/0.3\n";
const encoder = new TextEncoder();
// Preserve a leading BOM so strict JSON rejects it, as the Go verifier does.
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const hex = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("");
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const KEY = /^sha256:[0-9a-f]{64}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HEADER = ["protocol", "kind", "issuer", "issuer_key_id", "issued_at"];
const FIELDS = {
    "origin-statement": ["agent_id", "delegation_sha256", "artifact_sha256", "artifact_size", "artifact_media_type", "nonce"],
    "agent-delegation": ["agent_id", "agent_key_id", "agent_public_key", "service_audience", "not_before", "expires_at", "scopes"],
    "agent-acceptance": ["agent_id", "delegation_sha256"],
    "publication-grant": ["statement_sha256", "delegation_sha256", "service_audience", "visibility", "purpose", "expires_at", "nonce"],
    "origin-certificate": ["certificate_id", "statement_sha256", "delegation_sha256", "source_key_id", "expires_at", "signature_check", "agent_binding", "organization_binding", "content_truth"],
};
function need(condition, message) { if (!condition) throw new Error(message); }
function exact(value, keys) {
    need(value && typeof value === "object" && !Array.isArray(value), "Expected an object.");
    need(Object.keys(value).length === keys.length && keys.every((k) => Object.hasOwn(value, k)), "Missing or unsupported field.");
}
function textFields(value, except = []) {
    for (const [key, field] of Object.entries(value)) if (!except.includes(key)) need(typeof field === "string", `Expected text: ${key}`);
}
export function decodeBytes(bytes) { return decoder.decode(bytes); }
export function b64(bytes) {
    let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
export function unb64(value) {
    need(typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value), "Invalid base64url.");
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
    const bytes = Uint8Array.from(binary, (x) => x.charCodeAt(0));
    need(b64(bytes) === value, "Noncanonical base64url."); return bytes;
}
export async function hash(bytes) { return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))); }
// The raw key of a canonical field of exactly the profile's size; the encoded length is checked before decoding.
function decodeKey(value, prof) {
    need(typeof value === "string" && value.length === prof.encodedPublicKeyLength, `Invalid ${prof.algorithm} key.`);
    const raw = unb64(value); need(raw.length === prof.publicKeySize, `Invalid ${prof.algorithm} key.`); return raw;
}
// The key ID is sha256 over the raw key: 32 bytes for the 0.1 default, the protocol's size otherwise.
export async function fingerprint(publicKey, protocol = PROTOCOL) { const prof = profileFor(protocol); need(prof, "Unsupported protocol."); return `sha256:${await hash(decodeKey(publicKey, prof))}`; }
export function keyIdentity(keyID) { return `urn:apostille:key:${keyID}`; }
export function timestamp(now = new Date()) { return new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z"); }
function millis(value) {
    need(typeof value === "string" && TIME.test(value) && Number.isFinite(Date.parse(value)) && timestamp(new Date(value)) === value, "Expected a UTC timestamp in seconds.");
    return Date.parse(value);
}
function interval(a, b) { need(millis(b) > millis(a), "Invalid validity interval."); }
// The profile of a protocol the caller names; an unknown value is refused before any work.
function profileOf(protocol) { const prof = profileFor(protocol); need(prof, "Unsupported protocol."); return prof; }
// Signers made before key algorithms were tagged are Ed25519.
const algorithmOf = (signer) => signer?.algorithm ?? ALGORITHM;
const signerMismatch = "Signer does not support the protocol's signature algorithm.";
async function validatePayload(kind, p, prof) {
    need(Object.hasOwn(FIELDS, kind), "Unsupported artifact kind."); exact(p, [...HEADER, ...FIELDS[kind]]); textFields(p, ["scopes"]);
    need(p.protocol === prof.protocol && p.kind === kind && prof.validIssuer(p.issuer) && KEY.test(p.issuer_key_id), "Invalid protocol header."); millis(p.issued_at);
    if (kind === "origin-statement") {
        need(ID.test(p.agent_id) && DIGEST.test(p.artifact_sha256) && /^(0|[1-9][0-9]{0,18})$/.test(p.artifact_size) && ID.test(p.nonce), "Invalid origin statement.");
        need(encoder.encode(p.artifact_media_type).length <= 128 && p.artifact_media_type.includes("/") && !/[\r\n\0]/.test(p.artifact_media_type), "Invalid artifact media type.");
        need(p.delegation_sha256 === "" || DIGEST.test(p.delegation_sha256), "Invalid delegation digest.");
    } else if (kind === "agent-delegation") {
        need(ID.test(p.agent_id) && prof.validIssuer(p.service_audience) && p.issuer === keyIdentity(p.issuer_key_id) && Array.isArray(p.scopes) && p.scopes.length === 1 && p.scopes[0] === "sign_origin_statement", "Invalid delegation.");
        need(await fingerprint(p.agent_public_key, prof.protocol) === p.agent_key_id, "Delegated key fingerprint mismatch."); prof.checkKey(decodeKey(p.agent_public_key, prof)); interval(p.not_before, p.expires_at);
    } else if (kind === "agent-acceptance") {
        need(ID.test(p.agent_id) && DIGEST.test(p.delegation_sha256) && p.issuer === keyIdentity(p.issuer_key_id), "Invalid agent acceptance.");
    } else if (kind === "publication-grant") {
        need(DIGEST.test(p.statement_sha256) && DIGEST.test(p.delegation_sha256) && prof.validIssuer(p.service_audience) && ["private", "public"].includes(p.visibility) && p.purpose === "issue_origin_certificate" && ID.test(p.nonce) && p.issuer === keyIdentity(p.issuer_key_id), "Invalid publication grant.");
        interval(p.issued_at, p.expires_at);
    } else if (kind === "origin-certificate") {
        need(ID.test(p.certificate_id) && DIGEST.test(p.statement_sha256) && KEY.test(p.source_key_id) && p.signature_check === "valid" && p.organization_binding === "unproven" && p.content_truth === "not_established" && ["admin_key_delegation", "not_provided"].includes(p.agent_binding), "Unsupported certificate assertion.");
        need(p.delegation_sha256 === "" || DIGEST.test(p.delegation_sha256), "Invalid delegation digest.");
        need((p.agent_binding === "admin_key_delegation") === (p.delegation_sha256 !== ""), "Contradictory certificate binding."); interval(p.issued_at, p.expires_at);
    }
}
// UTF8("iff-apostille/" + kind + "/" + domain + "\n") || SHA256(payload)
async function signingInput(kind, payload, prof) {
    const domain = encoder.encode(`iff-apostille/${kind}/${prof.domain}\n`);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", payload));
    const bytes = new Uint8Array(domain.length + digest.length); bytes.set(domain); bytes.set(digest, domain.length); return bytes;
}
export async function envelopeDigest(envelope) { return hash(encoder.encode(canonical(envelope))); }
export async function verifyEnvelope(e, expectedKind = "", options = {}) {
    exact(e, ["protocol", "kind", "payload", "payload_sha256", "signature"]);
    exact(e.signature, ["algorithm", "key_id", "public_key", "value"]);
    const prof = profileFor(e.protocol);
    need(prof && e.signature.algorithm === prof.algorithm && (!expectedKind || e.kind === expectedKind), "Unsupported protocol, algorithm or artifact kind.");
    need(acceptsProtocol(options?.acceptedProtocols, e.protocol), "Protocol is not accepted by the receiver's policy.");
    need(typeof e.payload === "string" && e.payload.length <= MAX_INPUT_BYTES && typeof e.signature.public_key === "string" && e.signature.public_key.length <= prof.publicKeyFieldLimit && typeof e.signature.value === "string" && e.signature.value.length <= prof.signatureFieldLimit, "Envelope fields exceed size limit.");
    const raw = unb64(e.payload); need(raw.length > 0 && raw.length <= MAX_INPUT_BYTES / 2, "Invalid payload size.");
    const text = decodeBytes(raw), p = parseStrict(text);
    const canonicalBytes = encoder.encode(canonical(p));
    need(canonicalBytes.length === raw.length && canonicalBytes.every((byte, i) => byte === raw[i]) && await hash(raw) === e.payload_sha256, "Payload digest or canonical encoding mismatch.");
    // Exact encoded lengths first, then canonical decoding to exact sizes.
    need(e.signature.public_key.length === prof.encodedPublicKeyLength && e.signature.value.length === prof.encodedSignatureLength, "Invalid key or signature encoding.");
    const pub = unb64(e.signature.public_key), sig = unb64(e.signature.value);
    need(pub.length === prof.publicKeySize && sig.length === prof.signatureSize && await fingerprint(e.signature.public_key, prof.protocol) === e.signature.key_id, "Invalid key or signature encoding.");
    prof.checkKey(pub);
    await prof.verify(pub, await signingInput(e.kind, raw, prof), sig);
    await validatePayload(e.kind, p, prof); need(p.issuer_key_id === e.signature.key_id, "Signed key ID mismatch."); return p;
}
async function registration(de, ae, audience = "", at = null) {
    need(de?.protocol === ae?.protocol, "Delegation and acceptance carry different protocol versions.");
    const d = await verifyEnvelope(de, "agent-delegation"), a = await verifyEnvelope(ae, "agent-acceptance");
    need(a.delegation_sha256 === await envelopeDigest(de) && a.agent_id === d.agent_id && a.issuer_key_id === d.agent_key_id && ae.signature.public_key === d.agent_public_key, "Agent proof is not bound to this delegation.");
    need(!audience || d.service_audience === audience, "Delegation audience mismatch.");
    if (at !== null) {
        const n = new Date(at).getTime();
        need(n >= millis(d.not_before) && n < millis(d.expires_at) && millis(d.issued_at) <= n + 120000 && millis(a.issued_at) <= n + 120000 && millis(a.issued_at) >= millis(d.not_before), "Delegation is not active at the evaluation time.");
    }
    return d;
}
export async function verifyRegistration(reg, audience = "", at = null) {
    exact(reg, ["delegation", "acceptance"]);
    return registration(reg.delegation, reg.acceptance, audience, at);
}
// The rule set comes from bundle.protocol; every present envelope must carry the
// same version, and no signature is checked before that holds. options.acceptedProtocols
// restricts the versions a receiver accepts (undefined: every known version; an
// array, even an empty one: only its members).
export async function verifyBundle(input, options = {}) {
    const b = typeof input === "string" ? parseStrict(input) : input;
    exact(b, ["protocol", "statement", "delegation", "acceptance", "certificate"]); need(profileFor(b.protocol), "Unsupported bundle.");
    need(acceptsProtocol(options?.acceptedProtocols, b.protocol), "Bundle protocol is not accepted by the receiver's policy.");
    for (const envelope of [b.statement, b.delegation, b.acceptance, b.certificate]) {
        if (envelope !== null && envelope?.protocol !== b.protocol) throw new Error(profileFor(envelope?.protocol) ? "Bundle mixes protocol versions." : "Unsupported protocol, algorithm or artifact kind.");
    }
    const s = await verifyEnvelope(b.statement, "origin-statement");
    need(s.issuer === keyIdentity(s.issuer_key_id), "Source issuer must identify agent key.");
    need((b.delegation === null) === (b.acceptance === null), "Incomplete agent registration.");
    let d = null;
    if (b.delegation !== null) {
        d = await registration(b.delegation, b.acceptance);
        need(s.delegation_sha256 === await envelopeDigest(b.delegation) && s.agent_id === d.agent_id && s.issuer_key_id === d.agent_key_id && b.statement.signature.public_key === d.agent_public_key, "Statement is not authorized by this delegation.");
    } else need(s.delegation_sha256 === "", "Missing referenced delegation.");
    const result = { protocol: b.protocol, artifact_integrity: "valid", issuer_trust: "unknown", certificate_scope: "producer_only", agent_binding: d ? "admin_key_delegation" : "not_provided", organization_binding: "unproven", authorization_policy: "unknown", freshness: "unknown", time_basis: "producer_claimed", content_truth: "not_established", provider_evidence: "not_provided", log_inclusion: "not_registered", anchor: "not_requested", issuer: s.issuer, issuer_key_id: s.issuer_key_id, certificate_id: "", statement: s };
    if (b.certificate === null) return result;
    const c = await verifyEnvelope(b.certificate, "origin-certificate");
    need(c.statement_sha256 === await envelopeDigest(b.statement) && c.delegation_sha256 === s.delegation_sha256 && c.source_key_id === s.issuer_key_id && c.agent_binding === result.agent_binding, "Certificate is attached to the wrong source.");
    need(millis(s.issued_at) <= millis(c.issued_at) + 120000, "Certificate predates claimed source signature.");
    if (d) {
        await registration(b.delegation, b.acceptance, c.issuer, c.issued_at);
        need(millis(s.issued_at) >= millis(d.not_before) && millis(c.expires_at) <= millis(d.expires_at), "Certificate exceeds delegation scope.");
    }
    Object.assign(result, { certificate_scope: "origin_signature_checked", time_basis: "issuer_claimed_check_time", issuer: c.issuer, issuer_key_id: c.issuer_key_id, certificate_id: c.certificate_id, authorization_policy: "current_revocation_unknown" });
    if (options.issuer || options.keyIDs?.length) result.issuer_trust = "untrusted";
    if (options.issuer === c.issuer && options.keyIDs?.includes(c.issuer_key_id)) result.issuer_trust = "accepted_by_policy";
    if (options.at !== undefined && options.at !== null) {
        const at = new Date(options.at).getTime(); need(Number.isFinite(at), "Invalid evaluation time.");
        result.freshness = at < millis(c.issued_at) ? "not_yet_valid" : at >= millis(c.expires_at) ? "expired" : "valid_at_evaluation_time";
    }
    return result;
}
export async function verifyArtifact(result, bytes) { return result.statement.artifact_sha256 === await hash(bytes) && result.statement.artifact_size === String(bytes.length); }
const PKCS8_PREFIX = Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
// A key file's protocol names its key's algorithm: the 0.1 identifier is Ed25519
// (the key signs 0.1 and 0.2) and the 0.3 identifier is ML-DSA-65 (0.3 only). The
// 0.2 identifier is not a key file protocol. Both seeds are 32 bytes, so the
// derived public key and key ID must equal the stored ones. A string is the file's
// text and is size-checked as such; an object is checked by its compact JSON size.
export async function importKeyFile(file) {
    if (typeof file === "string") { need(encoder.encode(file).length <= MAX_KEY_FILE_BYTES, "Key file is too large."); file = parseStrict(file); }
    else if (file && typeof file === "object") {
        let size; try { size = encoder.encode(canonical(file)).length; } catch { throw new Error("Invalid key file."); }
        need(size <= MAX_KEY_FILE_BYTES, "Key file is too large.");
    }
    const hasRole = file && Object.hasOwn(file, "role");
    exact(file, ["protocol", "seed", "public_key", "key_id", ...(hasRole ? ["role"] : [])]);
    const algorithm = file.protocol === PROTOCOL ? ALGORITHM : file.protocol === PROTOCOL_03 ? ALGORITHM_03 : null; need(algorithm, "Unsupported key file.");
    if (hasRole) need(typeof file.role === "string" && encoder.encode(file.role).length <= 64 && !/[\r\n\0]/.test(file.role), "Invalid local key role label.");
    need(typeof file.seed === "string" && file.seed.length === 43, "A 32-byte seed is required.");
    const seed = unb64(file.seed); need(seed.length === 32, "A 32-byte seed is required.");
    if (algorithm === ALGORITHM_03) {
        const { publicKey, secretKey } = mldsaKeys(seed), encoded = b64(publicKey);
        need(encoded === file.public_key && await fingerprint(encoded, PROTOCOL_03) === file.key_id, "Key file fingerprint mismatch.");
        return { key: secretKey, keyID: file.key_id, publicKey: encoded, algorithm };
    }
    const pkcs8 = new Uint8Array(48); pkcs8.set(PKCS8_PREFIX); pkcs8.set(seed, 16);
    const key = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    need(jwk.x === file.public_key && await fingerprint(jwk.x) === file.key_id, "Key file fingerprint mismatch.");
    return { key, keyID: file.key_id, publicKey: file.public_key, algorithm };
}
// options.algorithm is "ML-DSA-65" (the default, a Core 0.3 key file) or "Ed25519" (a Core 0.1 key file,
// for deployments that still issue Core 0.1).
export async function generateKeyFile({ algorithm = ALGORITHM_03 } = {}) {
    need(algorithm === ALGORITHM || algorithm === ALGORITHM_03, "Unsupported key algorithm.");
    if (algorithm === ALGORITHM_03) {
        const seed = crypto.getRandomValues(new Uint8Array(32)), publicKey = b64(mldsaKeys(seed).publicKey), file = { protocol: PROTOCOL_03, seed: b64(seed), public_key: publicKey, key_id: await fingerprint(publicKey, PROTOCOL_03) };
        seed.fill(0); return file;
    }
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    return { protocol: PROTOCOL, seed: jwk.d, public_key: jwk.x, key_id: await fingerprint(jwk.x) };
}
// A signer's natural Core version: 0.3 for an ML-DSA-65 key, 0.1 for an Ed25519 key. Signing forms
// default to it and take the protocol explicitly otherwise (an Ed25519 key can also sign Core 0.2).
export function naturalProtocol(signer) { return algorithmOf(signer) === ALGORITHM_03 ? PROTOCOL_03 : PROTOCOL; }
export function header(kind, signer, now = new Date(), identity = keyIdentity(signer.keyID), protocol = naturalProtocol(signer)) { return { protocol: profileOf(protocol).protocol, kind, issuer: identity, issuer_key_id: signer.keyID, issued_at: timestamp(now) }; }
async function signBytes(signer, input) {
    return algorithmOf(signer) === ALGORITHM_03 ? signMLDSA(signer.key, input) : new Uint8Array(await crypto.subtle.sign("Ed25519", signer.key, input));
}
export async function sign(kind, payload, signer, protocol = naturalProtocol(signer)) {
    const prof = profileOf(protocol); need(algorithmOf(signer) === prof.algorithm, signerMismatch);
    await validatePayload(kind, payload, prof); need(payload.issuer_key_id === signer.keyID, "Signed key ID does not match signer.");
    const raw = encoder.encode(canonical(payload)), input = await signingInput(kind, raw, prof);
    const signature = await signBytes(signer, input);
    // As core-0.2.md recommends, check the signer's own key and signature under the profile before releasing them.
    const publicKey = decodeKey(signer.publicKey, prof); prof.checkKey(publicKey); await prof.verify(publicKey, input, signature);
    return { protocol: prof.protocol, kind, payload: b64(raw), payload_sha256: await hash(raw), signature: { algorithm: prof.algorithm, key_id: signer.keyID, public_key: signer.publicKey, value: b64(signature) } };
}
// Login is a distinct, bounded purpose. Reconstruct every signed byte from
// validated fields; a matching prefix alone is not authorization to sign.
export function validateLoginChallenge(challenge, keyID, expectedIssuer, now = Date.now()) {
    const invalid = "Invalid login challenge.";
    need(challenge && validIssuer(expectedIssuer) && challenge.issuer === expectedIssuer && typeof keyID === "string" && KEY.test(keyID) && typeof challenge.challenge_id === "string" && ID.test(challenge.challenge_id), invalid);
    let expires;
    try { expires = millis(challenge.expires_at); } catch { throw new Error(invalid); }
    need(Number.isFinite(now) && expires > now && expires <= now + 7 * 60000, invalid);
    const expected = `iff-apostille/login/0.1\nissuer:${expectedIssuer}\nkey_id:${keyID}\nchallenge:${challenge.challenge_id}\nexpires_at:${challenge.expires_at}\npurpose:register_or_login`;
    need(challenge.message === expected, invalid);
    return expected;
}
export async function signLogin(message, signer, expectedIssuer) {
    need(typeof message === "string" && message.length <= 4096 && algorithmOf(signer) === ALGORITHM, "Invalid login challenge.");
    const match = /^iff-apostille\/login\/0\.1\nissuer:([^\n]+)\nkey_id:([^\n]+)\nchallenge:([^\n]+)\nexpires_at:([^\n]+)\npurpose:register_or_login$/.exec(message);
    need(match, "Invalid login challenge.");
    validateLoginChallenge({ issuer: match[1], challenge_id: match[3], expires_at: match[4], message }, signer.keyID, expectedIssuer);
    return b64(new Uint8Array(await crypto.subtle.sign("Ed25519", signer.key, encoder.encode(message))));
}
// The Core 0.3 login challenge: UTF-8 bytes starting with the 0.3 prefix, at most 4096 bytes,
// signed with pure hedged ML-DSA-65 under the empty context. Its prefix is distinct from every
// artifact domain, and a login signature cannot substitute for a publication grant.
function loginBytes(message) {
    if (typeof message !== "string" || !message.startsWith(LOGIN_PREFIX_03)) return null;
    const raw = encoder.encode(message);
    return raw.length <= 4096 && decoder.decode(raw) === message ? raw : null;
}
export async function signLogin03(message, signer) {
    need(algorithmOf(signer) === ALGORITHM_03, "The 0.3 login challenge needs an ML-DSA-65 key.");
    const raw = loginBytes(message); need(raw, "Invalid login challenge.");
    const signature = signMLDSA(signer.key, raw);
    need(verifyLogin03(signer.publicKey, message, b64(signature)), "Invalid login challenge signature.");
    return b64(signature);
}
// Whether signature is a canonical ML-DSA-65 signature by publicKey over message; never throws.
export function verifyLogin03(publicKey, message, signature) {
    const prof = profileFor(PROTOCOL_03), raw = loginBytes(message);
    try {
        need(raw && typeof signature === "string" && signature.length === prof.encodedSignatureLength, "Invalid login signature.");
        return verifyMLDSA(decodeKey(publicKey, prof), raw, unb64(signature));
    } catch { return false; }
}
export async function createRegistration(admin, agent, audience, days = 30, protocol = naturalProtocol(admin)) {
    const prof = profileOf(protocol); need(algorithmOf(admin) === prof.algorithm && algorithmOf(agent) === prof.algorithm, signerMismatch);
    const now = new Date(), agentID = crypto.randomUUID();
    const de = await sign("agent-delegation", { ...header("agent-delegation", admin, now, keyIdentity(admin.keyID), protocol), agent_id: agentID, agent_key_id: agent.keyID, agent_public_key: agent.publicKey, service_audience: audience, not_before: timestamp(now), expires_at: timestamp(new Date(now.getTime() + days * 86400000)), scopes: ["sign_origin_statement"] }, admin, protocol);
    const ae = await sign("agent-acceptance", { ...header("agent-acceptance", agent, now, keyIdentity(agent.keyID), protocol), agent_id: agentID, delegation_sha256: await envelopeDigest(de) }, agent, protocol);
    return { delegation: de, acceptance: ae };
}
// A statement or grant takes the version of the material it binds to. An explicit protocol must
// agree with it, so a signer never emits a bundle the no-mixing rule would reject.
function boundVersion(protocol, ...bound) {
    need(bound.every((version) => version === bound[0]) && (protocol === undefined || protocol === bound[0]), "Bound artifacts must carry one protocol version.");
    return bound[0];
}
export async function createStatement(bytes, mediaType, agent, reg, protocol) {
    const version = boundVersion(protocol, reg?.delegation?.protocol, reg?.acceptance?.protocol);
    const d = await registration(reg.delegation, reg.acceptance);
    need(d.agent_key_id === agent.keyID, "The loaded key belongs to a different agent.");
    return sign("origin-statement", { ...header("origin-statement", agent, new Date(), keyIdentity(agent.keyID), version), agent_id: d.agent_id, delegation_sha256: await envelopeDigest(reg.delegation), artifact_sha256: await hash(bytes), artifact_size: String(bytes.length), artifact_media_type: mediaType || "application/octet-stream", nonce: crypto.randomUUID() }, agent, version);
}
export async function createProducerStatement(bytes, mediaType, agent, agentID, protocol = naturalProtocol(agent)) {
    return sign("origin-statement", { ...header("origin-statement", agent, new Date(), keyIdentity(agent.keyID), protocol), agent_id: agentID, delegation_sha256: "", artifact_sha256: await hash(bytes), artifact_size: String(bytes.length), artifact_media_type: mediaType || "application/octet-stream", nonce: crypto.randomUUID() }, agent, protocol);
}
// Local issuance checks source signatures only. Hosted publication still needs
// its own administrator grant; an issuer key alone never establishes trust. The
// certificate takes the source bundle's version and never certifies another's.
export async function issueBundle(input, signer, issuerID, at = new Date()) {
    const bundle = parseStrict(canonical(input));
    need(bundle.certificate === null, "Cannot replace an existing certificate.");
    const prof = profileOf(bundle.protocol); need(algorithmOf(signer) === prof.algorithm, signerMismatch);
    const checked = await verifyBundle(bundle), s = checked.statement;
    const now = millis(timestamp(at));
    need(millis(s.issued_at) <= now + 120000, "Source claims a future signing time.");
    let expiry = now + 86400000;
    if (bundle.delegation !== null) {
        const d = await verifyRegistration({ delegation: bundle.delegation, acceptance: bundle.acceptance }, issuerID, new Date(now));
        need(millis(s.issued_at) >= millis(d.not_before), "Source claims a time before delegation.");
        expiry = Math.min(expiry, millis(d.expires_at));
    }
    bundle.certificate = await sign("origin-certificate", { ...header("origin-certificate", signer, new Date(now), issuerID, prof.protocol), certificate_id: crypto.randomUUID(), statement_sha256: await envelopeDigest(bundle.statement), delegation_sha256: s.delegation_sha256, source_key_id: s.issuer_key_id, expires_at: timestamp(new Date(expiry)), signature_check: "valid", agent_binding: checked.agent_binding, organization_binding: "unproven", content_truth: "not_established" }, signer, prof.protocol);
    return bundle;
}
export async function createGrant(statement, reg, admin, audience, visibility, protocol) {
    const version = boundVersion(protocol, statement?.protocol, reg?.delegation?.protocol, reg?.acceptance?.protocol);
    const now = new Date();
    return sign("publication-grant", { ...header("publication-grant", admin, now, keyIdentity(admin.keyID), version), statement_sha256: await envelopeDigest(statement), delegation_sha256: await envelopeDigest(reg.delegation), service_audience: audience, visibility, purpose: "issue_origin_certificate", expires_at: timestamp(new Date(now.getTime() + 300000)), nonce: crypto.randomUUID() }, admin, version);
}
