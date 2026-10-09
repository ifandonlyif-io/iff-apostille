// Protocol profiles: everything that differs between Core versions, mirroring
// apostille/profile.go. Verification and signing select one profile by protocol
// string and never branch on the version themselves, so a later version is one
// more entry in PROFILES. The decoded key and signature sizes fix the exact
// encoded lengths (unpadded base64url); nothing else in the version-dependent
// paths assumes an algorithm's sizes.
import { validIssuer02 } from "./apostille-identifier.mjs";
import { checkStrictPublicKey, verifyStrict } from "./apostille-ed25519.mjs";
import { MLDSA65, verifyMLDSA } from "./apostille-mldsa.mjs";

export const PROTOCOL = "https://ifandonlyif.io/apostille/spec/0.1";
export const PROTOCOL_02 = "https://ifandonlyif.io/apostille/spec/0.2";
export const PROTOCOL_03 = "https://ifandonlyif.io/apostille/spec/0.3";
export const ALGORITHM = "Ed25519";
export const ALGORITHM_03 = "ML-DSA-65";

// Core 0.1 identifier rule (core-0.1.md "Common values"): kept exactly, URL parser included.
export function validIssuer(value) {
    if (typeof value !== "string" || value.length > 256 || !/^[\x21-\x7e]+$/.test(value) || value.includes("?") || value.includes("#")) return false;
    try {
        if (/[\\%]/.test(value)) return false;
        if (value.startsWith("urn:")) return value.length > 4 && value[4] !== "/";
        const u = new URL(value);
        return u.protocol === "https:" && u.host.length > 0 && !u.username && !u.password && u.host === value.split("/")[2] && !/%[0-9a-f]{2}/i.test(u.pathname);
    } catch { return false; }
}

const base64Length = (bytes) => Math.ceil(bytes * 4 / 3);
function need(condition, message) { if (!condition) throw new Error(message); }

// verify(key, message, signature) resolves when the signature is valid and
// throws otherwise; key and signature are already exact-size raw bytes.
async function verifyEd25519(key, message, signature) {
    const imported = await crypto.subtle.importKey("raw", key, "Ed25519", false, ["verify"]);
    need(await crypto.subtle.verify("Ed25519", imported, signature, message), "Invalid source signature.");
}
function profile(fields) {
    return Object.freeze({ ...fields, encodedPublicKeyLength: base64Length(fields.publicKeySize), encodedSignatureLength: base64Length(fields.signatureSize),
        // Bound on an encoded key or signature field before it is decoded: twice the decoded size (64 and 128 for Ed25519).
        publicKeyFieldLimit: 2 * fields.publicKeySize, signatureFieldLimit: 2 * fields.signatureSize });
}

// Core 0.1: platform WebCrypto, no key check.
const profile01 = profile({ protocol: PROTOCOL, domain: "0.1", algorithm: ALGORITHM, publicKeySize: 32, signatureSize: 64, validIssuer, checkKey() {}, verify: verifyEd25519 });
// Core 0.2: the exact identifier grammar and strict Ed25519 (apostille-ed25519.mjs).
const profile02 = profile({ protocol: PROTOCOL_02, domain: "0.2", algorithm: ALGORITHM, publicKeySize: 32, signatureSize: 64, validIssuer: validIssuer02, checkKey: checkStrictPublicKey, verify: async (key, message, signature) => verifyStrict(key, message, signature) });
// Core 0.3: ML-DSA-65, pure, empty context. Every 1952-byte string is a
// decodable public key, so the exact length is the whole key check.
const profile03 = profile({ protocol: PROTOCOL_03, domain: "0.3", algorithm: ALGORITHM_03, publicKeySize: MLDSA65.publicKeySize, signatureSize: MLDSA65.signatureSize, validIssuer: validIssuer02,
    checkKey(key) { need(key.length === MLDSA65.publicKeySize, "Invalid ML-DSA-65 public key length."); },
    async verify(key, message, signature) { need(verifyMLDSA(key, message, signature), "Invalid source signature."); } });

export const PROFILES = Object.freeze([profile01, profile02, profile03]);
// Every protocol identifier this implementation verifies and signs, oldest first.
export const KNOWN_PROTOCOLS = Object.freeze(PROFILES.map((p) => p.protocol));

// The profile of a protocol identifier, or undefined for an unknown value.
export function profileFor(protocol) { return typeof protocol === "string" ? PROFILES.find((p) => p.protocol === protocol) : undefined; }

// An undefined or null list accepts every known version; any array, even an
// empty one, accepts only its members.
export function acceptsProtocol(accepted, protocol) {
    if (accepted === undefined || accepted === null) return true;
    need(Array.isArray(accepted) && accepted.every((p) => typeof p === "string"), "Invalid accepted protocols.");
    return accepted.includes(protocol);
}
