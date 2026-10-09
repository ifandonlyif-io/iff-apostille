// ML-DSA-65 (FIPS 204) for Core 0.3, over the vendored @noble/post-quantum.
// Pure ML-DSA with an explicit empty context: the message actually signed is
// 0x00 || 0x00 || M (FIPS 204 Algorithm 2). HashML-DSA, an external mu and a
// non-empty context are never used, so such signatures do not verify.
// Mirrors apostille/mldsa.go and the 0.3 profile in apostille/profile.go.
import { ml_dsa65 } from "./vendor/noble/post-quantum/ml-dsa.js";

export const MLDSA65 = Object.freeze({ publicKeySize: ml_dsa65.lengths.publicKey, signatureSize: ml_dsa65.lengths.signature, seedSize: ml_dsa65.lengths.seed });
const EMPTY_CONTEXT = new Uint8Array(0);
const bytes = (value) => value instanceof Uint8Array;

// FIPS 204 ML-DSA.Verify with the empty context. Sizes are checked exactly first;
// a library error is a rejection, never an exception for the caller.
export function verifyMLDSA(publicKey, message, signature) {
    if (!bytes(publicKey) || !bytes(message) || !bytes(signature) || publicKey.length !== MLDSA65.publicKeySize || signature.length !== MLDSA65.signatureSize) return false;
    try { return ml_dsa65.verify(signature, message, publicKey, { context: EMPTY_CONTEXT }) === true; } catch { return false; }
}

// The key pair of a 32-byte FIPS 204 seed; secretKey is the library's expanded key.
export function mldsaKeys(seed) {
    if (!bytes(seed) || seed.length !== MLDSA65.seedSize) throw new Error("An ML-DSA-65 seed is 32 bytes.");
    const { publicKey, secretKey } = ml_dsa65.keygen(seed);
    return { publicKey, secretKey };
}

// FIPS 204 Algorithm 2 with the empty context, hedged: the library draws fresh
// randomness for every signature (no extraEntropy override is accepted here).
export function signMLDSA(secretKey, message) {
    if (!bytes(secretKey) || secretKey.length !== ml_dsa65.lengths.secretKey || !bytes(message)) throw new Error("Invalid ML-DSA-65 signing input.");
    return ml_dsa65.sign(message, secretKey, { context: EMPTY_CONTEXT });
}
