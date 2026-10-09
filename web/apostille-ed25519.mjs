// Strict Ed25519 verification, Core 0.2 "Strict Ed25519 verification". The
// vendored curve library supplies point decoding and arithmetic only; every
// step of the specification is performed here, explicitly, in order, and no
// library "strict" mode is relied on. Mirrors apostille/strict.go.
import { ed25519 } from "./vendor/noble/curves/ed25519.js";
import { sha512 } from "./vendor/noble/hashes/sha2.js";

// L = 2^252 + 27742317777372353535851937790883648493, the order of the base point.
const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
const Point = ed25519.Point;
const le = (bytes) => { let n = 0n; for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]); return n; };
const equal = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);
function fail(message) { throw new Error(message); }

// Steps 2 and 3 for one 32-byte encoding: it decodes (with the library's permissive
// ZIP-215 decoding, so the canonical-encoding rule is enforced by this module and
// not by a library flag), re-encodes to the same
// bytes, is not the identity and lies in the prime-order subgroup. The subgroup
// test is [L-1]P + P = identity: the library's scalar multiplication accepts
// 0 <= s < L only, so [L]P cannot be asked for directly, and its own
// isTorsionFree() is not relied on (the tests prove the two agree on every
// vector). The errors carry no input bytes.
export function strictPoint(encoding) {
    if (!(encoding instanceof Uint8Array) || encoding.length !== 32) fail("point encoding must be 32 bytes");
    let point;
    try { point = Point.fromBytes(encoding, true); } catch { fail("point does not decode"); }
    if (!equal(point.toBytes(), encoding)) fail("point encoding is not canonical");
    if (point.is0()) fail("point is the identity");
    if (!point.multiplyUnsafe(L - 1n).add(point).is0()) fail("point is not in the prime-order subgroup");
    return point;
}

// Steps 2 and 3 for a public key. A key generated and used as RFC 8032 describes always passes.
export function checkStrictPublicKey(key) {
    try { strictPoint(key); } catch (error) { fail(`invalid public key: ${error.message}`); }
}

// Steps 1 to 4, reporting the first failure. Once A and R are torsion-free the
// cofactorless and cofactored equations agree; the equation is checked here
// with the library's points, so the verdict never depends on a platform's
// WebCrypto Ed25519 implementation.
export function verifyStrict(key, message, signature) {
    if (!(key instanceof Uint8Array) || !(signature instanceof Uint8Array) || key.length !== 32 || signature.length !== 64) fail("invalid source signature: wrong key or signature size");
    const s = le(signature.subarray(32));
    if (s >= L) fail("invalid source signature: S is not below the group order");
    let a, r;
    try { a = strictPoint(key); } catch (error) { fail(`invalid source signature: public key: ${error.message}`); }
    try { r = strictPoint(signature.subarray(0, 32)); } catch (error) { fail(`invalid source signature: R: ${error.message}`); }
    const input = new Uint8Array(64 + message.length);
    input.set(signature.subarray(0, 32)); input.set(key, 32); input.set(message, 64);
    const k = le(sha512(input)) % L;
    // [S]B = R + [k]A
    if (!Point.BASE.multiplyUnsafe(s).equals(r.add(a.multiplyUnsafe(k)))) fail("invalid source signature: equation does not hold");
}
