// Core 0.2 identifier grammar ("Identifier grammar" in docs/apostille/spec/core-0.2.md),
// decided over the characters as written for issuer and service_audience values.
// A hand-written byte scanner mirroring apostille/identifier02.go: it never
// normalizes, resolves or parses with URL, so every implementation returns the
// same verdict. Core 0.3 uses the same grammar.
const digit = (c) => c >= 0x30 && c <= 0x39;
const lowerAlnum = (c) => digit(c) || (c >= 0x61 && c <= 0x7a);
const PCHAR_PUNCTUATION = "-._~!$&'()*+,;=:@";
// RFC 3986 pchar without pct-encoded.
const pchar = (c) => digit(c) || (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c < 0x80 && PCHAR_PUNCTUATION.includes(String.fromCharCode(c)));
const allCodes = (text, test) => { for (let i = 0; i < text.length; i++) if (!test(text.charCodeAt(i))) return false; return true; };

// lower-alnum [ *( lower-alnum / "-" ) lower-alnum ], 1 to 63 bytes.
function label(text) {
    if (text.length === 0 || text.length > 63) return false;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if (!lowerAlnum(c) && (c !== 0x2d || i === 0 || i === text.length - 1)) return false;
    }
    return true;
}
// label *( "." label ) of at most 253 bytes whose final label does not start with a digit.
function regName(host) {
    if (host.length === 0 || host.length > 253) return false;
    const labels = host.split(".");
    return labels.every(label) && !digit(labels[labels.length - 1].charCodeAt(0));
}
function ipv4(host) {
    const octets = host.split(".");
    return octets.length === 4 && octets.every((octet) => octet.length >= 1 && octet.length <= 3 && (octet.length === 1 || octet[0] !== "0") && allCodes(octet, digit) && Number(octet) <= 255);
}
// %x31-39 *4DIGIT, at most 65535, and not 443.
function port(text) {
    if (text.length === 0 || text.length > 5 || text.charCodeAt(0) < 0x31 || text.charCodeAt(0) > 0x39 || !allCodes(text, digit)) return false;
    const n = Number(text);
    return n <= 65535 && n !== 443;
}

// Colon-separated groups of 1 to 4 lowercase hex digits; the empty string is no groups.
function hexGroups(text) {
    if (text === "") return [];
    const groups = [];
    for (const group of text.split(":")) {
        if (group.length === 0 || group.length > 4 || !/^[0-9a-f]+$/.test(group)) return null;
        groups.push(parseInt(group, 16));
    }
    return groups;
}
function parseIPv6(text) {
    const at = text.indexOf("::");
    const head = hexGroups(at < 0 ? text : text.slice(0, at));
    if (head === null) return null;
    if (at < 0) return head.length === 8 ? head : null;
    const rest = text.slice(at + 2);
    if (rest.includes("::")) return null;
    const tail = hexGroups(rest);
    if (tail === null || head.length + tail.length > 7) return null;
    return [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail];
}
// Lowercase groups without leading zeros; the longest run of two or more zero
// groups (the leftmost on a tie) becomes "::".
function formatIPv6(groups) {
    let bestStart = -1, bestLength = 1;
    for (let i = 0; i < 8;) {
        if (groups[i] !== 0) { i++; continue; }
        let j = i;
        while (j < 8 && groups[j] === 0) j++;
        if (j - i > bestLength) { bestStart = i; bestLength = j - i; }
        i = j;
    }
    let out = "";
    for (let i = 0; i < 8; i++) {
        if (i === bestStart) { out += "::"; i += bestLength - 1; continue; }
        if (i > 0 && i !== bestStart + bestLength) out += ":";
        out += groups[i].toString(16);
    }
    return out;
}
function canonicalIPv6(text) {
    const groups = parseIPv6(text);
    return groups !== null && formatIPv6(groups) === text;
}

// host [ ":" port ] *( "/" segment ), after the scheme.
function httpsIdentifier(rest) {
    let host;
    if (rest.startsWith("[")) {
        const end = rest.indexOf("]");
        if (end < 0 || !canonicalIPv6(rest.slice(1, end))) return false;
        rest = rest.slice(end + 1);
    } else {
        let end = rest.search(/[:/]/);
        if (end < 0) end = rest.length;
        host = rest.slice(0, end);
        rest = rest.slice(end);
        if (!ipv4(host) && !regName(host)) return false;
    }
    if (rest.startsWith(":")) {
        let end = rest.indexOf("/");
        if (end < 0) end = rest.length;
        if (!port(rest.slice(1, end))) return false;
        rest = rest.slice(end);
    }
    if (rest === "") return true;
    if (rest[0] !== "/") return false;
    // An empty segment is valid; "." and ".." are not.
    return rest.slice(1).split("/").every((segment) => segment !== "." && segment !== ".." && allCodes(segment, pchar));
}
// nid ":" nss after "urn:". The nid is lowercase only and is not converted.
function urnIdentifier(rest) {
    const colon = rest.indexOf(":");
    if (colon < 0) return false;
    const nid = rest.slice(0, colon), nss = rest.slice(colon + 1);
    return nid.length >= 2 && nid.length <= 32 && label(nid) && nss.length > 0 && pchar(nss.charCodeAt(0)) && allCodes(nss.slice(1), (c) => pchar(c) || c === 0x2f);
}

export function validIssuer02(value) {
    if (typeof value !== "string" || value.length === 0 || value.length > 256 || !allCodes(value, (c) => c >= 0x21 && c <= 0x7e)) return false;
    if (value.startsWith("https://")) return httpsIdentifier(value.slice(8));
    if (value.startsWith("urn:")) return urnIdentifier(value.slice(4));
    return false;
}
