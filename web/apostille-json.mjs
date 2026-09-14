// Strict JSON parsing is derived from the existing MIT-licensed receipt parser.
// This module has no receipt schemas, issuer defaults, or network behavior.
const MAX_JSON_DEPTH = 24;
function fail(code, message) { const error = new Error(message); error.code = code; throw error; }
export function parseJSONStrict(text) {
    if (typeof text !== "string") fail("invalid_json", "Apostille input must be text.");
    let position = 0;
    const whitespace = /[ \t\r\n]/;

    function skipWhitespace() {
        while (position < text.length && whitespace.test(text[position])) position += 1;
    }

    function parseStringNode() {
        const start = position;
        position += 1;
        let escaped = false;
        while (position < text.length) {
            const character = text[position];
            if (!escaped && character === '"') {
                position += 1;
                const raw = text.slice(start, position);
                let value;
                try { value = JSON.parse(raw); } catch { fail("invalid_json", "JSON contains an invalid string escape."); }
                if (!hasOnlyPairedUTF16Surrogates(value)) {
                    fail("invalid_json", "JSON contains an unpaired Unicode surrogate.");
                }
                return { kind: "string", value, canonical: JSON.stringify(value) };
            }
            if (!escaped && character.charCodeAt(0) < 0x20) fail("invalid_json", "JSON string contains a control character.");
            if (!escaped && character === "\\") escaped = true;
            else escaped = false;
            position += 1;
        }
        fail("invalid_json", "JSON string is not terminated.");
    }

    function parsePrimitive() {
        const remaining = text.slice(position);
        for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
            if (remaining.startsWith(literal)) {
                position += literal.length;
                return { kind: "primitive", value, canonical: literal };
            }
        }
        const match = remaining.match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
        if (!match) fail("invalid_json", "JSON contains an invalid value.");
        position += match[0].length;
        return { kind: "number", value: Number(match[0]), canonical: match[0] };
    }

    function parseArray(depth) {
        if (depth >= MAX_JSON_DEPTH) fail("json_depth_exceeded", `JSON nesting exceeds ${MAX_JSON_DEPTH} containers.`);
        position += 1;
        const items = [];
        skipWhitespace();
        if (text[position] === "]") {
            position += 1;
            return { kind: "array", value: [], items };
        }
        while (position < text.length) {
            const node = parseValue(depth + 1);
            items.push(node);
            skipWhitespace();
            if (text[position] === "]") {
                position += 1;
                return { kind: "array", value: items.map((item) => item.value), items };
            }
            if (text[position] !== ",") fail("invalid_json", "JSON array is missing a comma.");
            position += 1;
            skipWhitespace();
        }
        fail("invalid_json", "JSON array is not terminated.");
    }

    function parseObject(depth) {
        if (depth >= MAX_JSON_DEPTH) fail("json_depth_exceeded", `JSON nesting exceeds ${MAX_JSON_DEPTH} containers.`);
        position += 1;
        const entries = [];
        const seen = new Set();
        const value = Object.create(null);
        skipWhitespace();
        if (text[position] === "}") {
            position += 1;
            return { kind: "object", value, entries };
        }
        while (position < text.length) {
            if (text[position] !== '"') fail("invalid_json", "JSON object key must be a string.");
            const keyNode = parseStringNode();
            if (seen.has(keyNode.value)) fail("duplicate_json_key", `Duplicate JSON key: ${keyNode.value}`);
            seen.add(keyNode.value);
            skipWhitespace();
            if (text[position] !== ":") fail("invalid_json", "JSON object key is missing a colon.");
            position += 1;
            const node = parseValue(depth + 1);
            entries.push({ key: keyNode.value, node });
            value[keyNode.value] = node.value;
            skipWhitespace();
            if (text[position] === "}") {
                position += 1;
                return { kind: "object", value, entries };
            }
            if (text[position] !== ",") fail("invalid_json", "JSON object is missing a comma.");
            position += 1;
            skipWhitespace();
        }
        fail("invalid_json", "JSON object is not terminated.");
    }

    function parseValue(depth) {
        skipWhitespace();
        const character = text[position];
        if (character === "{") return parseObject(depth);
        if (character === "[") return parseArray(depth);
        if (character === '"') return parseStringNode();
        return parsePrimitive();
    }

    const node = parseValue(0);
    skipWhitespace();
    if (position !== text.length) fail("invalid_json", "Apostille input contains more than one JSON value.");
    return { value: node.value, node };
}

function hasOnlyPairedUTF16Surrogates(value) {
    for (let index = 0; index < value.length; index += 1) {
        const unit = value.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            const low = value.charCodeAt(index + 1);
            if (!(low >= 0xdc00 && low <= 0xdfff)) return false;
            index += 1;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            return false;
        }
    }
    return true;
}

export function parseStrict(text) {
    if (new TextEncoder().encode(text).length > 256 * 1024) fail("input_too_large", "Input exceeds 256 KiB.");
    const parsed = parseJSONStrict(text).value;
    const check = (value) => {
        if (typeof value === "number") fail("numeric_value", "Exact quantities must use decimal strings.");
        if (value && typeof value === "object") Object.values(value).forEach(check);
    };
    check(parsed);
    return parsed;
}
export function canonical(value) {
    if (value === null || typeof value === "boolean") return JSON.stringify(value);
    if (typeof value === "string") {
        if (!hasOnlyPairedUTF16Surrogates(value)) fail("invalid_unicode", "Unpaired Unicode surrogate.");
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
    if (value && typeof value === "object" && Object.getPrototypeOf(value) !== undefined) {
        return `{${Object.keys(value).sort().map((key) => `${canonical(key)}:${canonical(value[key])}`).join(",")}}`;
    }
    fail("unsupported_value", "Unsupported canonical JSON value.");
}
