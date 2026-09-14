import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { formatBytes, localizedPath, publicCertificatePath, quotaErrorMessage, shouldFetch, validateTrustPolicy, verificationHeadline } from "./apostille-page.mjs";
import * as apostillePage from "./apostille-page.mjs";
import { message, messages } from "./apostille-messages.mjs";
import { b64, canonical, createRegistration, envelopeDigest, fingerprint, generateKeyFile, hash, importKeyFile, verifyEnvelope } from "./apostille-core.mjs";
import { ERC8004_PROTOCOL, createERC8004Request, verifyERC8004Binding } from "./apostille-erc8004.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const [html, css, page, messageSource] = await Promise.all([
    readFile(join(here, "apostille.html"), "utf8"),
    readFile(join(here, "apostille.css"), "utf8"),
    readFile(join(here, "apostille-page.mjs"), "utf8"),
    readFile(join(here, "apostille-messages.mjs"), "utf8"),
]);

test("all four locales contain every UI message", () => {
    const baseline = Object.keys(messages.en).sort();
    assert.deepEqual(Object.keys(messages.ja).sort(), baseline);
    assert.deepEqual(Object.keys(messages["zh-hant"]).sort(), baseline);
    assert.deepEqual(Object.keys(messages["zh-hans"]).sort(), baseline);
    for (const table of Object.values(messages)) {
        for (const value of Object.values(table)) assert.equal(typeof value === "string" && value.length > 0, true);
    }
    for (const key of [...html.matchAll(/data-i18n="([^"]+)"/g)].map((match) => match[1])) {
        assert.ok(Object.hasOwn(messages.en, key), `missing message: ${key}`);
    }
    assert.equal(message("zh-hant", "fileSelected", { name: "a", size: "1 B" }), "a · 1 B");
});

test("quota messages interpolate status limits and stay neutral until status loads", () => {
    for (const locale of Object.keys(messages)) {
        assert.equal(
            quotaErrorMessage(locale, "agent_limit_reached", { max_agents: 7, max_daily_certificates: 9 }),
            message(locale, "agent_limit_reached", { limit: 7 }),
        );
        assert.equal(
            quotaErrorMessage(locale, "daily_submission_limit", { max_agents: 7, max_daily_certificates: 9 }),
            message(locale, "daily_submission_limit", { limit: 9 }),
        );
        assert.equal(
            quotaErrorMessage(locale, "agent_limit_reached", null),
            message(locale, "agent_limit_reached_loading"),
        );
        assert.equal(
            quotaErrorMessage(locale, "daily_submission_limit", null),
            message(locale, "daily_submission_limit_loading"),
        );
        assert.doesNotMatch(message(locale, "agent_limit_reached", { limit: 7 }), /100/);
        assert.doesNotMatch(message(locale, "daily_submission_limit", { limit: 9 }), /100/);
    }
});

test("Simplified Chinese is a reviewed static dictionary", () => {
    assert.doesNotMatch(messageSource, /simplifiedCharacters|function simplify|Object\.fromEntries/);
    const visible = Object.values(messages["zh-hans"]).join("\n");
    assert.doesNotMatch(visible, /[請達筆規進體證簽鑰檔網驗區儲載讀頁記間時後來這個與為會開發過實錄應權閱務態從項於獨選擇稱憶離產匯數據絡確綁構維銷無處讓聲對並備劃當歷隱隨戶狀該傳詢單冊語線預覽瀏鏈組織帶攜見結帳資復範圍鐘檢測協環試內註變輸脈際參機連託]/);
});

test("locale paths preserve route and public record identifier", () => {
    const id = "11111111-1111-4111-8111-111111111111";
    assert.equal(localizedPath(`/apostille/certificates/${id}`, "ja"), `/ja/apostille/certificates/${id}`);
    assert.equal(localizedPath(`/zh-hant/apostille/certificates/${id}`, "en"), `/apostille/certificates/${id}`);
    assert.equal(localizedPath("/ja/apostille/console", "zh-hans"), "/zh-hans/apostille/console");
    assert.equal(publicCertificatePath({ id: "private", public_id: id }, "zh-hant"), `/zh-hant/apostille/certificates/${id}`);
    assert.throws(() => publicCertificatePath({ id: "private" }), /Public certificate ID/);
});

test("offline and verifier modes categorically disable fetch", () => {
    assert.equal(shouldFetch("verify", false), false);
    assert.equal(shouldFetch("home", true), false);
    assert.equal(shouldFetch("home", false), true);
    assert.match(html, /connect-src \{\{CONNECT\}\}/);
    assert.match(page, /if \(shouldFetch\(mode, offline\)\)/);
});

test("trust policy accepts both pins or neither", () => {
    assert.deepEqual(validateTrustPolicy("", ""), { issuer: "", keyID: "" });
    assert.deepEqual(validateTrustPolicy(" https://issuer.example/apostille ", " sha256:abc "), { issuer: "https://issuer.example/apostille", keyID: "sha256:abc" });
    assert.throws(() => validateTrustPolicy("https://issuer.example", ""), /supplied together/);
    assert.throws(() => validateTrustPolicy("", "sha256:abc"), /supplied together/);
    assert.equal(formatBytes(64 * 1024 * 1024), "64.0 MiB");
});

test("verification headline never treats a matching pin as overall authorization", () => {
    const pinned = { issuer_trust: "accepted_by_policy", freshness: "valid_at_evaluation_time" };
    assert.equal(verificationHeadline(pinned, null), "pinned");
    assert.equal(verificationHeadline(pinned, false), "failure");
    assert.equal(verificationHeadline({ ...pinned, freshness: "expired" }, true), "historical");
    assert.equal(verificationHeadline({ issuer_trust: "unknown", freshness: "valid_at_evaluation_time" }, true), "untrusted");
});

test("shell includes every route mode and local assets", () => {
    for (const mode of ["home", "console", "verify", "docs", "downloads", "keys", "certificate", "organization"]) {
        assert.match(html, new RegExp(`data-view="${mode}"`));
    }
    assert.match(html, /href="\{\{ASSETS\}\}apostille\.css\{\{ASSET_VERSION\}\}"/);
    assert.match(html, /src="\{\{ASSETS\}\}apostille-page\.mjs\{\{ASSET_VERSION\}\}"/);
    assert.doesNotMatch(html, /https?:\/\/[^"<{]+\.(?:woff2?|ttf|css|js)/i);
    assert.doesNotMatch(`${html}\n${page}`, /localStorage|sessionStorage/);
    assert.match(page, /public_id/);
    assert.match(page, /MAX_ARTIFACT_BYTES = 64 \* 1024 \* 1024/);
});

test("visual system has requested palette and accessibility states", () => {
    for (const color of ["#0c1420", "#15283d", "#93b3ce", "#65cbb7", "#eff3f7"]) assert.ok(css.includes(color));
    assert.match(css, /Avenir Next/);
    assert.match(css, /:focus-visible/);
    assert.match(css, /prefers-reduced-motion/);
    assert.match(css, /@media \(max-width:/);
});

function deferred() {
    let resolve;
    const promise = new Promise((done) => { resolve = done; });
    return { promise, resolve };
}

function jsonResponse(data, init = {}) {
    return new Response(JSON.stringify(data), { ...init, headers: { "Content-Type": "application/json", ...init.headers } });
}

async function uiERC8004Document(signer, registration, request, ownerSignature) {
    const issued = new Date(); issued.setMilliseconds(0);
    const stamp = (offset) => new Date(issued.getTime() + offset).toISOString().replace(/\.\d{3}Z$/, "Z");
    const payload = {
        protocol: ERC8004_PROTOCOL, kind: "erc8004-binding", issuer: "https://issuer.example/apostille",
        issuer_key_id: signer.keyID, issued_at: stamp(0), request, owner_signature: ownerSignature,
        block_number: "123", block_hash: `0x${"12".repeat(32)}`, block_timestamp: stamp(-30000),
        expires_at: stamp(3600000), check: "owner_of_eoa",
    };
    const raw = new TextEncoder().encode(canonical(payload));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
    const domain = new TextEncoder().encode("iff-apostille/erc8004-binding/snapshot/0.1\n"), input = new Uint8Array(domain.length + digest.length);
    input.set(domain); input.set(digest, domain.length);
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", signer.key, input));
    return { protocol: ERC8004_PROTOCOL, binding: {
        protocol: ERC8004_PROTOCOL, kind: "erc8004-binding", payload: b64(raw), payload_sha256: await hash(raw),
        signature: { algorithm: "Ed25519", key_id: signer.keyID, public_key: signer.publicKey, value: b64(signature) },
    }, ...registration };
}

// Exercise the actual page event handlers with real WebCrypto. Only DOM I/O
// and the hosted API are simulated; the signature pause controls event order.
async function consoleHarness(t, { certificates = [], empty = false, mode = "console" } = {}) {
    const downloads = [], submissions = [], agents = [], requests = [], nodes = new Map();
    let intercept = null;
    const blobs = new Map();
    class Element {
        constructor() {
            this.value = ""; this.checked = false; this.disabled = false;
            this.files = []; this.dataset = {}; this.children = [];
            this.listeners = new Map(); this.classList = { toggle() {} };
        }
        addEventListener(type, handler) {
            this.listeners.set(type, [...(this.listeners.get(type) || []), handler]);
        }
        async dispatch(type) {
            for (const handler of this.listeners.get(type) || []) await handler({ target: this, preventDefault() {} });
        }
        append(...children) { this.children.push(...children); }
        replaceChildren(...children) { this.children = children; }
        setAttribute() {}
        focus() {}
        scrollIntoView() { this.scrolledIntoView = true; }
        click() { if (this.download) downloads.push({ name: this.download, blob: blobs.get(this.href) }); }
    }
    const node = (id) => {
        if (!nodes.has(id)) nodes.set(id, new Element());
        return nodes.get(id);
    };
    const radios = ["private", "public"].map((value) => Object.assign(new Element(), { value, checked: value === "private" }));
    const document = {
        body: { dataset: { mode, lang: "en", offline: "false" } }, documentElement: {},
        getElementById: node, createElement: () => new Element(),
        querySelector: (selector) => selector === 'input[name="visibility"]:checked' ? radios.find((radio) => radio.checked) : null,
        querySelectorAll: (selector) => selector === 'input[name="visibility"]' ? radios : [],
    };
    const previousDocument = globalThis.document;
    globalThis.document = document;
    t.after(() => {
        if (previousDocument === undefined) delete globalThis.document;
        else globalThis.document = previousDocument;
    });
    t.mock.method(URL, "createObjectURL", (blob) => { const url = `blob:test-${blobs.size}`; blobs.set(url, blob); return url; });
    t.mock.method(URL, "revokeObjectURL", () => {});
    const issuer = "https://issuer.example/apostille";
    t.mock.method(globalThis, "fetch", async (url, options) => {
        const path = url.replace("/api/apostille/v1", ""), req = options.body ? JSON.parse(options.body) : null;
        requests.push({ path, method: options.method || "GET", body: req, headers: options.headers });
        let data;
        if (path === "/status") data = { issuer, enabled: true };
        else if (path === "/erc8004/config") data = { profile: "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.1", enabled: true, networks: [{ chain_id: "8453", registry_address: "0x1111111111111111111111111111111111111111" }], max_binding_age_seconds: 3600, wallet_support: "eoa_only" };
        else if (path === "/auth/challenges") {
            const challengeID = crypto.randomUUID(), expiresAt = new Date(Date.now() + 300000).toISOString().replace(/\.\d{3}Z$/, "Z");
            data = { issuer, challenge_id: challengeID, expires_at: expiresAt, message: `iff-apostille/login/0.1\nissuer:${issuer}\nkey_id:${await fingerprint(req.public_key)}\nchallenge:${challengeID}\nexpires_at:${expiresAt}\npurpose:register_or_login` };
        }
        else if (path === "/auth/verify") data = { access_token: "test-session" };
        else if (path === "/me") data = { workspace: { name: "Test", is_public: false }, agents, certificates };
        else if (path === "/workspace") data = req;
        else if (path === "/agents") {
            const d = await verifyEnvelope(req.delegation, "agent-delegation");
            data = { id: d.agent_id, key_id: d.agent_key_id, name: req.name, expires_at: d.expires_at, delegation: req.delegation, acceptance: req.acceptance };
            agents.push(data);
        } else if (path === "/submissions") { submissions.push(req); data = { id: "test", bundle: { statement: req.statement } }; }
        else if (/^\/agents\/[^/]+\/revoke$/.test(path)) { data = agents.find((agent) => path.includes(agent.id)); data.revoked_at = new Date().toISOString(); }
        else if (/^\/agents\/[^/]+\/erc8004$/.test(path)) data = {};
        else if (/^\/certificates\/[^/]+\/bundle$/.test(path)) data = { example: "stored bundle" };
        else if (/^\/certificates\/[^/]+\/hide$/.test(path)) { data = certificates.find((certificate) => path.includes(certificate.id)); data.is_public = false; }
        else throw new Error(`Unexpected request: ${path}`);
        const response = jsonResponse(data);
        return intercept ? intercept({ path, req, options, response }) : response;
    });
    await import(`./apostille-page.mjs?race-test=${crypto.randomUUID()}`);
    if (empty) return { node, downloads, submissions, requests };
    await node("admin-generate").dispatch("click");
    await node("admin-login").dispatch("click");
    await node("agent-generate").dispatch("click");
    node("agent-name").value = "Test agent";
    await node("agent-register").dispatch("click");
    const selectFile = async (content, read) => {
        const bytes = new TextEncoder().encode(content);
        node("artifact-input").files = [{ name: `${content}.txt`, size: bytes.length, type: "text/plain", arrayBuffer: read || (async () => bytes.buffer) }];
        await node("artifact-input").dispatch("change");
    };
    await selectFile("original");
    await node("statement-create").dispatch("click");
    assert.equal(node("grant-create").disabled, false, node("issue-status").textContent);
    return {
        node, downloads, submissions, selectFile, requests,
        intercept(fn) { intercept = fn; },
        async visibility(value) {
            radios.forEach((radio) => { radio.checked = radio.value === value; });
            await radios.find((radio) => radio.checked).dispatch("change");
        },
    };
}

test("protocol deep links open the section and retain it when changing language", async (t) => {
    const previousWindow = globalThis.window, destinations = [];
    globalThis.window = {
        location: { pathname: "/apostille/docs", hash: "#zk-budget", assign: (destination) => destinations.push(destination) },
    };
    t.after(() => {
        if (previousWindow === undefined) delete globalThis.window;
        else globalThis.window = previousWindow;
    });
    const ui = await consoleHarness(t, { empty: true, mode: "docs" });
    assert.equal(ui.node("zk-budget").scrolledIntoView, true, "reveal the section after the docs view is translated");
    for (const hash of ["#zk-budget", "#erc8004", "#core", "#unrecognized-data"]) {
        window.location.hash = hash;
        ui.node("locale-select").value = "ja";
        await ui.node("locale-select").dispatch("change");
    }
    assert.deepEqual(destinations, ["/ja/apostille/docs#zk-budget", "/ja/apostille/docs#erc8004", "/ja/apostille/docs#core", "/ja/apostille/docs"]);
    const verifier = await consoleHarness(t, { empty: true, mode: "verify" });
    window.location.pathname = "/apostille/verify";
    window.location.hash = "#zk-budget";
    verifier.node("locale-select").value = "zh-hant";
    await verifier.node("locale-select").dispatch("change");
    assert.equal(destinations.at(-1), "/zh-hant/apostille/verify", "only protocol pages carry section fragments");
});

test("workspace exit guard covers document exits and canceled language changes retain the draft", async (t) => {
    const previousWindow = globalThis.window, destinations = [], listeners = new Map();
    globalThis.window = {
        location: { href: "https://ifandonlyif.io/apostille/console", pathname: "/apostille/console", assign: (destination) => destinations.push(destination) },
        addEventListener: (type, handler) => listeners.set(type, handler),
    };
    t.after(() => {
        if (previousWindow === undefined) delete globalThis.window;
        else globalThis.window = previousWindow;
    });
    await consoleHarness(t, { empty: true, mode: "verify" });
    assert.equal(listeners.has("beforeunload"), false, "public verifier never guards navigation");
    await consoleHarness(t, { empty: true });
    const emptyExit = { preventDefault() { this.canceled = true; } };
    listeners.get("beforeunload")(emptyExit);
    assert.equal(emptyExit.canceled, undefined, "empty workspace does not prompt");
    const ui = await consoleHarness(t);
    const event = { preventDefault() { this.canceled = true; } };
    listeners.get("beforeunload")(event);
    assert.equal(event.canceled, true);
    assert.equal(event.returnValue, "");
    ui.node("locale-select").value = "zh-hant";
    await ui.node("locale-select").dispatch("change");
    assert.equal(ui.node("locale-select").value, "en");
    assert.deepEqual(destinations, ["/zh-hant/apostille/console"]);
    await ui.node("grant-create").dispatch("click");
    assert.equal(ui.node("certificate-submit").disabled, false, "canceling navigation retains the signed draft");
});

function pauseSignature(t, kind) {
    const entered = deferred(), resume = deferred();
    const sign = crypto.subtle.sign.bind(crypto.subtle);
    let paused = false;
    t.mock.method(crypto.subtle, "sign", async (...args) => {
        if (!paused && new TextDecoder().decode(args[2]).startsWith(`iff-apostille/${kind}/0.1\n`)) {
            paused = true; entered.resolve(); await resume.promise;
        }
        return sign(...args);
    });
    return { entered: entered.promise, resume: resume.resolve };
}

function pauseProfileVerification(t, part) {
    const entered = deferred(), resume = deferred();
    const verify = crypto.subtle.verify.bind(crypto.subtle);
    let paused = false;
    const method = t.mock.method(crypto.subtle, "verify", async (...args) => {
        if (!paused && new TextDecoder().decode(args[3]).startsWith(`iff-apostille/erc8004-binding/${part}/0.1\n`)) {
            paused = true; entered.resolve(); await resume.promise;
        }
        return verify(...args);
    });
    return { entered: entered.promise, resume: resume.resolve, restore: () => method.mock.restore() };
}

test("console reconstructs the complete login challenge before signing", async (t) => {
    const mutations = {
        purpose: (data) => { data.message = data.message.replace("purpose:register_or_login", "purpose:publish"); },
        suffix: (data) => { data.message += "\npermission:publish"; },
        issuer: (data) => { data.message = data.message.replace(data.issuer, "https://other.example/apostille"); data.issuer = "https://other.example/apostille"; },
        metadata: (data) => { data.challenge_id = crypto.randomUUID(); },
        identifier: (data) => { data.message = data.message.replace(data.challenge_id, "invalid"); data.challenge_id = "invalid"; },
        expiry: (data) => { const later = new Date(Date.now() + 8 * 60000).toISOString().replace(/\.\d{3}Z$/, "Z"); data.message = data.message.replace(data.expires_at, later); data.expires_at = later; },
        expired: (data) => { const past = new Date(Date.now() - 1000).toISOString().replace(/\.\d{3}Z$/, "Z"); data.message = data.message.replace(data.expires_at, past); data.expires_at = past; },
    };
    for (const [name, mutate] of Object.entries(mutations)) await t.test(name, async (st) => {
        const ui = await consoleHarness(st);
        const before = ui.requests.filter(({ path }) => path === "/auth/verify").length;
        ui.intercept(async ({ path, response }) => {
            if (path !== "/auth/challenges") return response;
            const data = await response.json(); mutate(data); return jsonResponse(data);
        });
        const sign = st.mock.method(crypto.subtle, "sign");
        await ui.node("admin-login").dispatch("click");
        assert.equal(sign.mock.callCount(), 0, "unvalidated challenge must never reach the private key");
        assert.equal(ui.requests.filter(({ path }) => path === "/auth/verify").length, before);
        assert.match(ui.node("auth-status").textContent, /login challenge/i);
        assert.equal(ui.node("workspace-panels").hidden, true);
    });
});

test("console discards grants canceled by visibility changes, including a round trip", async (t) => {
    const ui = await consoleHarness(t);
    for (const toggleBack of [false, true]) {
        await t.test(`visibility round trip: ${toggleBack}`, async (st) => {
            await ui.visibility("public");
            const pause = pauseSignature(st, "publication-grant"), count = ui.downloads.length;
            const pending = ui.node("grant-create").dispatch("click");
            await pause.entered;
            await ui.visibility("private");
            if (toggleBack) await ui.visibility("public");
            pause.resume(); await pending;
            assert.equal(ui.downloads.length, count, "canceled grant must not be downloaded");
            assert.equal(ui.node("certificate-submit").disabled, true);
            await ui.node("certificate-submit").dispatch("click");
            assert.equal(ui.submissions.length, 0, "canceled grant must not be submitted");
        });
    }
    await ui.visibility("private");
    await ui.node("grant-create").dispatch("click");
    assert.equal(ui.node("certificate-submit").disabled, false);
    await ui.node("certificate-submit").dispatch("click");
    assert.equal(ui.submissions.length, 1);
    const req = ui.submissions[0], grant = await verifyEnvelope(req.grant, "publication-grant");
    assert.equal(grant.visibility, "private");
    assert.equal(grant.statement_sha256, await envelopeDigest(req.statement));
});

test("rebuilding a statement invalidates a pending publication grant", async (t) => {
    const ui = await consoleHarness(t), pause = pauseSignature(t, "publication-grant");
    const pending = ui.node("grant-create").dispatch("click");
    await pause.entered;
    await ui.node("statement-create").dispatch("click");
    const count = ui.downloads.length;
    pause.resume(); await pending;
    assert.equal(ui.downloads.length, count);
    assert.equal(ui.node("certificate-submit").disabled, true);
    await ui.node("certificate-submit").dispatch("click");
    assert.equal(ui.submissions.length, 0);
});

test("changing the original file invalidates a pending statement", async (t) => {
    const ui = await consoleHarness(t), pause = pauseSignature(t, "origin-statement");
    const pending = ui.node("statement-create").dispatch("click");
    await pause.entered;
    await ui.selectFile("replacement");
    const count = ui.downloads.length;
    pause.resume(); await pending;
    assert.equal(ui.downloads.length, count);
    assert.equal(ui.node("grant-create").disabled, true);
    await ui.node("statement-create").dispatch("click");
    const statement = await verifyEnvelope(JSON.parse(await ui.downloads.at(-1).blob.text()), "origin-statement");
    assert.equal(statement.artifact_sha256, await hash(new TextEncoder().encode("replacement")));
});

test("a slow file read cannot replace the subsequently selected original", async (t) => {
    const ui = await consoleHarness(t), read = deferred();
    const pending = ui.selectFile("slow", () => read.promise);
    assert.equal(ui.node("statement-create").disabled, true);
    await ui.selectFile("latest");
    read.resolve(new TextEncoder().encode("slow").buffer); await pending;
    await ui.node("statement-create").dispatch("click");
    const statement = await verifyEnvelope(JSON.parse(await ui.downloads.at(-1).blob.text()), "origin-statement");
    assert.equal(statement.artifact_sha256, await hash(new TextEncoder().encode("latest")));
});

test("changing the administrator cancels every stage of an older login", async (t) => {
    for (const stage of ["/auth/challenges", "signature", "/auth/verify", "/me"]) {
        await t.test(stage, async (st) => {
            const ui = await consoleHarness(st), entered = deferred(), release = deferred();
            const oldKey = ui.node("admin-key-id").textContent;
            let signature;
            if (stage === "signature") signature = pauseSignature(st, "login");
            else ui.intercept(async ({ path, response }) => {
                if (path === stage) { entered.resolve(); await release.promise; }
                return response;
            });
            const pending = ui.node("admin-login").dispatch("click");
            await (signature ? signature.entered : entered.promise);
            await ui.node("admin-generate").dispatch("click");
            const importedStatus = ui.node("auth-status").textContent;
            const requestCount = ui.requests.length;
            if (signature) signature.resume(); else release.resolve();
            await pending;
            assert.notEqual(ui.node("admin-key-id").textContent, oldKey);
            assert.equal(ui.node("workspace-panels").hidden, true);
            assert.equal(ui.node("agent-register").disabled, true);
            assert.equal(ui.node("certificate-submit").disabled, true);
            assert.equal(ui.node("auth-status").textContent, importedStatus);
            assert.equal(ui.requests.length, requestCount, "obsolete login must not send its next request");
        });
    }
});

test("old login and workspace successes or failures cannot replace a newer session", async (t) => {
    for (const stage of ["/auth/verify", "/me"]) for (const fail of [false, true]) {
        await t.test(`${stage} ${fail ? "failure" : "success"}`, async (st) => {
            const ui = await consoleHarness(st), entered = deferred(), release = deferred();
            let paused = false;
            ui.intercept(async ({ path, response }) => {
                if (!paused && path === stage) {
                    paused = true; entered.resolve(); await release.promise;
                    if (fail) throw new Error("old session failed");
                    return response;
                }
                if (path === "/auth/verify") return jsonResponse({ access_token: "new-session" });
                if (path === "/me") return jsonResponse({ workspace: { name: "New workspace", is_public: false }, agents: [], certificates: [] });
                return response;
            });
            const pending = ui.node("admin-login").dispatch("click");
            await entered.promise;
            const keyFile = await generateKeyFile(), raw = new TextEncoder().encode(JSON.stringify(keyFile));
            ui.node("admin-import").files = [{ size: raw.length, arrayBuffer: async () => raw.buffer }];
            await ui.node("admin-import").dispatch("change");
            await ui.node("admin-login").dispatch("click");
            const status = ui.node("auth-status").textContent;
            release.resolve(); await pending;
            assert.equal(ui.node("admin-key-id").textContent, keyFile.key_id);
            assert.equal(ui.node("workspace-name").value, "New workspace");
            assert.equal(ui.node("workspace-panels").hidden, false);
            assert.equal(ui.node("auth-status").textContent, status);
            await ui.node("workspace-form").dispatch("submit");
            assert.equal(ui.requests.at(-1).headers.Authorization, "Bearer new-session");
        });
    }
});

test("starting a slow administrator import immediately invalidates login and cannot replace a newer key", async (t) => {
    const ui = await consoleHarness(t), entered = deferred(), release = deferred(), read = deferred();
    ui.intercept(async ({ path, response }) => {
        if (path === "/auth/verify") { entered.resolve(); await release.promise; }
        return response;
    });
    const login = ui.node("admin-login").dispatch("click");
    await entered.promise;
    const keyFile = await generateKeyFile(), raw = new TextEncoder().encode(JSON.stringify(keyFile));
    ui.node("admin-import").files = [{ size: raw.length, arrayBuffer: () => read.promise }];
    const importing = ui.node("admin-import").dispatch("change");
    assert.equal(ui.node("admin-login").disabled, true);
    release.resolve(); await login;
    assert.equal(ui.node("workspace-panels").hidden, true);
    await ui.node("admin-generate").dispatch("click");
    const latest = ui.node("admin-key-id").textContent;
    read.resolve(raw.buffer); await importing;
    assert.equal(ui.node("admin-key-id").textContent, latest);
    assert.notEqual(latest, keyFile.key_id);
});

test("a profile update response from an old session cannot restore its public profile", async (t) => {
    const ui = await consoleHarness(t), entered = deferred(), release = deferred();
    ui.intercept(async ({ path, response }) => {
        if (path === "/workspace") {
            entered.resolve(); await release.promise;
            return jsonResponse({ name: "Old public profile", is_public: true, public_id: "old-profile" });
        }
        return response;
    });
    const pending = ui.node("workspace-form").dispatch("submit");
    await entered.promise;
    await ui.node("admin-generate").dispatch("click");
    const linkCount = ui.node("workspace-public-link").children.length;
    release.resolve(); await pending;
    assert.equal(ui.node("workspace-panels").hidden, true);
    assert.equal(ui.node("workspace-public-link").children.length, linkCount);
});

test("canceling a key file selection preserves the loaded keys and session", async (t) => {
    const ui = await consoleHarness(t);
    const before = {
        admin: ui.node("admin-key-id").textContent,
        agent: ui.node("agent-key-id").textContent,
        authStatus: ui.node("auth-status").textContent,
        agentStatus: ui.node("agent-status").textContent,
        requests: ui.requests.length,
    };
    await ui.node("admin-import").dispatch("change");
    await ui.node("agent-import").dispatch("change");
    assert.equal(ui.node("admin-key-id").textContent, before.admin);
    assert.equal(ui.node("agent-key-id").textContent, before.agent);
    assert.equal(ui.node("auth-status").textContent, before.authStatus);
    assert.equal(ui.node("agent-status").textContent, before.agentStatus);
    assert.equal(ui.node("workspace-panels").hidden, false);
    assert.equal(ui.node("statement-create").disabled, false);
    assert.equal(ui.requests.length, before.requests);
});

test("empty bundle selection is distinct from an oversized JSON file", async (t) => {
    const ui = await consoleHarness(t);
    ui.node("verify-bundle").files = [{ size: 256 * 1024 + 1, arrayBuffer() { throw new Error("must not read oversized JSON"); } }];
    await ui.node("verify-form").dispatch("submit");
    assert.match(ui.node("verify-status").textContent, /JSON file exceeds/);
    ui.node("verify-bundle").files = [];
    await ui.node("verify-form").dispatch("submit");
    assert.equal(ui.node("verify-status").textContent, "");
    assert.equal(ui.node("verification-result").hidden, true);
});

test("clearing an oversized original restores the no-file state", async (t) => {
    const ui = await consoleHarness(t);
    ui.node("artifact-input").files = [{ size: 64 * 1024 * 1024 + 1, arrayBuffer() { throw new Error("must not read oversized original"); } }];
    await ui.node("artifact-input").dispatch("change");
    assert.equal(ui.node("issue-status").textContent, message("en", "fileTooLarge"));
    ui.node("artifact-input").files = [];
    await ui.node("artifact-input").dispatch("change");
    assert.equal(ui.node("artifact-summary").textContent, message("en", "noFile"));
    assert.equal(ui.node("issue-status").textContent, "");
    assert.equal(ui.node("statement-create").disabled, true);
    assert.equal(ui.node("grant-create").disabled, true);
});

test("console login aborts stalled headers after ten seconds and clears the working state", async (t) => {
    const ui = await consoleHarness(t), entered = deferred();
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let signal;
    ui.intercept(({ path, options, response }) => {
        if (path !== "/auth/challenges") return response;
        signal = options.signal;
        entered.resolve();
        if (!signal) return response;
        return new Promise((_, reject) => signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true }));
    });
    const pending = ui.node("admin-login").dispatch("click");
    await entered.promise;
    if (!signal) await pending;
    assert.ok(signal instanceof AbortSignal, "API fetch must receive an abort signal");
    t.mock.timers.tick(9999);
    assert.equal(signal.aborted, false);
    assert.equal(ui.node("auth-status").textContent, message("en", "loginWorking"));
    t.mock.timers.tick(1);
    await pending;
    assert.equal(signal.aborted, true);
    assert.match(ui.node("auth-status").textContent, /timed out/i);
    assert.equal(ui.node("workspace-panels").hidden, true);
    assert.equal(ui.node("agent-register").disabled, true);
    assert.equal(ui.node("admin-login").disabled, false, "the user can try a fresh login");
});

test("console request deadline also covers a stalled response body", async (t) => {
    const ui = await consoleHarness(t), entered = deferred();
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let signal, streamController;
    ui.intercept(({ path, options, response }) => {
        if (path !== "/auth/challenges") return response;
        signal = options.signal;
        const body = new ReadableStream({ start(controller) {
            streamController = controller;
            controller.enqueue(new TextEncoder().encode('{"challenge_id":'));
            signal?.addEventListener("abort", () => controller.error(new DOMException("Aborted", "AbortError")), { once: true });
        } });
        entered.resolve();
        return new Response(body);
    });
    const pending = ui.node("admin-login").dispatch("click");
    await entered.promise;
    if (!signal) { streamController.error(new Error("end red-test stalled body")); await pending; }
    assert.ok(signal instanceof AbortSignal, "the deadline must remain active while consuming the body");
    t.mock.timers.tick(10000);
    await pending;
    assert.match(ui.node("auth-status").textContent, /timed out/i);
    assert.equal(ui.node("workspace-panels").hidden, true);
});

test("console rejects oversized response streams with absent or misleading Content-Length", async (t) => {
    for (const contentLength of [null, "2"]) await t.test(`Content-Length ${contentLength}`, async (st) => {
        const ui = await consoleHarness(st);
        let canceled = false, chunksRead = 0;
        ui.intercept(({ path, response }) => {
            if (path !== "/workspace") return response;
            const chunks = [new TextEncoder().encode('{"name":"'), ...Array.from({ length: 9 }, () => new Uint8Array(1024 * 1024).fill(97)), new TextEncoder().encode('","is_public":false}')];
            const body = new ReadableStream({
                pull(controller) { if (chunks.length) { chunksRead += 1; controller.enqueue(chunks.shift()); } else controller.close(); },
                cancel() { canceled = true; },
            }, { highWaterMark: 0 });
            return new Response(body, { headers: contentLength ? { "Content-Length": contentLength } : {} });
        });
        await ui.node("workspace-form").dispatch("submit");
        assert.equal(canceled, true, "stop the stream as soon as it exceeds 8 MiB");
        assert.equal(chunksRead, 9, "do not read the remaining body after crossing the limit");
        assert.match(ui.node("workspace-status").textContent, /8 MiB/);
        assert.doesNotMatch(ui.node("workspace-status").textContent, /Profile saved/);
    });
});

test("console rejects an oversized declared response before reading its body", async (t) => {
    const ui = await consoleHarness(t);
    let reads = 0, canceled = false;
    ui.intercept(({ path, response }) => path !== "/workspace" ? response : new Response(new ReadableStream({
        pull(controller) { reads += 1; controller.enqueue(new TextEncoder().encode('{"name":"Test","is_public":false}')); controller.close(); },
        cancel() { canceled = true; },
    }, { highWaterMark: 0 }), { headers: { "Content-Length": String(8 * 1024 * 1024 + 1) } }));
    await ui.node("workspace-form").dispatch("submit");
    assert.equal(reads, 0);
    assert.equal(canceled, true);
    assert.match(ui.node("workspace-status").textContent, /8 MiB/);
});

test("public API requests omit bearer tokens even with a loaded session", async (t) => {
    const requests = [];
    t.mock.method(globalThis, "fetch", async (url, options) => { requests.push({ url, options }); return jsonResponse({ ok: true }); });
    for (const path of ["/status", "/keys", "/erc8004/config", "/public/certificates/test", "/public/organizations/test", "/auth/challenges", "/auth/verify"]) {
        await apostillePage.requestAPI(path, {}, { token: "loaded-session" });
        assert.equal(new Headers(requests.at(-1).options.headers).has("Authorization"), false, path);
    }
    await apostillePage.requestAPI("/me", {}, { token: "loaded-session", authenticated: true });
    assert.equal(new Headers(requests.at(-1).options.headers).get("Authorization"), "Bearer loaded-session");
});

test("every console owner action explicitly includes the session bearer", async (t) => {
    const certificate = { id: "cert", public_id: "public-cert", created_at: "2026-09-14T00:00:00Z", is_public: true };
    const ui = await consoleHarness(t, { certificates: [certificate] });
    await ui.node("workspace-form").dispatch("submit");
    await ui.node("grant-create").dispatch("click");
    await ui.node("certificate-submit").dispatch("click");
    const actions = ui.node("certificate-list").children[0].children[1].children;
    await actions.find((button) => button.textContent === message("en", "downloadBundle")).dispatch("click");
    await actions.find((button) => button.textContent === message("en", "hide")).dispatch("click");
    const agentActions = ui.node("agent-list").children[0].children[1].children;
    await agentActions.find((button) => button.textContent === message("en", "revoke")).dispatch("click");
    const owners = ui.requests.filter(({ path }) => !["/status", "/erc8004/config", "/auth/challenges", "/auth/verify"].includes(path));
    for (const request of owners) assert.equal(new Headers(request.headers).get("Authorization"), "Bearer test-session", request.path);
    for (const path of ["/me", "/workspace", "/agents", "/submissions", "/certificates/cert/bundle", "/certificates/cert/hide"]) {
        assert.ok(owners.some((request) => request.path === path), `missing exercised owner action ${path}`);
    }
    assert.ok(owners.some(({ path }) => /^\/agents\/[^/]+\/revoke$/.test(path)));
});

test("ERC-8004 console does not contact a wallet until the explicit create action", async (t) => {
    const calls = [], previousEthereum = globalThis.ethereum;
    globalThis.ethereum = { request: async ({ method }) => {
        calls.push(method);
        if (method === "eth_requestAccounts") return ["0x2222222222222222222222222222222222222222"];
        if (method === "eth_chainId") return "0x2105";
        if (method === "personal_sign") return `0x${"12".repeat(65)}`;
        throw new Error("unexpected wallet method");
    } };
    t.after(() => {
        if (previousEthereum === undefined) delete globalThis.ethereum;
        else globalThis.ethereum = previousEthereum;
    });
    const ui = await consoleHarness(t);
    assert.deepEqual(calls, []);
    const registrationRequest = ui.requests.find(({ path }) => path === "/agents");
    const delegation = await verifyEnvelope(registrationRequest.body.delegation, "agent-delegation");
    ui.node("erc8004-agent").value = delegation.agent_id;
    ui.node("erc8004-network").value = "8453:0x1111111111111111111111111111111111111111";
    ui.node("erc8004-token").value = "42";
    await ui.node("erc8004-token").dispatch("input");
    assert.equal(ui.node("erc8004-create").disabled, false);
    await ui.node("erc8004-create").dispatch("click");
    assert.deepEqual(calls, ["eth_requestAccounts", "eth_chainId", "personal_sign"]);
});

test("ERC-8004 create is single-flight and an input change cancels consent before personal_sign", async (t) => {
    const calls = [], previousEthereum = globalThis.ethereum;
    globalThis.ethereum = { request: async ({ method }) => {
        calls.push(method);
        if (method === "eth_requestAccounts") return ["0x2222222222222222222222222222222222222222"];
        if (method === "eth_chainId") return "0x2105";
        if (method === "personal_sign") return `0x${"12".repeat(65)}`;
    } };
    t.after(() => previousEthereum === undefined ? delete globalThis.ethereum : globalThis.ethereum = previousEthereum);
    const ui = await consoleHarness(t), registrationRequest = ui.requests.find(({ path }) => path === "/agents");
    const delegation = await verifyEnvelope(registrationRequest.body.delegation, "agent-delegation");
    ui.node("erc8004-agent").value = delegation.agent_id;
    ui.node("erc8004-network").value = "8453:0x1111111111111111111111111111111111111111";
    ui.node("erc8004-token").value = "42";
    await ui.node("erc8004-token").dispatch("input");
    const pause = pauseProfileVerification(t, "request"), pending = ui.node("erc8004-create").dispatch("click");
    await pause.entered;
    await ui.node("erc8004-create").dispatch("click");
    ui.node("erc8004-token").value = "43";
    await ui.node("erc8004-token").dispatch("input");
    pause.resume(); await pending;
    assert.deepEqual(calls, ["eth_requestAccounts", "eth_chainId"]);
    assert.equal(ui.requests.some(({ path }) => /\/erc8004$/.test(path)), false);
    assert.equal(ui.node("erc8004-create").disabled, false, "latest valid selection is restored after canceled work");
});

test("ERC-8004 create and historical load discard verification completed after session or draft changes", async (t) => {
    const previousEthereum = globalThis.ethereum;
    globalThis.ethereum = { request: async ({ method }) => {
        if (method === "eth_requestAccounts") return ["0x2222222222222222222222222222222222222222"];
        if (method === "eth_chainId") return "0x2105";
        if (method === "personal_sign") return `0x${"12".repeat(65)}`;
    } };
    t.after(() => previousEthereum === undefined ? delete globalThis.ethereum : globalThis.ethereum = previousEthereum);
    const ui = await consoleHarness(t), registrationRequest = ui.requests.find(({ path }) => path === "/agents");
    const registration = { delegation: registrationRequest.body.delegation, acceptance: registrationRequest.body.acceptance };
    const delegation = await verifyEnvelope(registration.delegation, "agent-delegation"), issuerSigner = await importKeyFile(await generateKeyFile());
    let stored;
    ui.intercept(async ({ path, req, response }) => {
        if (!/\/erc8004$/.test(path)) return response;
        if (req) {
            const document = await uiERC8004Document(issuerSigner, registration, req.request, req.owner_signature);
            const checked = await verifyERC8004Binding(document);
            stored = { id: crypto.randomUUID(), agent_id: delegation.agent_id, document, created_at: checked.checked_at, expires_at: checked.expires_at };
        }
        return jsonResponse(stored);
    });
    ui.node("erc8004-agent").value = delegation.agent_id;
    ui.node("erc8004-network").value = "8453:0x1111111111111111111111111111111111111111";
    ui.node("erc8004-token").value = "42";
    await ui.node("erc8004-token").dispatch("input");

    const createPause = pauseProfileVerification(t, "snapshot"), create = ui.node("erc8004-create").dispatch("click");
    await createPause.entered;
    await ui.node("admin-generate").dispatch("click");
    const afterLogoutDownloads = ui.downloads.length;
    createPause.resume(); await create;
    createPause.restore();
    assert.equal(ui.downloads.length, afterLogoutDownloads, "late verified response is not downloaded");
    assert.equal(ui.node("erc8004-record").children.length, 0);

    await ui.node("admin-login").dispatch("click");
    ui.node("erc8004-agent").value = delegation.agent_id;
    await ui.node("erc8004-agent").dispatch("change");
    const agentActions = ui.node("agent-list").children[0].children[1].children;
    await agentActions.find((button) => button.textContent === message("en", "revoke")).dispatch("click");
    ui.node("erc8004-agent").value = delegation.agent_id;
    await ui.node("erc8004-agent").dispatch("change");
    assert.equal(ui.node("erc8004-load").disabled, false, "revoked agent remains selectable for historical retrieval");
    assert.equal(ui.node("erc8004-create").disabled, true);

    const loadPause = pauseProfileVerification(t, "snapshot"), load = ui.node("erc8004-load").dispatch("click");
    await loadPause.entered;
    ui.node("erc8004-token").value = "44";
    await ui.node("erc8004-token").dispatch("input");
    loadPause.resume(); await load;
    assert.equal(ui.node("erc8004-record").children.length, 0, "late historical verification does not restore a stale selection");
});

test("offline ERC-8004 UI reports binding integrity without claiming artifact or current ownership verification", async (t) => {
    const ui = await consoleHarness(t, { empty: true, mode: "verify" });
    const admin = await importKeyFile(await generateKeyFile()), agent = await importKeyFile(await generateKeyFile());
    const issuer = await importKeyFile(await generateKeyFile()), audience = "https://issuer.example/apostille";
    const registration = await createRegistration(admin, agent, audience, 30);
    const request = await createERC8004Request(admin, registration, {
        chain_id: "8453", registry_address: `0x${"1".repeat(40)}`, erc8004_agent_id: "42", owner_address: `0x${"2".repeat(40)}`,
    }, audience);
    const document = await uiERC8004Document(issuer, registration, request, `0x${"12".repeat(65)}`);
    const raw = new TextEncoder().encode(JSON.stringify(document));
    ui.node("verify-bundle").files = [{ size: raw.length, arrayBuffer: async () => raw.buffer }];
    ui.node("verify-time").value = new Date().toISOString();
    await ui.node("verify-form").dispatch("submit");
    assert.equal(ui.node("verify-status").textContent, "");
    assert.equal(ui.node("result-title").textContent, message("en", "erc8004VerifyUnknown"));
    const rows = ui.node("check-list").children;
    assert.equal(rows[0].children[0].textContent, message("en", "erc8004Integrity"));
    assert.ok(rows.every((row) => row.children[0].textContent !== message("en", "checkIntegrity")));
    const provider = rows.find((row) => row.children[0].textContent === message("en", "erc8004ProviderEvidence"));
    assert.equal(provider.children[1].className, "is-warn");
    assert.equal(ui.node("result-note").textContent, message("en", "erc8004Boundary"));
    assert.equal(ui.requests.length, 0, "verifying the detached proof must not fetch provider evidence or keys");
});
