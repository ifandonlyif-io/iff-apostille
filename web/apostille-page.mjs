import {
    MAX_INPUT_BYTES,
    canonical,
    createGrant,
    createRegistration,
    createStatement,
    decodeBytes,
    generateKeyFile,
    importKeyFile,
    parseStrict,
    signLogin,
    unb64,
    validateLoginChallenge,
    verifyArtifact,
    verifyBundle,
} from "./apostille-core.mjs";
import { ERC8004_PROTOCOL, createERC8004Request, erc8004OwnerMessage, verifyERC8004Binding } from "./apostille-erc8004.mjs";
import { message, messages } from "./apostille-messages.mjs?v=20260914-profiles-1";
import { DEFAULT_TIMEOUT_MS, MAX_RESPONSE_BYTES } from "./apostille-http.mjs";

export const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
export const MAX_KEY_FILE_BYTES = 4 * 1024;
export const API_TIMEOUT_MS = DEFAULT_TIMEOUT_MS;
export const MAX_API_RESPONSE_BYTES = MAX_RESPONSE_BYTES;
const API = "/api/apostille/v1";
const LOCALES = new Set(Object.keys(messages));
const DOC_FRAGMENTS = new Set(["#erc8004", "#zk-budget", "#core"]);
const QUOTA_LIMIT_FIELDS = Object.freeze({
    agent_limit_reached: "max_agents",
    daily_submission_limit: "max_daily_certificates",
});

export function shouldFetch(mode, offline) {
    return !offline && mode !== "verify";
}

export function localizedPath(pathname, locale) {
    const selected = LOCALES.has(locale) ? locale : "en";
    const path = pathname.replace(/^\/(?:ja|zh-hant|zh-hans)(?=\/apostille(?:\/|$))/, "") || "/apostille";
    return `${selected === "en" ? "" : `/${selected}`}${path}`;
}

export function validateTrustPolicy(issuer, keyID) {
    const normalized = { issuer: issuer.trim(), keyID: keyID.trim() };
    if (Boolean(normalized.issuer) !== Boolean(normalized.keyID)) throw new Error("Issuer and key pin must be supplied together.");
    return normalized;
}

export function publicCertificatePath(record, locale = "en") {
    if (!record?.public_id) throw new Error("Public certificate ID is unavailable.");
    return localizedPath(`/apostille/certificates/${encodeURIComponent(record.public_id)}`, locale);
}

export function formatBytes(size) {
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
    return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
}

export function verificationHeadline(result, artifactMatch) {
    if (artifactMatch === false) return "failure";
    if (result.freshness === "expired" || result.freshness === "not_yet_valid") return "historical";
    if (result.issuer_trust === "accepted_by_policy") return "pinned";
    return "untrusted";
}

class APIRequestError extends Error {}

// The console and direct callers use the same deadline, bounded stream reader
// and explicit authentication policy.
export async function requestAPI(path, options = {}, { token = "", authenticated = false, translate = (key) => message("en", key) } = {}) {
    const failure = (code) => new APIRequestError(translate(code));
    if (authenticated && !token) throw failure("authentication_required");
    const headers = { ...options.headers, Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}) };
    for (const name of Object.keys(headers)) if (name.toLowerCase() === "authorization") delete headers[name];
    if (authenticated) headers.Authorization = `Bearer ${token}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
    try {
        const response = await fetch(`${API}${path}`, { ...options, headers, signal: controller.signal, redirect: "error", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" });
        if (response.redirected || (response.status >= 300 && response.status < 400)) throw failure("network_error");
        const length = response.headers.get("content-length");
        if (length && Number(length) > MAX_API_RESPONSE_BYTES) {
            await response.body?.cancel();
            throw failure("response_too_large");
        }
        if (!response.body) throw failure("invalid_response");
        const reader = response.body.getReader(), chunks = [];
        let size = 0;
        try {
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                size += value.byteLength;
                if (size > MAX_API_RESPONSE_BYTES) {
                    await reader.cancel();
                    throw failure("response_too_large");
                }
                chunks.push(value);
            }
        } finally { reader.releaseLock(); }
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        let data;
        try { data = JSON.parse(decodeBytes(bytes)); } catch { throw failure("invalid_response"); }
        if (!response.ok) throw failure(typeof data?.code === "string" && /^[a-z][a-z0-9_]{0,79}$/.test(data.code) ? data.code : `HTTP ${response.status}`);
        if (!data || typeof data !== "object" || Array.isArray(data)) throw failure("invalid_response");
        return data;
    } catch (error) {
        if (controller.signal.aborted) throw failure("request_timeout");
        if (error instanceof APIRequestError) throw error;
        throw failure("network_error");
    } finally { clearTimeout(timeout); }
}

export function quotaErrorMessage(locale, code, limits) {
    const field = QUOTA_LIMIT_FIELDS[code];
    if (!field) return message(locale, code);
    const limit = limits?.[field];
    return Number.isSafeInteger(limit) && limit > 0
        ? message(locale, code, { limit })
        : message(locale, `${code}_loading`);
}

function statusLimits(value) {
    if (!value || typeof value !== "object") return null;
    const maxAgents = value.max_agents, maxDailyCertificates = value.max_daily_certificates;
    if (!Number.isSafeInteger(maxAgents) || maxAgents <= 0 || !Number.isSafeInteger(maxDailyCertificates) || maxDailyCertificates <= 0) return null;
    return { max_agents: maxAgents, max_daily_certificates: maxDailyCertificates };
}

function initialize() {
    const body = document.body;
    const mode = body.dataset.mode || "home";
    const offline = body.dataset.offline === "true";
    let locale = LOCALES.has(body.dataset.lang) ? body.dataset.lang : "en";
    const state = {
        adminKey: null, agentKey: null, registration: null, statement: null, grant: null, grantVisibility: null,
        token: "", issuer: "", limits: null, workspace: null, agents: [], certificates: [], artifact: null, verification: null,
        erc8004Config: null, erc8004Record: null,
    };
    let draftRevision = 0;
    let artifactReadRevision = 0;
    let sessionRevision = 0;
    let adminReadRevision = 0;
    let erc8004Revision = 0;
    let erc8004Busy = false;
    const element = (id) => document.getElementById(id);
    const t = (key, values) => message(locale, key, values);
    const docFragment = () => mode === "docs" && typeof window !== "undefined" && DOC_FRAGMENTS.has(window.location.hash) ? window.location.hash : "";
    const setStatus = (id, value, error = false) => {
        const node = element(id);
        if (!node) return;
        node.textContent = value;
        node.classList.toggle("is-error", error);
    };

    function translate() {
        document.documentElement.lang = locale;
        document.querySelectorAll("[data-i18n]").forEach((node) => { node.textContent = t(node.dataset.i18n); });
        document.querySelectorAll("[data-ap-link]").forEach((node) => {
            node.href = localizedPath(`/apostille${node.dataset.apLink}`, locale);
        });
        document.querySelectorAll("[data-iff-monitor]").forEach((node) => {
            node.href = `${locale === "en" ? "" : `/${locale}`}/monitor`;
        });
        if (offline) {
            document.querySelector(".primary-nav").hidden = true;
            const navigation = document.querySelector("footer nav");
            const spec = document.createElement("a");
            spec.href = "./core-0.1.md";
            spec.textContent = t("navDocs");
            navigation.replaceChildren(spec);
        }
        element("locale-select").value = locale;
        element("locale-select").setAttribute("aria-label", t("language"));
        if (state.verification) {
            if (state.verification.erc8004) renderERC8004Verification(state.verification.result, false);
            else renderVerification(state.verification.result, state.verification.artifactMatch, false);
        }
    }

    document.querySelectorAll("[data-view]").forEach((view) => { view.hidden = view.dataset.view !== mode; });
    document.querySelector(`[data-nav="${mode}"]`)?.setAttribute("aria-current", "page");
    if (mode === "console") document.querySelector('[data-nav="console"]')?.setAttribute("aria-current", "page");
    translate();
    // The target was hidden until the localized docs view became visible.
    if (docFragment()) element(docFragment().slice(1))?.scrollIntoView({ block: "start" });

    const hasLocalWork = () => Boolean(state.adminKey || state.agentKey || state.token || state.artifact || state.statement);
    // The browser's native guard covers links, reload, Back and closing the
    // tab, without persisting keys or tokens. It needs prior user interaction.
    if (!offline && mode === "console" && typeof window !== "undefined") window.addEventListener("beforeunload", (event) => {
        if (!hasLocalWork()) return;
        event.preventDefault();
        event.returnValue = "";
    });

    element("locale-select")?.addEventListener("change", (event) => {
        const selected = event.target.value;
        if (offline) { locale = selected; translate(); }
        else {
            // If the browser's exit guard is canceled, the current page and
            // its language selector must still describe the same locale.
            event.target.value = locale;
            if (selected !== locale) window.location.assign(localizedPath(window.location.pathname + docFragment(), selected));
        }
    });

    function keyBackup(file) {
        return { protocol: file.protocol, key_id: file.key_id, public_key: file.public_key, seed: file.seed };
    }

    function downloadJSON(name, value) {
        const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = name;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 0);
    }

    async function readJSONFile(file, cap) {
        if (file.size > cap) throw new Error(t("jsonTooLarge", { size: formatBytes(cap) }));
        return parseStrict(decodeBytes(new Uint8Array(await file.arrayBuffer())));
    }

    async function api(path, options = {}, authenticated = false) {
        return requestAPI(path, options, { token: state.token, authenticated, translate: (code) => quotaErrorMessage(locale, code, state.limits) });
    }

    function updateSignerButtons() {
        if (element("admin-login")) element("admin-login").disabled = !state.adminKey;
        if (element("agent-register")) element("agent-register").disabled = !(state.adminKey && state.agentKey && state.token);
        const canSign = Boolean(state.agentKey && state.registration && state.artifact);
        if (element("statement-create")) element("statement-create").disabled = !canSign;
        if (element("grant-create")) element("grant-create").disabled = !(state.statement && state.adminKey);
        if (element("certificate-submit")) element("certificate-submit").disabled = !canSubmit();
        updateERC8004Buttons();
    }

    function selectedVisibility() {
        return document.querySelector('input[name="visibility"]:checked')?.value;
    }

    function canSubmit() {
        return Boolean(state.statement && state.grant && state.token && state.grantVisibility === selectedVisibility());
    }

    function clearAuthenticatedState({ preserveInputs = false } = {}) {
        sessionRevision += 1;
        state.token = "";
        state.workspace = null;
        state.agents = [];
        state.certificates = [];
        state.registration = null;
        state.erc8004Record = null;
        erc8004Revision += 1;
        clearSignedDraft();
        element("workspace-panels").hidden = true;
        if (!preserveInputs) {
            state.agentKey = null;
            artifactReadRevision += 1;
            state.artifact = null;
            element("agent-readout").hidden = true;
            element("artifact-summary").textContent = t("noFile");
            if (element("artifact-input")) element("artifact-input").value = "";
            if (element("agent-import")) element("agent-import").value = "";
        }
        updateSignerButtons();
    }

    function clearSignedDraft() {
        state.statement = null;
        invalidateGrant();
    }

    function invalidateGrant() {
        // Cancellation must survive an async signer finishing after an input change.
        draftRevision += 1;
        state.grant = null;
        state.grantVisibility = null;
        updateSignerButtons();
    }

    async function replaceAdminKey(read, status, downloadName = "") {
        const revision = ++adminReadRevision;
        clearAuthenticatedState();
        state.adminKey = null;
        element("admin-key-id").textContent = "";
        element("admin-readout").hidden = true;
        updateSignerButtons();
        try {
            const file = await read();
            if (revision !== adminReadRevision) return;
            const signer = await importKeyFile(file);
            if (revision !== adminReadRevision) return;
            state.adminKey = signer;
            if (downloadName) downloadJSON(downloadName, keyBackup(file));
            element("admin-key-id").textContent = signer.keyID;
            element("admin-readout").hidden = false;
            setStatus("auth-status", t(status));
            updateSignerButtons();
        } catch (error) { if (revision === adminReadRevision) setStatus("auth-status", error.message, true); }
    }

    async function loadAgentFile(file) {
        if (!file) return;
        const revision = sessionRevision;
        const parsed = await readJSONFile(file, MAX_KEY_FILE_BYTES);
        const signer = await importKeyFile(parsed);
        if (revision !== sessionRevision) return;
        clearSignedDraft();
        state.agentKey = signer;
        element("agent-key-id").textContent = state.agentKey.keyID;
        element("agent-readout").hidden = false;
        const registered = state.agents.find((agent) => agent.key_id === state.agentKey.keyID && !agent.revoked_at);
        state.registration = registered ? { delegation: registered.delegation, acceptance: registered.acceptance } : null;
        setStatus("agent-status", t("agentImported"));
        renderAgents();
        updateSignerButtons();
    }

    async function loadWorkspace(revision = sessionRevision) {
        if (revision !== sessionRevision || !state.token) return false;
        let data;
        try { data = await api("/me", {}, true); }
        catch (error) { if (revision !== sessionRevision) return false; throw error; }
        if (revision !== sessionRevision) return false;
        state.workspace = data.workspace;
        state.agents = data.agents || [];
        state.certificates = data.certificates || [];
        if (state.agentKey) {
            const active = state.agents.find((agent) => agent.key_id === state.agentKey.keyID && !agent.revoked_at && Date.parse(agent.expires_at) > Date.now());
            if (!active) clearSignedDraft();
            state.registration = active ? { delegation: active.delegation, acceptance: active.acceptance } : null;
        }
        element("workspace-name").value = state.workspace.name || "";
        element("workspace-public").checked = Boolean(state.workspace.is_public);
        element("workspace-panels").hidden = false;
        renderProfileLink();
        renderAgents();
        renderERC8004Agents();
        renderCertificates();
        updateSignerButtons();
        return true;
    }

    function renderProfileLink() {
        const container = element("workspace-public-link");
        if (!container) return;
        container.replaceChildren();
        container.hidden = !state.workspace?.is_public;
        if (container.hidden) return;
        const link = document.createElement("a");
        link.className = "button secondary";
        link.textContent = t("shareProfile");
        link.href = localizedPath(`/apostille/organizations/${encodeURIComponent(state.workspace.public_id)}`, locale);
        container.append(link);
    }

    function button(label, onClick, variant = "secondary") {
        const control = document.createElement("button");
        control.type = "button";
        control.className = `button ${variant}`;
        control.textContent = label;
        control.addEventListener("click", onClick);
        return control;
    }

    function record(title, fields) {
        const article = document.createElement("article");
        article.className = "record-row";
        const copy = document.createElement("div");
        const heading = document.createElement("strong");
        heading.textContent = title;
        copy.append(heading);
        fields.forEach((field) => {
            const code = document.createElement("code");
            code.textContent = field;
            copy.append(code);
        });
        const actions = document.createElement("div");
        actions.className = "record-actions";
        article.append(copy, actions);
        return { article, actions };
    }

    function renderAgents() {
        const list = element("agent-list");
        if (!list) return;
        list.replaceChildren();
        if (!state.agents.length) {
            const empty = document.createElement("p"); empty.textContent = t("emptyAgents"); list.append(empty); return;
        }
        state.agents.forEach((agent) => {
            const item = record(agent.name, [agent.key_id, agent.expires_at]);
            const matchingKey = state.agentKey?.keyID === agent.key_id;
            if (!agent.revoked_at) {
                item.actions.append(button(matchingKey ? t("activeAgent") : t("useAgent"), () => {
                    if (!matchingKey) { setStatus("agent-status", t("agentImported"), true); return; }
                    clearSignedDraft();
                    state.registration = { delegation: agent.delegation, acceptance: agent.acceptance };
                    renderAgents(); updateSignerButtons();
                }));
                item.actions.append(button(t("revoke"), async () => {
                    const revision = sessionRevision;
                    try { await api(`/agents/${encodeURIComponent(agent.id)}/revoke`, { method: "POST" }, true); if (await loadWorkspace(revision)) setStatus("agent-status", t("agentRevoked")); }
                    catch (error) { if (revision === sessionRevision) setStatus("agent-status", error.message, true); }
                }));
            }
            item.article.classList.toggle("is-inactive", Boolean(agent.revoked_at));
            list.append(item.article);
        });
    }

    function selectedERC8004Agent() {
        return state.agents.find((agent) => agent.id === element("erc8004-agent")?.value);
    }

    function activeERC8004Agent() {
        const agent = selectedERC8004Agent();
        return agent && !agent.revoked_at && Date.parse(agent.expires_at) > Date.now() ? agent : null;
    }

    function selectedERC8004Network() {
        return state.erc8004Config?.networks?.find((network) => `${network.chain_id}:${network.registry_address}` === element("erc8004-network")?.value);
    }

    function updateERC8004Buttons() {
        const token = element("erc8004-token")?.value || "";
        let tokenValid = false;
        try { tokenValid = /^(0|[1-9][0-9]{0,77})$/.test(token) && BigInt(token) < (1n << 256n); } catch {}
        const available = Boolean(!erc8004Busy && state.token && state.adminKey && activeERC8004Agent() && selectedERC8004Network() && tokenValid);
        if (element("erc8004-create")) element("erc8004-create").disabled = !available;
        if (element("erc8004-load")) element("erc8004-load").disabled = erc8004Busy || !Boolean(state.token && selectedERC8004Agent());
    }

    function renderERC8004Agents() {
        const select = element("erc8004-agent");
        if (!select) return;
        const previous = select.value;
        select.replaceChildren();
        state.agents.forEach((agent) => {
            const option = document.createElement("option"); option.value = agent.id; option.textContent = `${agent.name} · ${agent.id}${agent.revoked_at || Date.parse(agent.expires_at) <= Date.now() ? ` · ${t("historical")}` : ""}`; select.append(option);
        });
        if ([...select.children].some((option) => option.value === previous)) select.value = previous;
        updateERC8004Buttons();
    }

    function showERC8004Record(record) {
        state.erc8004Record = record;
        const container = element("erc8004-record");
        if (!container) return;
        container.replaceChildren();
        const item = recordRow(record.id, [record.created_at, record.expires_at]);
        item.actions.append(button(t("erc8004Download"), () => downloadJSON(`apostille-erc8004-${record.id}.json`, record.document)));
        container.append(item.article);
    }

    // Keep this alias separate from the binding response named `record`.
    const recordRow = record;

    async function loadERC8004Config() {
        const config = await api("/erc8004/config");
        if (config.profile !== ERC8004_PROTOCOL || config.enabled !== true || !Array.isArray(config.networks) || !config.networks.length) return;
        state.erc8004Config = config;
        const network = element("erc8004-network"); network.replaceChildren();
        config.networks.forEach((item) => {
            const option = document.createElement("option"); option.value = `${item.chain_id}:${item.registry_address}`; option.textContent = `${item.chain_id} · ${item.registry_address}`; network.append(option);
        });
        element("erc8004-panel").hidden = false;
        renderERC8004Agents();
    }

    async function downloadStoredBundle(certificate) {
        const revision = sessionRevision;
        const bundle = await api(`/certificates/${encodeURIComponent(certificate.id)}/bundle`, {}, true);
        if (revision !== sessionRevision) return;
        downloadJSON(`apostille-bundle-${certificate.id}.json`, bundle);
    }

    function renderCertificates() {
        const list = element("certificate-list");
        if (!list) return;
        list.replaceChildren();
        if (!state.certificates.length) {
            const empty = document.createElement("p"); empty.textContent = t("emptyCertificates"); list.append(empty); return;
        }
        state.certificates.forEach((certificate) => {
            const item = record(certificate.id, [certificate.created_at, certificate.is_public ? t("public") : t("private")]);
            item.actions.append(button(t("downloadBundle"), () => {
                const revision = sessionRevision;
                return downloadStoredBundle(certificate).catch((error) => { if (revision === sessionRevision) setStatus("issue-status", error.message, true); });
            }));
            if (certificate.is_public) {
                const link = document.createElement("a");
                link.className = "button secondary";
                link.textContent = t("share");
                link.href = publicCertificatePath(certificate, locale);
                item.actions.append(link, button(t("hide"), async () => {
                    const revision = sessionRevision;
                    try { await api(`/certificates/${encodeURIComponent(certificate.id)}/hide`, { method: "POST" }, true); if (await loadWorkspace(revision)) setStatus("issue-status", t("certificateHidden")); }
                    catch (error) { if (revision === sessionRevision) setStatus("issue-status", error.message, true); }
                }));
            }
            list.append(item.article);
        });
    }

    element("admin-generate")?.addEventListener("click", () => replaceAdminKey(generateKeyFile, "keyGenerated", "apostille-admin-key.json"));

    element("admin-import")?.addEventListener("change", (event) => {
        const file = event.target.files?.[0];
        if (!file) return;
        return replaceAdminKey(() => readJSONFile(file, MAX_KEY_FILE_BYTES), "keyImported");
    });

    element("admin-login")?.addEventListener("click", async () => {
        const adminKey = state.adminKey;
        const expectedIssuer = state.issuer;
        if (!adminKey) return;
        clearAuthenticatedState({ preserveInputs: true });
        const revision = sessionRevision;
        try {
            setStatus("auth-status", t("loginWorking"));
            const challenge = await api("/auth/challenges", { method: "POST", body: JSON.stringify({ public_key: adminKey.publicKey }) });
            if (revision !== sessionRevision) return;
            const loginMessage = validateLoginChallenge(challenge, adminKey.keyID, expectedIssuer);
            const signature = await signLogin(loginMessage, adminKey, expectedIssuer);
            if (revision !== sessionRevision) return;
            const login = await api("/auth/verify", { method: "POST", body: JSON.stringify({ challenge_id: challenge.challenge_id, message: challenge.message, signature }) });
            if (revision !== sessionRevision) return;
            state.token = login.access_token;
            if (await loadWorkspace(revision)) setStatus("auth-status", t("loginComplete"));
        } catch (error) {
            if (revision !== sessionRevision) return;
            clearAuthenticatedState({ preserveInputs: true });
            setStatus("auth-status", error.message, true);
        }
    });

    element("workspace-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const revision = sessionRevision;
        try {
            const workspace = await api("/workspace", { method: "PUT", body: JSON.stringify({ name: element("workspace-name").value, is_public: element("workspace-public").checked }) }, true);
            if (revision !== sessionRevision) return;
            state.workspace = workspace;
            renderProfileLink();
            setStatus("workspace-status", t("profileSaved"));
        } catch (error) { if (revision === sessionRevision) setStatus("workspace-status", error.message, true); }
    });

    element("agent-generate")?.addEventListener("click", async () => {
        const revision = sessionRevision;
        try {
            const generated = keyBackup(await generateKeyFile());
            const signer = await importKeyFile(generated);
            if (revision !== sessionRevision) return;
            clearSignedDraft();
            state.agentKey = signer;
            state.registration = null;
            downloadJSON("apostille-agent-key.json", generated);
            element("agent-key-id").textContent = state.agentKey.keyID;
            element("agent-readout").hidden = false;
            setStatus("agent-status", t("agentKeyReady")); renderAgents(); updateSignerButtons();
        } catch (error) { if (revision === sessionRevision) setStatus("agent-status", error.message, true); }
    });

    element("agent-import")?.addEventListener("change", (event) => {
        const revision = sessionRevision;
        return loadAgentFile(event.target.files?.[0]).catch((error) => { if (revision === sessionRevision) setStatus("agent-status", error.message, true); });
    });

    element("agent-register")?.addEventListener("click", async () => {
        const revision = sessionRevision;
        try {
            const name = element("agent-name").value.trim();
            if (!name) throw new Error(t("agentNameRequired"));
            clearSignedDraft();
            const agentKey = state.agentKey;
            const registration = await createRegistration(state.adminKey, agentKey, state.issuer, 30);
            if (revision !== sessionRevision || agentKey !== state.agentKey) return;
            state.registration = registration;
            const registered = await api("/agents", { method: "POST", body: JSON.stringify({ name, ...registration }) }, true);
            if (revision !== sessionRevision) return;
            downloadJSON(`apostille-registration-${registered.id}.json`, registration);
            if (await loadWorkspace(revision)) setStatus("agent-status", t("agentRegistered"));
        } catch (error) { if (revision === sessionRevision) setStatus("agent-status", error.message, true); }
    });

    for (const id of ["erc8004-agent", "erc8004-network", "erc8004-token"]) element(id)?.addEventListener(id === "erc8004-token" ? "input" : "change", () => {
        erc8004Revision += 1;
        state.erc8004Record = null;
        element("erc8004-record")?.replaceChildren();
        setStatus("erc8004-status", "");
        updateERC8004Buttons();
    });

    element("erc8004-create")?.addEventListener("click", async () => {
        if (erc8004Busy) return;
        const revision = ++erc8004Revision, session = sessionRevision;
        const agent = activeERC8004Agent(), network = selectedERC8004Network(), admin = state.adminKey;
        if (!agent || !network || !admin) return;
        erc8004Busy = true; updateERC8004Buttons();
        try {
            const wallet = globalThis.ethereum;
            if (!wallet || typeof wallet.request !== "function") throw new Error(t("erc8004WalletMissing"));
            setStatus("erc8004-status", t("erc8004WalletWorking"));
            const accounts = await wallet.request({ method: "eth_requestAccounts" });
            if (revision !== erc8004Revision || session !== sessionRevision) return;
            const owner = accounts?.[0]?.toLowerCase();
            if (!/^0x[0-9a-f]{40}$/.test(owner || "") || /^0x0{40}$/.test(owner)) throw new Error(t("erc8004WalletInvalid"));
            const walletChain = await wallet.request({ method: "eth_chainId" });
            if (revision !== erc8004Revision || session !== sessionRevision) return;
            if (typeof walletChain !== "string" || BigInt(walletChain) !== BigInt(network.chain_id)) throw new Error(t("erc8004WrongNetwork", { chain: network.chain_id }));
            const identity = { chain_id: network.chain_id, registry_address: network.registry_address, erc8004_agent_id: element("erc8004-token").value, owner_address: owner };
            const registration = { delegation: agent.delegation, acceptance: agent.acceptance };
            const request = await createERC8004Request(admin, registration, identity, state.issuer, new Date());
            if (revision !== erc8004Revision || session !== sessionRevision || admin !== state.adminKey) return;
            const message = await erc8004OwnerMessage(request);
            if (revision !== erc8004Revision || session !== sessionRevision || admin !== state.adminKey) return;
            const messageHex = `0x${Array.from(new TextEncoder().encode(message), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
            const ownerSignature = await wallet.request({ method: "personal_sign", params: [messageHex, owner] });
            if (revision !== erc8004Revision || session !== sessionRevision) return;
            if (typeof ownerSignature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(ownerSignature)) throw new Error(t("erc8004WalletInvalid"));
            const normalizedSignature = ownerSignature.toLowerCase();
            const response = await api(`/agents/${encodeURIComponent(agent.id)}/erc8004`, { method: "POST", body: JSON.stringify({ request, owner_signature: normalizedSignature }) }, true);
            if (revision !== erc8004Revision || session !== sessionRevision) return;
            const checked = await verifyERC8004Binding(response.document, { issuer: state.issuer, now: new Date() });
            if (revision !== erc8004Revision || session !== sessionRevision) return;
            if (!response || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(response.id) || response.agent_id !== agent.id || checked.request.agent_id !== agent.id || response.created_at !== checked.checked_at || response.expires_at !== checked.expires_at) throw new Error(t("invalid_binding_response"));
            const binding = parseStrict(decodeBytes(unb64(response.document.binding.payload)));
            if (canonical(binding.request) !== canonical(request) || binding.owner_signature !== normalizedSignature) throw new Error(t("invalid_binding_response"));
            showERC8004Record(response);
            downloadJSON(`apostille-erc8004-${response.id}.json`, response.document);
            setStatus("erc8004-status", t("erc8004Created"));
        } catch (error) { if (revision === erc8004Revision && session === sessionRevision) setStatus("erc8004-status", error.message, true); }
        finally { erc8004Busy = false; updateERC8004Buttons(); }
    });

    element("erc8004-load")?.addEventListener("click", async () => {
        if (erc8004Busy) return;
        const revision = ++erc8004Revision, session = sessionRevision, agent = selectedERC8004Agent();
        if (!agent) return;
        erc8004Busy = true; updateERC8004Buttons();
        try {
            const response = await api(`/agents/${encodeURIComponent(agent.id)}/erc8004`, {}, true);
            if (revision !== erc8004Revision || session !== sessionRevision) return;
            const checked = await verifyERC8004Binding(response.document, { issuer: state.issuer, now: new Date() });
            if (revision !== erc8004Revision || session !== sessionRevision) return;
            if (response.agent_id !== agent.id || checked.request.agent_id !== agent.id || response.created_at !== checked.checked_at || response.expires_at !== checked.expires_at) throw new Error(t("invalid_binding_response"));
            showERC8004Record(response);
            setStatus("erc8004-status", t("erc8004Loaded"));
        } catch (error) { if (revision === erc8004Revision && session === sessionRevision) setStatus("erc8004-status", error.message, true); }
        finally { erc8004Busy = false; updateERC8004Buttons(); }
    });

    element("artifact-input")?.addEventListener("change", async (event) => {
        const revision = ++artifactReadRevision;
        clearSignedDraft();
        state.artifact = null;
        updateSignerButtons();
        try {
            const file = event.target.files?.[0];
            if (!file) { element("artifact-summary").textContent = t("noFile"); setStatus("issue-status", ""); return; }
            if (file.size > MAX_ARTIFACT_BYTES) throw new Error(t("fileTooLarge"));
            const bytes = new Uint8Array(await file.arrayBuffer());
            if (revision !== artifactReadRevision) return;
            state.artifact = { name: file.name, mediaType: file.type || "application/octet-stream", bytes };
            element("artifact-summary").textContent = t("fileSelected", { name: file.name, size: formatBytes(file.size) });
            updateSignerButtons();
        } catch (error) {
            if (revision !== artifactReadRevision) return;
            state.artifact = null; clearSignedDraft(); setStatus("issue-status", error.message, true); updateSignerButtons();
        }
    });

    element("statement-create")?.addEventListener("click", async () => {
        clearSignedDraft();
        const revision = draftRevision;
        try {
            const statement = await createStatement(state.artifact.bytes, state.artifact.mediaType, state.agentKey, state.registration);
            if (revision !== draftRevision) return;
            state.statement = statement;
            downloadJSON("apostille-statement.json", state.statement);
            setStatus("issue-status", t("statementReady")); updateSignerButtons();
        } catch (error) { if (revision === draftRevision) setStatus("issue-status", error.message, true); }
    });

    element("grant-create")?.addEventListener("click", async () => {
        invalidateGrant();
        const revision = draftRevision;
        try {
            const visibility = selectedVisibility();
            const { statement, registration, adminKey, issuer } = state;
            const grant = await createGrant(statement, registration, adminKey, issuer, visibility);
            if (revision !== draftRevision || visibility !== selectedVisibility() || statement !== state.statement || registration !== state.registration || adminKey !== state.adminKey || issuer !== state.issuer) return;
            state.grant = grant;
            state.grantVisibility = visibility;
            downloadJSON("apostille-publication-grant.json", state.grant);
            setStatus("issue-status", t("grantReady", { visibility })); updateSignerButtons();
        } catch (error) { if (revision === draftRevision) setStatus("issue-status", error.message, true); }
    });

    document.querySelectorAll('input[name="visibility"]').forEach((control) => control.addEventListener("change", () => {
        invalidateGrant();
    }));

    element("certificate-submit")?.addEventListener("click", async () => {
        if (!canSubmit()) return;
        const revision = draftRevision;
        const session = sessionRevision;
        try {
            const certificate = await api("/submissions", { method: "POST", body: JSON.stringify({ statement: state.statement, grant: state.grant }) }, true);
            if (session !== sessionRevision) return;
            downloadJSON(`apostille-bundle-${certificate.id}.json`, certificate.bundle);
            if (revision === draftRevision) clearSignedDraft();
            if (await loadWorkspace(session)) setStatus("issue-status", t("certificateIssued"));
        } catch (error) { if (session === sessionRevision) setStatus("issue-status", error.message, true); }
    });

    function resultValue(value) {
        const aliases = { valid_at_evaluation_time: "pass", accepted_by_policy: "pass", valid: "pass", pinned: "pinMatched", within_validity: "withinValidity", issuer_checked: "issuerChecked", unproven: "unprovenValue", not_established: "notEstablished", not_yet_valid: "notYetValid", not_provided: "notProvided", current_revocation_unknown: "unknown" };
        return t(aliases[value] || value) || value;
    }

    function renderVerification(result, artifactMatch, focus = true) {
        const headline = verificationHeadline(result, artifactMatch);
        const titleKeys = { failure: "verifyFail", historical: "verifyHistorical", pinned: "verifyPinned", untrusted: "verifyUntrusted" };
        element("result-title").textContent = t(titleKeys[headline]);
        element("result-badge").textContent = headline === "failure" ? t("mismatch") : headline === "historical" ? resultValue(result.freshness) : headline === "pinned" ? t("pinMatched") : t("untrusted");
        element("result-badge").className = `result-badge ${headline === "failure" ? "is-fail" : "is-warn"}`;
        const checks = [
            [t("checkIntegrity"), result.artifact_integrity],
            [t("checkIssuer"), result.issuer_trust],
            [t("checkFreshness"), result.freshness],
            [t("checkAgent"), result.authorization_policy],
            [t("checkArtifact"), artifactMatch === null ? "not_provided" : artifactMatch ? "valid" : "mismatch"],
            ["certificate_scope", result.certificate_scope],
            ["agent_binding", result.agent_binding],
            ["organization_binding", result.organization_binding],
            ["content_truth", result.content_truth],
            ["provider_evidence", result.provider_evidence],
            ["log_inclusion", result.log_inclusion],
            ["anchor", result.anchor],
            ["time_basis", result.time_basis],
        ];
        const list = element("check-list"); list.replaceChildren();
        checks.forEach(([label, value]) => {
            const row = document.createElement("div"), name = document.createElement("span"), status = document.createElement("strong");
            row.className = "check-row";
            name.textContent = label; status.textContent = resultValue(value); status.className = ["valid", "valid_at_evaluation_time", "accepted_by_policy"].includes(value) ? "is-pass" : value === "mismatch" ? "is-fail" : "is-warn";
            row.append(name, status); list.append(row);
        });
        element("result-id-label").textContent = "certificate_id";
        element("result-digest-label").textContent = "artifact_sha256";
        element("result-cert-id").textContent = result.certificate_id || "—";
        element("result-issuer").textContent = result.issuer;
        element("result-key").textContent = result.issuer_key_id;
        element("result-digest").textContent = result.statement.artifact_sha256;
        element("result-note").textContent = t("revocationNote");
        element("verification-result").hidden = false;
        if (focus) element("verification-result").focus();
    }

    function renderERC8004Verification(result, focus = true) {
        const historical = result.freshness === "expired" || result.freshness === "not_yet_valid";
        element("result-title").textContent = historical ? t("erc8004VerifyHistorical") : result.issuer_trust === "pinned" ? t("erc8004VerifyPinned") : t("erc8004VerifyUnknown");
        element("result-badge").textContent = historical ? resultValue(result.freshness) : result.issuer_trust === "pinned" ? t("pinMatched") : t("unknown");
        element("result-badge").className = "result-badge is-warn";
        const checks = [
            [t("erc8004Integrity"), result.artifact_integrity],
            [t("checkIssuer"), result.issuer_trust],
            [t("checkFreshness"), result.freshness],
            [t("erc8004ProviderEvidence"), result.provider_evidence],
            [t("erc8004CurrentOwnership"), result.current_ownership],
            [t("erc8004Organization"), result.organization_binding],
            [t("erc8004Payment"), result.payment_authority],
        ];
        const list = element("check-list"); list.replaceChildren();
        checks.forEach(([label, value]) => {
            const row = document.createElement("div"), name = document.createElement("span"), status = document.createElement("strong");
            row.className = "check-row"; name.textContent = label; status.textContent = resultValue(value);
            status.className = ["valid", "pinned", "within_validity"].includes(value) ? "is-pass" : "is-warn";
            row.append(name, status); list.append(row);
        });
        element("result-id-label").textContent = "agent_id";
        element("result-digest-label").textContent = "identity_tuple";
        element("result-cert-id").textContent = result.request.agent_id;
        element("result-issuer").textContent = result.issuer;
        element("result-key").textContent = result.issuer_key_id;
        element("result-digest").textContent = `${result.request.chain_id}:${result.request.registry_address}:${result.request.erc8004_agent_id}`;
        element("result-note").textContent = t("erc8004Boundary");
        element("verification-result").hidden = false;
        if (focus) element("verification-result").focus();
    }

    function localDateTimeValue(date) {
        const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
        return local.toISOString().slice(0, 19);
    }
    if (element("verify-time")) element("verify-time").value = localDateTimeValue(new Date());

    element("verify-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const bundleFile = element("verify-bundle").files?.[0];
            if (!bundleFile) {
                state.verification = null;
                element("verification-result").hidden = true;
                setStatus("verify-status", "");
                return;
            }
            const bundle = await readJSONFile(bundleFile, MAX_INPUT_BYTES);
            let policy;
            try { policy = validateTrustPolicy(element("verify-issuer").value, element("verify-key").value); }
            catch { throw new Error(t("trustPair")); }
            const when = element("verify-time").value;
            if (!when) throw new Error(t("timeRequired"));
            const options = { at: new Date(when).toISOString() };
            if (policy.issuer) { options.issuer = policy.issuer; options.keyIDs = [policy.keyID]; }
            const erc8004 = bundle?.protocol === ERC8004_PROTOCOL;
            const result = erc8004
                ? await verifyERC8004Binding(bundle, { issuer: policy.issuer, trustedKeyIDs: policy.keyID ? [policy.keyID] : [], now: new Date(when).toISOString() })
                : await verifyBundle(bundle, options);
            const original = element("verify-artifact").files?.[0];
            if (original?.size > MAX_ARTIFACT_BYTES) throw new Error(t("fileTooLarge"));
            const artifactMatch = erc8004 ? null : original ? await verifyArtifact(result, new Uint8Array(await original.arrayBuffer())) : null;
            state.verification = { result, artifactMatch, erc8004 };
            if (erc8004) renderERC8004Verification(result); else renderVerification(result, artifactMatch);
            setStatus("verify-status", "");
        } catch (error) {
            state.verification = null; element("verification-result").hidden = true;
            setStatus("verify-status", `${t("verifyFail")}: ${error.message}`, true);
        }
    });

    function appendFact(container, label, value) {
        const row = document.createElement("div"), name = document.createElement("span"), content = document.createElement("code");
        name.textContent = label; content.textContent = String(value ?? "—"); row.append(name, content); container.append(row);
    }

    async function loadKeys() {
        const data = await api("/keys"), container = element("key-directory"); container.replaceChildren();
        (data.keys || []).forEach((key) => {
            const card = document.createElement("article"); appendFact(card, "key_id", key.key_id); appendFact(card, "public_key", key.public_key); appendFact(card, "algorithm", key.algorithm); container.append(card);
        });
        if (!(data.keys || []).length) { const p = document.createElement("p"); p.textContent = t("serviceUnavailable"); container.append(p); }
    }

    function routeID() {
        return decodeURIComponent(window.location.pathname.replace(/\/$/, "").split("/").pop());
    }

    async function loadPublicCertificate() {
        const data = await api(`/public/certificates/${encodeURIComponent(routeID())}`);
        const checked = await verifyBundle(data.bundle);
        const container = element("public-certificate-content"); container.replaceChildren();
        const sheet = document.createElement("article"); sheet.className = "certificate-sheet";
        const intro = document.createElement("p"); intro.textContent = t("publicBundleIntro"); sheet.append(intro);
        appendFact(sheet, "public_id", data.public_id); appendFact(sheet, t("createdAt"), data.created_at);
        for (const field of ["certificate_id", "issuer", "issuer_key_id", "issuer_trust", "agent_binding", "organization_binding", "content_truth"]) appendFact(sheet, field, checked[field]);
        appendFact(sheet, "artifact_sha256", checked.statement.artifact_sha256);
        appendFact(sheet, "artifact_size", checked.statement.artifact_size);
        const boundary = document.createElement("p"); boundary.textContent = t("heroBoundary"); sheet.append(boundary);
        const details = document.createElement("details"), summary = document.createElement("summary");
        summary.textContent = "Signed bundle JSON";
        const serialized = document.createElement("pre"); serialized.textContent = JSON.stringify(data.bundle, null, 2); details.append(summary, serialized); sheet.append(details);
        sheet.append(button(t("downloadPublicBundle"), () => downloadJSON(`apostille-public-${data.public_id}.json`, data.bundle), "primary"));
        container.append(sheet);
    }

    async function loadPublicOrganization() {
        const data = await api(`/public/organizations/${encodeURIComponent(routeID())}`), profile = data.profile;
        const container = element("public-organization-content"); container.replaceChildren();
        const badge = document.createElement("strong"); badge.className = "self-declared"; badge.textContent = t("selfDeclared"); container.append(badge);
        const title = document.createElement("h2"); title.textContent = profile.name; container.append(title);
        appendFact(container, "public_id", profile.public_id); appendFact(container, t("createdAt"), profile.created_at); appendFact(container, "organization_binding", data.organization_binding);
    }

    if (shouldFetch(mode, offline)) {
        if (mode === "keys") loadKeys().catch(() => { element("key-directory").textContent = t("serviceUnknown"); });
        else if (mode === "certificate") loadPublicCertificate().catch(() => { element("public-certificate-content").textContent = t("loadFailed"); });
        else if (mode === "organization") loadPublicOrganization().catch(() => { element("public-organization-content").textContent = t("loadFailed"); });
        else api("/status").then((status) => {
            state.issuer = status.issuer;
            state.limits = statusLimits(status.limits);
            const strip = element("service-strip"); strip.hidden = false; strip.textContent = status.enabled ? t("serviceReady", { issuer: status.issuer }) : t("serviceUnavailable");
            if (mode === "console" && status.enabled) loadERC8004Config().catch(() => { element("erc8004-panel").hidden = true; });
        }).catch(() => { const strip = element("service-strip"); strip.hidden = false; strip.textContent = t("serviceUnknown"); });
    }
}

if (typeof document !== "undefined") initialize();
