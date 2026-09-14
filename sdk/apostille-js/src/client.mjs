import {
    MAX_INPUT_BYTES, PROTOCOL, canonical, decodeBytes, envelopeDigest, fingerprint,
    parseStrict, signLogin, unb64, validIssuer, validateLoginChallenge, verifyBundle, verifyEnvelope, verifyRegistration,
} from "./apostille-core.mjs";
import { DEFAULT_TIMEOUT_MS, MAX_RESPONSE_BYTES } from "./apostille-http.mjs";
import { ERC8004_PROTOCOL, erc8004OwnerMessage, verifyERC8004Binding } from "./apostille-erc8004.mjs";

const encoder = new TextEncoder();
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TOKEN = /^[A-Za-z0-9._~-]{1,4096}$/;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,79}$/;

export class ApostilleAPIError extends Error {
    constructor(status, code, retryAfter = null) {
        super(`Apostille API: ${code} (${status})`);
        this.name = "ApostilleAPIError";
        this.status = status;
        this.code = code;
        this.retryAfter = retryAfter;
    }
}
function need(value, code) { if (!value) throw new ApostilleAPIError(0, code); }
function id(value) { need(typeof value === "string" && ID.test(value), "invalid_id"); return value; }
function snapshot(value) {
    const raw = canonical(value);
    need(encoder.encode(raw).length <= MAX_INPUT_BYTES, "request_too_large");
    return { raw, value: parseStrict(raw) };
}
function validateBaseURL(value, allowLocal) {
    need(typeof value === "string" && value.length <= 2048 && !/[\s\\%?#]/.test(value), "invalid_base_url");
    let url;
    try { url = new URL(value); } catch { throw new ApostilleAPIError(0, "invalid_base_url"); }
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    need((url.protocol === "https:" || (allowLocal && local && url.protocol === "http:")) && !url.username && !url.password && url.origin + url.pathname === value && !url.pathname.split("/").some((part) => part === "." || part === ".."), "invalid_base_url");
    const base = value.replace(/\/$/, "");
    need(base.endsWith("/api/apostille/v1"), "invalid_base_url");
    return base;
}
async function readResponse(response) {
    const contentLength = response.headers.get("content-length");
    if (contentLength && Number(contentLength) > MAX_RESPONSE_BYTES) {
        await response.body?.cancel();
        throw new ApostilleAPIError(response.status, "response_too_large");
    }
    need(response.body, "invalid_response");
    const reader = response.body.getReader(), chunks = [];
    let size = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new ApostilleAPIError(response.status, "response_too_large"); }
            chunks.push(value);
        }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    try { return JSON.parse(decodeBytes(bytes)); } catch { throw new ApostilleAPIError(response.status, "invalid_response"); }
}

// Importing or constructing a client does no I/O. All requests are explicit,
// never follow redirects or retry writes, and never upload original files/keys.
export class ApostilleClient {
    #base; #issuer; #fetch; #timeout; #token = ""; #sessionRevision = 0; #trustedKeyIDs;
    constructor({ baseURL, issuer, accessToken = "", trustedKeyIDs = [], timeoutMs = DEFAULT_TIMEOUT_MS, fetch: fetcher = globalThis.fetch, allowInsecureLocalhost = false }) {
        this.#base = validateBaseURL(baseURL, allowInsecureLocalhost === true);
        need(validIssuer(issuer), "invalid_issuer");
        this.#issuer = issuer;
        need(Array.isArray(trustedKeyIDs) && trustedKeyIDs.every(key => typeof key === "string" && /^sha256:[0-9a-f]{64}$/.test(key)), "invalid_trusted_key_id");
        this.#trustedKeyIDs = [...trustedKeyIDs];
        need(typeof fetcher === "function", "fetch_required");
        need(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 120000, "invalid_timeout");
        this.#fetch = fetcher;
        this.#timeout = timeoutMs;
        if (accessToken) this.setAccessToken(accessToken);
    }
    setAccessToken(token) { need(typeof token === "string" && TOKEN.test(token), "invalid_access_token"); this.#sessionRevision += 1; this.#token = token; }
    clearSession() { this.#sessionRevision += 1; this.#token = ""; }

    async #request(method, path, body, authenticated = false) {
        const token = authenticated ? this.#token : "", revision = this.#sessionRevision;
        need(!authenticated || token, "authentication_required");
        const raw = body === undefined ? undefined : snapshot(body).raw;
        const headers = { Accept: "application/json" };
        if (raw !== undefined) headers["Content-Type"] = "application/json";
        if (token) headers.Authorization = `Bearer ${token}`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.#timeout);
        try {
            const response = await this.#fetch.call(globalThis, this.#base + path, { method, headers, body: raw, redirect: "error", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer", signal: controller.signal });
            if (response.redirected || (response.status >= 300 && response.status < 400)) throw new ApostilleAPIError(response.status, "redirect_rejected");
            if (response.status === 401 && token && revision === this.#sessionRevision) this.clearSession();
            const data = await readResponse(response);
            if (!response.ok) {
                const code = typeof data?.code === "string" && ERROR_CODE.test(data.code) ? data.code : "http_error";
                const retry = response.headers.get("retry-after");
                throw new ApostilleAPIError(response.status, code, retry && retry.length <= 128 ? retry : null);
            }
            need(data && typeof data === "object" && !Array.isArray(data), "invalid_response");
            return data;
        } catch (error) {
            if (error instanceof ApostilleAPIError) throw error;
            // Do not echo transport URLs, server messages or signed request data.
            throw new ApostilleAPIError(0, controller.signal.aborted ? "request_timeout" : "network_error");
        } finally { clearTimeout(timeout); }
    }
    async status() {
        const data = await this.#request("GET", "/status");
        need(data.protocol === PROTOCOL && data.issuer === this.#issuer, "issuer_mismatch");
        return data;
    }
    async keys() {
        const data = await this.#request("GET", "/keys");
        need(data.protocol === PROTOCOL && data.issuer === this.#issuer && Array.isArray(data.keys), "invalid_key_directory");
        for (const key of data.keys) need(key.algorithm === "Ed25519" && key.key_id === await fingerprint(key.public_key), "invalid_key_directory");
        return data;
    }
    async createChallenge(publicKey) {
        const keyID = await fingerprint(publicKey);
        const data = await this.#request("POST", "/auth/challenges", { public_key: publicKey });
        try { validateLoginChallenge(data, keyID, this.#issuer); }
        catch { throw new ApostilleAPIError(0, "invalid_challenge"); }
        return data;
    }
    async login(signer) {
        this.clearSession();
        const revision = this.#sessionRevision;
        const challenge = await this.createChallenge(signer.publicKey);
        need(revision === this.#sessionRevision, "session_changed");
        const signature = await signLogin(challenge.message, signer, this.#issuer);
        need(revision === this.#sessionRevision, "session_changed");
        const data = await this.#request("POST", "/auth/verify", { challenge_id: challenge.challenge_id, message: challenge.message, signature });
        need(revision === this.#sessionRevision, "session_changed");
        need(data.token_type === "Bearer" && Number.isInteger(data.expires_in) && data.expires_in > 0 && data.workspace?.admin_key_id === signer.keyID && data.workspace?.admin_public_key === signer.publicKey, "invalid_session");
        this.setAccessToken(data.access_token);
        return data;
    }
    me() { return this.#request("GET", "/me", undefined, true); }
    updateWorkspace({ name, is_public }) {
        need(typeof name === "string" && typeof is_public === "boolean", "invalid_profile");
        return this.#request("PUT", "/workspace", { name, is_public }, true);
    }
    async registerAgent(name, registration) {
        need(typeof name === "string", "invalid_agent");
        const reg = snapshot(registration).value;
        await verifyRegistration(reg, this.#issuer, new Date());
        return this.#request("POST", "/agents", { name, ...reg }, true);
    }
    async erc8004Config() {
        const data = await this.#request("GET", "/erc8004/config");
        try {
            need(data.profile === ERC8004_PROTOCOL && typeof data.enabled === "boolean" && data.max_binding_age_seconds === 3600 && data.wallet_support === "eoa_only" && Array.isArray(data.networks), "invalid_erc8004_config");
            for (const network of data.networks) {
                need(network && Object.keys(network).length === 2 && typeof network.chain_id === "string" && /^(1|8453)$/.test(network.chain_id) && /^0x[0-9a-f]{40}$/.test(network.registry_address) && !/^0x0{40}$/.test(network.registry_address), "invalid_erc8004_config");
            }
            return data;
        } catch (error) {
            if (error instanceof ApostilleAPIError && error.code === "invalid_erc8004_config") throw error;
            throw new ApostilleAPIError(0, "invalid_erc8004_config");
        }
    }
    async #checkedERC8004Record(record, agentID, submitted = null) {
        try {
            need(record && ID.test(record.id) && record.agent_id === agentID && typeof record.created_at === "string" && typeof record.expires_at === "string", "invalid_binding_response");
            const verification = await verifyERC8004Binding(record.document, { issuer: this.#issuer, trustedKeyIDs: this.#trustedKeyIDs, now: new Date() });
            need(!this.#trustedKeyIDs.length || verification.issuer_trust === "pinned", "invalid_binding_response");
            need(verification.request.agent_id === agentID && record.created_at === verification.checked_at && record.expires_at === verification.expires_at, "invalid_binding_response");
            if (submitted) {
                const binding = parseStrict(decodeBytes(unb64(record.document.binding.payload)));
                need(canonical(binding.request) === canonical(submitted.request), "invalid_binding_response");
                need(binding.owner_signature === submitted.owner_signature, "invalid_binding_response");
            }
            return { ...record, verification };
        } catch {
            throw new ApostilleAPIError(0, "invalid_binding_response");
        }
    }
    async createERC8004Binding(agentID, request, ownerSignature) {
        const agent = id(agentID);
        const body = snapshot({ request, owner_signature: ownerSignature }).value;
        try {
            need(/^0x[0-9a-f]{130}$/.test(body.owner_signature), "invalid_erc8004_request");
            await erc8004OwnerMessage(body.request);
            const payload = parseStrict(decodeBytes(unb64(body.request.payload)));
            need(payload.agent_id === agent && payload.service_audience === this.#issuer, "invalid_erc8004_request");
        } catch {
            throw new ApostilleAPIError(0, "invalid_erc8004_request");
        }
        const record = await this.#request("POST", `/agents/${agent}/erc8004`, body, true);
        return this.#checkedERC8004Record(record, agent, body);
    }
    async getERC8004Binding(agentID) {
        const agent = id(agentID);
        const record = await this.#request("GET", `/agents/${agent}/erc8004`, undefined, true);
        return this.#checkedERC8004Record(record, agent);
    }
    revokeAgent(agentID) { return this.#request("POST", `/agents/${id(agentID)}/revoke`, undefined, true); }
    async submit(statement, grant) {
        const body = snapshot({ statement, grant }).value;
        await verifyEnvelope(body.statement, "origin-statement");
        const g = await verifyEnvelope(body.grant, "publication-grant");
        const digest = await envelopeDigest(body.statement);
        need(g.service_audience === this.#issuer && g.statement_sha256 === digest, "invalid_publication_grant");
        const issued = Date.parse(g.issued_at), expires = Date.parse(g.expires_at), now = Date.now();
        need(issued <= now + 120000 && expires > now && expires - issued <= 15 * 60000, "invalid_publication_grant");
        const data = await this.#request("POST", "/submissions", body, true);
        const { verification: checked } = await this.#checkedBundle(data.bundle);
        need(checked.issuer === this.#issuer && checked.certificate_scope === "origin_signature_checked" && await envelopeDigest(data.bundle.statement) === digest && (g.visibility !== "private" || data.is_public === false), "invalid_certificate_response");
        return data;
    }
    async #checkedBundle(bundle) {
        try {
            const verification = await verifyBundle(bundle, {issuer: this.#issuer, keyIDs: this.#trustedKeyIDs, at: new Date()});
            need(verification.issuer === this.#issuer && verification.certificate_scope === "origin_signature_checked" && (!this.#trustedKeyIDs.length || verification.issuer_trust === "accepted_by_policy"), "invalid_certificate_response");
            return {bundle, verification};
        } catch { throw new ApostilleAPIError(0, "invalid_certificate_response"); }
    }
    async getBundle(certificateID) {
        const bundle = await this.#request("GET", `/certificates/${id(certificateID)}/bundle`, undefined, true);
        return this.#checkedBundle(bundle);
    }
    hideCertificate(certificateID) { return this.#request("POST", `/certificates/${id(certificateID)}/hide`, undefined, true); }
    async getPublicCertificate(publicID) {
        const data = await this.#request("GET", `/public/certificates/${id(publicID)}`);
        return {...data, ...await this.#checkedBundle(data.bundle)};
    }
    getPublicOrganization(publicID) { return this.#request("GET", `/public/organizations/${id(publicID)}`); }
}
