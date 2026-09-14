export declare const PROTOCOL: "https://ifandonlyif.io/apostille/spec/0.1";
export declare const MAX_INPUT_BYTES: 262144;
export declare const ERC8004_PROTOCOL: "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.1";

export type SignedKind =
  | "origin-statement"
  | "agent-delegation"
  | "agent-acceptance"
  | "publication-grant"
  | "origin-certificate";

export type Visibility = "private" | "public";

export interface Header<K extends SignedKind = SignedKind> {
  protocol: typeof PROTOCOL;
  kind: K;
  issuer: string;
  issuer_key_id: string;
  issued_at: string;
}

export interface Signature {
  algorithm: "Ed25519";
  key_id: string;
  public_key: string;
  value: string;
}

export interface ERC8004Envelope<K extends "erc8004-binding-request" | "erc8004-binding"> {
  protocol: typeof ERC8004_PROTOCOL;
  kind: K;
  payload: string;
  payload_sha256: string;
  signature: Signature;
}

export interface ERC8004Identity {
  chain_id: string;
  registry_address: string;
  erc8004_agent_id: string;
  owner_address: string;
}

export interface ERC8004Request extends ERC8004Identity {
  protocol: typeof ERC8004_PROTOCOL;
  kind: "erc8004-binding-request";
  issuer: string;
  issuer_key_id: string;
  issued_at: string;
  agent_id: string;
  agent_key_id: string;
  delegation_sha256: string;
  service_audience: string;
  nonce: string;
  expires_at: string;
  purpose: "link_identity_private";
}

export interface ERC8004BindingDocument {
  protocol: typeof ERC8004_PROTOCOL;
  binding: ERC8004Envelope<"erc8004-binding">;
  delegation: Envelope<"agent-delegation">;
  acceptance: Envelope<"agent-acceptance">;
}

export interface ERC8004VerifyOptions {
  issuer?: string;
  trustedKeyIDs?: readonly string[];
  now?: string | number | Date | null;
}

export interface ERC8004Verification {
  protocol: typeof ERC8004_PROTOCOL;
  artifact_integrity: "valid";
  issuer_trust: "pinned" | "unknown";
  provider_evidence: "issuer_checked";
  current_ownership: "unknown";
  organization_binding: "unproven";
  payment_authority: "not_established";
  freshness: "within_validity" | "expired" | "not_yet_valid" | "not_checked";
  issuer: string;
  issuer_key_id: string;
  checked_at: string;
  expires_at: string;
  request: ERC8004Request;
}

export interface Envelope<K extends SignedKind = SignedKind> {
  protocol: typeof PROTOCOL;
  kind: K;
  payload: string;
  payload_sha256: string;
  signature: Signature;
}

export interface OriginStatement extends Header<"origin-statement"> {
  agent_id: string;
  delegation_sha256: string;
  artifact_sha256: string;
  artifact_size: string;
  artifact_media_type: string;
  nonce: string;
}

export interface AgentDelegation extends Header<"agent-delegation"> {
  agent_id: string;
  agent_key_id: string;
  agent_public_key: string;
  service_audience: string;
  not_before: string;
  expires_at: string;
  scopes: ["sign_origin_statement"];
}

export interface AgentAcceptance extends Header<"agent-acceptance"> {
  agent_id: string;
  delegation_sha256: string;
}

export interface PublicationGrant extends Header<"publication-grant"> {
  statement_sha256: string;
  delegation_sha256: string;
  service_audience: string;
  visibility: Visibility;
  purpose: "issue_origin_certificate";
  expires_at: string;
  nonce: string;
}

export interface OriginCertificate extends Header<"origin-certificate"> {
  certificate_id: string;
  statement_sha256: string;
  delegation_sha256: string;
  source_key_id: string;
  expires_at: string;
  signature_check: "valid";
  agent_binding: "admin_key_delegation" | "not_provided";
  organization_binding: "unproven";
  content_truth: "not_established";
}

export interface KindPayloadMap {
  "origin-statement": OriginStatement;
  "agent-delegation": AgentDelegation;
  "agent-acceptance": AgentAcceptance;
  "publication-grant": PublicationGrant;
  "origin-certificate": OriginCertificate;
}

export type SignedPayload = KindPayloadMap[SignedKind];
export type Statement = OriginStatement;
export type Delegation = AgentDelegation;
export type Acceptance = AgentAcceptance;
export type Certificate = OriginCertificate;

export interface Bundle {
  protocol: typeof PROTOCOL;
  statement: Envelope<"origin-statement">;
  delegation: Envelope<"agent-delegation"> | null;
  acceptance: Envelope<"agent-acceptance"> | null;
  certificate: Envelope<"origin-certificate"> | null;
}

export interface AgentRegistration {
  delegation: Envelope<"agent-delegation">;
  acceptance: Envelope<"agent-acceptance">;
}

export interface Signer {
  readonly key: CryptoKey;
  readonly keyID: string;
  readonly publicKey: string;
}

export interface KeyFile {
  protocol: typeof PROTOCOL;
  seed: string;
  public_key: string;
  key_id: string;
  role?: string;
}

export interface VerifyOptions {
  issuer?: string;
  keyIDs?: readonly string[];
  at?: string | number | Date | null;
}

export interface Verification {
  protocol: typeof PROTOCOL;
  artifact_integrity: "valid";
  issuer_trust: "unknown" | "untrusted" | "accepted_by_policy";
  certificate_scope: "producer_only" | "origin_signature_checked";
  agent_binding: "admin_key_delegation" | "not_provided";
  organization_binding: "unproven";
  authorization_policy: "unknown" | "current_revocation_unknown";
  freshness: "unknown" | "not_yet_valid" | "expired" | "valid_at_evaluation_time";
  time_basis: "producer_claimed" | "issuer_claimed_check_time";
  content_truth: "not_established";
  provider_evidence: "not_provided";
  log_inclusion: "not_registered";
  anchor: "not_requested";
  issuer: string;
  issuer_key_id: string;
  certificate_id: string;
  statement: OriginStatement;
}

export declare function parseStrict<T = unknown>(text: string): T;
export declare function canonical(value: unknown): string;
export declare function decodeBytes(bytes: Uint8Array): string;
export declare function b64(bytes: Uint8Array): string;
export declare function unb64(value: string): Uint8Array;
export declare function hash(bytes: Uint8Array): Promise<string>;
export declare function fingerprint(publicKey: string): Promise<string>;
export declare function keyIdentity(keyID: string): string;
export declare function timestamp(now?: string | number | Date): string;
export declare function envelopeDigest(envelope: Envelope): Promise<string>;
export declare function verifyEnvelope<K extends SignedKind>(envelope: Envelope<K>, expectedKind: K): Promise<KindPayloadMap[K]>;
export declare function verifyEnvelope(envelope: Envelope, expectedKind?: ""): Promise<SignedPayload>;
export declare function verifyBundle(input: string | Bundle, options?: VerifyOptions): Promise<Verification>;
export declare function verifyArtifact(result: Verification, bytes: Uint8Array): Promise<boolean>;
export declare function importKeyFile(file: KeyFile): Promise<Signer>;
export declare function generateKeyFile(): Promise<Omit<KeyFile, "role">>;
export declare function header<K extends SignedKind>(kind: K, signer: Signer, now?: string | number | Date, identity?: string): Header<K>;
export declare function sign<K extends SignedKind>(kind: K, payload: KindPayloadMap[K], signer: Signer): Promise<Envelope<K>>;
export declare function signLogin(message: string, signer: Signer, expectedIssuer: string): Promise<string>;
export declare function validateLoginChallenge(challenge: { issuer: string; challenge_id: string; expires_at: string; message: string }, keyID: string, expectedIssuer: string, now?: number): string;
export declare function createRegistration(admin: Signer, agent: Signer, audience: string, days?: number): Promise<AgentRegistration>;
export declare function verifyRegistration(registration: AgentRegistration, audience?: string, at?: string | Date | null): Promise<Delegation>;
export declare function createStatement(bytes: Uint8Array, mediaType: string, agent: Signer, registration: AgentRegistration): Promise<Envelope<"origin-statement">>;
export declare function createProducerStatement(bytes: Uint8Array, mediaType: string, agent: Signer, agentID: string): Promise<Envelope<"origin-statement">>;
export declare function createGrant(statement: Envelope<"origin-statement">, registration: AgentRegistration, admin: Signer, audience: string, visibility: Visibility): Promise<Envelope<"publication-grant">>;
export declare function issueBundle(bundle: Bundle, issuerSigner: Signer, issuer: string, at?: Date): Promise<Bundle>;
export declare function createERC8004Request(admin: Signer, registration: AgentRegistration, identity: ERC8004Identity, audience: string, now?: string | number | Date | typeof Date): Promise<ERC8004Envelope<"erc8004-binding-request">>;
export declare function erc8004OwnerMessage(request: ERC8004Envelope<"erc8004-binding-request">): Promise<string>;
export declare function verifyERC8004Binding(document: string | ERC8004BindingDocument, options?: ERC8004VerifyOptions): Promise<ERC8004Verification>;

/** Whether an issuer uses the exact Core 0.1 identifier syntax. */
export declare function validIssuer(value: unknown): boolean;
