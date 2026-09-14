import type { AgentRegistration, Bundle, Envelope, ERC8004BindingDocument, ERC8004Envelope, ERC8004Verification, Signer, Verification } from "./index.d.ts";

export interface ApostilleClientOptions {
  baseURL: string;
  issuer: string;
  accessToken?: string;
  trustedKeyIDs?: readonly string[];
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
  allowInsecureLocalhost?: boolean;
}

export interface ApostilleStatus {
  protocol: "https://ifandonlyif.io/apostille/spec/0.1";
  issuer: string;
  enabled: boolean;
  features: string[];
  planned: string[];
  limits: { max_agents: number; max_daily_certificates: number };
}

export interface ApostilleIssuerKey {
  key_id: string;
  public_key: string;
  algorithm: "Ed25519";
}

export interface ApostilleKeyDirectory {
  protocol: "https://ifandonlyif.io/apostille/spec/0.1";
  issuer: string;
  keys: ApostilleIssuerKey[];
  trust: string;
}

export interface LoginChallenge {
  challenge_id: string;
  message: string;
  expires_at: string;
  issuer: string;
}

export interface Workspace {
  id: string;
  admin_key_id: string;
  admin_public_key: string;
  name: string;
  public_id: string;
  is_public: boolean;
  created_at: string;
}

export interface Agent {
  id: string;
  workspace_id: string;
  name: string;
  key_id: string;
  public_key: string;
  delegation: Envelope<"agent-delegation">;
  acceptance: Envelope<"agent-acceptance">;
  expires_at: string;
  created_at: string;
  revoked_at?: string;
}

export interface CertificateRecord {
  id: string;
  workspace_id: string;
  agent_id: string;
  public_id: string;
  idempotency_key: string;
  body_hash: string;
  bundle: Bundle;
  is_public: boolean;
  created_at: string;
}

export interface LoginResult {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  workspace: Workspace;
}

export interface MeResult {
  workspace: Workspace;
  agents: Agent[];
  certificates: CertificateRecord[];
}

export interface VerifiedBundle {
  bundle: Bundle;
  verification: Verification;
}

export interface PublicCertificate extends VerifiedBundle {
  public_id: string;
  bundle: Bundle;
  created_at: string;
}

export interface PublicWorkspace {
  public_id: string;
  name: string;
  created_at: string;
}

export interface PublicOrganizationResult {
  profile: PublicWorkspace;
  organization_binding: "self_declared";
}

export interface ERC8004Config {
  profile: "https://ifandonlyif.io/apostille/profiles/erc8004-binding/0.1";
  enabled: boolean;
  networks: Array<{ chain_id: "1" | "8453"; registry_address: string }>;
  max_binding_age_seconds: 3600;
  wallet_support: "eoa_only";
}

export interface ERC8004BindingRecord {
  id: string;
  agent_id: string;
  document: ERC8004BindingDocument;
  created_at: string;
  expires_at: string;
}

export interface VerifiedERC8004BindingRecord extends ERC8004BindingRecord {
  verification: ERC8004Verification;
}

export declare class ApostilleAPIError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfter: string | null;
  constructor(status: number, code: string, retryAfter?: string | null);
}

export declare class ApostilleClient {
  constructor(options: ApostilleClientOptions);
  status(): Promise<ApostilleStatus>;
  keys(): Promise<ApostilleKeyDirectory>;
  createChallenge(publicKey: string): Promise<LoginChallenge>;
  login(signer: Signer): Promise<LoginResult>;
  clearSession(): void;
  setAccessToken(token: string): void;
  me(): Promise<MeResult>;
  updateWorkspace(input: { name: string; is_public: boolean }): Promise<Workspace>;
  registerAgent(name: string, registration: AgentRegistration): Promise<Agent>;
  erc8004Config(): Promise<ERC8004Config>;
  createERC8004Binding(id: string, request: ERC8004Envelope<"erc8004-binding-request">, ownerSignature: string): Promise<VerifiedERC8004BindingRecord>;
  getERC8004Binding(id: string): Promise<VerifiedERC8004BindingRecord>;
  revokeAgent(id: string): Promise<Agent>;
  submit(statement: Envelope<"origin-statement">, grant: Envelope<"publication-grant">): Promise<CertificateRecord>;
  getBundle(id: string): Promise<VerifiedBundle>;
  hideCertificate(id: string): Promise<{ id: string; is_public: false }>;
  getPublicCertificate(publicID: string): Promise<PublicCertificate>;
  getPublicOrganization(publicID: string): Promise<PublicOrganizationResult>;
}
