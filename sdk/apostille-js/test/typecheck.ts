import {
  PROTOCOL,
  createGrant,
  createERC8004Request,
  createProducerStatement,
  createRegistration,
  createStatement,
  generateKeyFile,
  importKeyFile,
  issueBundle,
  verifyArtifact,
  verifyBundle,
  verifyRegistration,
  verifyERC8004Binding,
  erc8004OwnerMessage,
  type AgentRegistration,
  type Bundle,
  type Envelope,
  type Signer,
  type Verification,
  type ERC8004Identity,
} from "@ifandonlyif/apostille";
import {
  ApostilleAPIError,
  ApostilleClient,
  type CertificateRecord,
  type MeResult,
} from "@ifandonlyif/apostille/client";

declare const signer: Signer;
declare const registration: AgentRegistration;
declare const statement: Envelope<"origin-statement">;
declare const grant: Envelope<"publication-grant">;
declare const bundle: Bundle;
declare const verification: Verification;

const protocol: typeof PROTOCOL = "https://ifandonlyif.io/apostille/spec/0.1";
void protocol;

async function offlineSurface(): Promise<void> {
  const keyFile = await generateKeyFile();
  const imported: Signer = await importKeyFile(keyFile);
  const createdRegistration = await createRegistration(imported, signer, "https://issuer.example/apostille");
  await verifyRegistration(createdRegistration, "https://issuer.example/apostille", new Date());
  const createdStatement = await createStatement(new Uint8Array(), "application/octet-stream", signer, createdRegistration);
  await createProducerStatement(new Uint8Array(), "application/octet-stream", signer, crypto.randomUUID());
  const createdGrant = await createGrant(createdStatement, createdRegistration, imported, "https://issuer.example/apostille", "private");
  await issueBundle(bundle, imported, "https://issuer.example/apostille", new Date());
  const checked: Verification = await verifyBundle(bundle, { issuer: "https://issuer.example/apostille", keyIDs: [imported.keyID], at: new Date() });
  const matches: boolean = await verifyArtifact(checked, new Uint8Array());
  void createdGrant;
  void matches;
}

async function hostedSurface(): Promise<void> {
  const client = new ApostilleClient({
    baseURL: "https://issuer.example/api/apostille/v1",
    issuer: "https://issuer.example/apostille",
    accessToken: "token",
    timeoutMs: 5_000,
    fetch: globalThis.fetch,
  });
  const me: MeResult = await client.me();
  const maxAgents: number = (await client.status()).limits.max_agents;
  void maxAgents;
  const certificate: CertificateRecord = await client.submit(statement, grant);
  await client.registerAgent("agent", registration);
  const identity: ERC8004Identity = { chain_id: "8453", registry_address: "0x1111111111111111111111111111111111111111", erc8004_agent_id: "42", owner_address: "0x2222222222222222222222222222222222222222" };
  const request = await createERC8004Request(signer, registration, identity, "https://issuer.example/apostille");
  await erc8004OwnerMessage(request);
  await client.erc8004Config();
  const binding = await client.createERC8004Binding((await verifyRegistration(registration)).agent_id, request, `0x${"00".repeat(65)}`);
  await verifyERC8004Binding(binding.document, { issuer: "https://issuer.example/apostille", trustedKeyIDs: [], now: new Date() });
  await client.getERC8004Binding(binding.agent_id);
  await client.updateWorkspace({ name: me.workspace.name, is_public: false });
  await client.getBundle(certificate.id);
  client.clearSession();
  client.setAccessToken("replacement");
  const error: ApostilleAPIError = new ApostilleAPIError(503, "apostille_service_unavailable", "60");
  void error.retryAfter;
}

void offlineSurface;
void hostedSurface;
void verification;
