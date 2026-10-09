import {
  ALGORITHM_03,
  KNOWN_PROTOCOLS,
  LOGIN_PREFIX_03,
  PROTOCOL,
  PROTOCOL_02,
  PROTOCOL_03,
  createGrant,
  createERC8004Request,
  createProducerStatement,
  createRegistration,
  createStatement,
  generateKeyFile,
  importKeyFile,
  issueBundle,
  verifyArtifact,
  signLogin03,
  validIssuer02,
  verifyBundle,
  verifyLogin03,
  verifyRegistration,
  verifyERC8004Binding,
  erc8004OwnerMessage,
  type AgentRegistration,
  type Bundle,
  type CoreProtocol,
  type Ed25519Signer,
  type Envelope,
  type MLDSA65Signer,
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
declare const edSigner: Ed25519Signer;
declare const mlSigner: MLDSA65Signer;
declare const registration: AgentRegistration;
declare const statement: Envelope<"origin-statement">;
declare const grant: Envelope<"publication-grant">;
declare const bundle: Bundle;
declare const verification: Verification;

const protocol: typeof PROTOCOL = "https://ifandonlyif.io/apostille/spec/0.1";
void protocol;
const versions: readonly CoreProtocol[] = [PROTOCOL, PROTOCOL_02, PROTOCOL_03, ...KNOWN_PROTOCOLS];
void versions;

// Core 0.2 and 0.3: explicit version, accepted-protocol policy, key algorithm and the 0.3 login helper.
async function versionedSurface(): Promise<void> {
  const ml = await importKeyFile(await generateKeyFile({ algorithm: ALGORITHM_03 }));
  const ed = await importKeyFile(await generateKeyFile({ algorithm: "Ed25519" }));
  const registration03 = await createRegistration(ml, ml, "https://issuer.example/apostille", 30, PROTOCOL_03);
  const statement03 = await createStatement(new Uint8Array(), "text/plain", ml, registration03, PROTOCOL_03);
  await createGrant(statement03, registration03, ml, "https://issuer.example/apostille", "private", PROTOCOL_03);
  await createProducerStatement(new Uint8Array(), "text/plain", ed, crypto.randomUUID(), PROTOCOL_02);
  const checked: Verification = await verifyBundle(bundle, { acceptedProtocols: [PROTOCOL_03] });
  const reported: CoreProtocol = checked.protocol;
  await verifyBundle(bundle, { acceptedProtocols: [] });
  await verifyBundle(bundle, { acceptedProtocols: null });
  const loginSignature: string = await signLogin03(`${LOGIN_PREFIX_03}issuer:x`, mlSigner);
  const valid: boolean = verifyLogin03(mlSigner.publicKey, `${LOGIN_PREFIX_03}issuer:x`, loginSignature);
  const grammar: boolean = validIssuer02("https://issuer.example/apostille");
  void [reported, valid, grammar, edSigner];
}
void versionedSurface;

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
  const request = await createERC8004Request(edSigner, registration, identity, "https://issuer.example/apostille");
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
