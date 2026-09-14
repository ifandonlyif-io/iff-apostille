import { lstat, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  canonical, createGrant, createRegistration, createStatement, decodeBytes,
  generateKeyFile, importKeyFile, parseStrict, verifyArtifact, verifyBundle, verifyEnvelope,
} from '@ifandonlyif/apostille';
import { ApostilleClient } from '@ifandonlyif/apostille/client';

const args = process.argv.slice(2);
const submit = args.includes('--submit');
const visibility = args.includes('--public') ? 'public' : 'private';
const files = args.filter((value) => !value.startsWith('--'));
const unknownFlag = args.some((value) => value.startsWith('--') && !['--submit', '--public', '--help'].includes(value));

if (args.includes('--help') || !submit || unknownFlag || files.length !== 1) {
  console.log(`Usage: node hosted.mjs <original-file> --submit [--public]
Required: APOSTILLE_BASE_URL and APOSTILLE_ISSUER for the service you intend to use.
Optional: APOSTILLE_STATE_DIR (default .apostille-private/hosted-example),
APOSTILLE_ISSUER_KEY_ID (independently obtained trust pin),
APOSTILLE_ALLOW_INSECURE_LOCALHOST=1 (local development only).
No request is made without --submit. Submission is private unless --public is present.
--submit authorizes login/workspace creation, agent registration and one submission.
--public additionally authorizes publishing the signed bundle, including keys,
UUIDs, timestamps, file digest and size. It does not publish the original file.`);
  process.exitCode = unknownFlag || (submit && files.length !== 1) ? 2 : 0;
} else {
  let client;
  try {
    const baseURL = process.env.APOSTILLE_BASE_URL;
    const issuer = process.env.APOSTILLE_ISSUER;
    if (!baseURL || !issuer) throw new Error('Set APOSTILLE_BASE_URL and APOSTILLE_ISSUER before opting into --submit.');
    const source = resolve(files[0]);
    const info = await stat(source);
    if (!info.isFile() || info.size > 64 * 1024 * 1024) {
      throw new Error('Use a regular file of at most 64 MiB; use the streaming CLI for larger files.');
    }
    const bytes = new Uint8Array(await readFile(source));
    const directory = resolve(process.env.APOSTILLE_STATE_DIR || '.apostille-private/hosted-example');
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const directoryInfo = await lstat(directory);
    if (!directoryInfo.isDirectory() || (process.platform !== 'win32' && (directoryInfo.mode & 0o077))) {
      throw new Error('The state directory must be a private directory (0700 on Unix).');
    }
    const save = (path, value) => writeFile(path, canonical(value) + '\n', { mode: 0o600, flag: 'wx' });
    const load = async (path, maxBytes = 256 * 1024) => {
      const file = await lstat(path);
      if (!file.isFile() || file.size > maxBytes || (process.platform !== 'win32' && (file.mode & 0o077))) {
        throw new Error('State files must be regular, size-limited private files (0600 on Unix).');
      }
      return parseStrict(decodeBytes(await readFile(path)));
    };
    const key = async (name) => {
      const path = resolve(directory, name);
      try { return await importKeyFile(await load(path, 4096)); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        const generated = await generateKeyFile();
        await save(path, generated);
        return importKeyFile(generated);
      }
    };
    const administrator = await key('admin-key.json');
    const agent = await key('agent-key.json');
    const registrationPath = resolve(directory, 'registration.json');
    let registration;
    try { registration = await load(registrationPath); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      registration = await createRegistration(administrator, agent, issuer);
      await save(registrationPath, registration);
    }
    const delegation = await verifyEnvelope(registration.delegation, 'agent-delegation');
    if (delegation.service_audience !== issuer || delegation.issuer_key_id !== administrator.keyID) {
      throw new Error('This state directory belongs to a different issuer or administrator.');
    }
    if (Date.parse(delegation.expires_at) <= Date.now()) {
      throw new Error('This example delegation has expired; choose a new state directory for a new demonstration.');
    }
    // Validate and sign locally before any service call. No original bytes enter the request.
    const statement = await createStatement(bytes, 'application/octet-stream', agent, registration);
    const attempt = resolve(directory, `submission-${crypto.randomUUID()}`);
    await mkdir(attempt, { mode: 0o700 });
    await save(resolve(attempt, 'statement.json'), statement);
    client = new ApostilleClient({
      baseURL, issuer,
      allowInsecureLocalhost: process.env.APOSTILLE_ALLOW_INSECURE_LOCALHOST === '1',
    });
    await client.login(administrator); // The bearer token stays in this client's memory.
    const account = await client.me();
    if (!account.agents.some((registered) => registered.id === delegation.agent_id)) {
      await client.registerAgent('SDK example agent', registration);
    }
    // The signed visibility is explicit; login alone never authorizes publication.
    const grant = await createGrant(statement, registration, administrator, issuer, visibility);
    await save(resolve(attempt, 'grant.json'), grant);
    const issued = await client.submit(statement, grant);
    // Save the issuance response before a separate download can fail.
    await save(resolve(attempt, 'issued-bundle.json'), issued.bundle);
    const { bundle } = await client.getBundle(issued.id);
    await save(resolve(attempt, 'downloaded-bundle.json'), bundle);
    const keyID = process.env.APOSTILLE_ISSUER_KEY_ID;
    const policy = keyID ? { issuer, keyIDs: [keyID], at: new Date() } : { at: new Date() };
    const result = await verifyBundle(bundle, policy);
    if (!await verifyArtifact(result, bytes)) throw new Error('Downloaded bundle does not match the original file.');
    if (keyID && result.issuer_trust !== 'accepted_by_policy') throw new Error('Downloaded bundle does not match the supplied issuer/key pin.');
    console.log(JSON.stringify({
      certificate_id: issued.id,
      requested_visibility: visibility,
      output_directory: attempt,
      artifact_integrity: result.artifact_integrity,
      original_matches: true,
      issuer_trust: result.issuer_trust,
      authorization_policy: result.authorization_policy,
      organization_binding: result.organization_binding,
      content_truth: result.content_truth,
    }, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Hosted example failed.');
    console.error('No automatic retry was made. If issuance may have completed, inspect your authenticated history before another submission.');
    process.exitCode = 1;
  } finally {
    client?.clearSession();
  }
}
