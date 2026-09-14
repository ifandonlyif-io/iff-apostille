import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  PROTOCOL, canonical, createRegistration, createStatement, generateKeyFile,
  importKeyFile, verifyArtifact, verifyBundle,
} from '@ifandonlyif/apostille';

// The caller chooses the original file. This is not a bot recorder or uploader.
const args = process.argv.slice(2);
if (args.length !== 1 || args[0] === '--help') {
  console.log('Usage: node offline.mjs <original-file>\nReads and signs locally; no network requests.');
  process.exitCode = args[0] === '--help' ? 0 : 2;
} else {
  try {
    const source = resolve(args[0]);
    const info = await stat(source);
    if (!info.isFile() || info.size > 64 * 1024 * 1024) {
      throw new Error('Use a regular file of at most 64 MiB; use the streaming CLI for larger files.');
    }
    const bytes = new Uint8Array(await readFile(source));
    const directory = resolve('.apostille-private', `offline-${crypto.randomUUID()}`);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const save = (name, value) => writeFile(resolve(directory, name), canonical(value) + '\n', { mode: 0o600, flag: 'wx' });

    const administratorKey = await generateKeyFile();
    const agentKey = await generateKeyFile();
    await save('admin-key.json', administratorKey);
    await save('agent-key.json', agentKey);
    const administrator = await importKeyFile(administratorKey);
    const agent = await importKeyFile(agentKey);
    // This local audience is an example identifier, not an IFF registration.
    const registration = await createRegistration(administrator, agent, 'urn:example:apostille:offline');
    const statement = await createStatement(bytes, 'application/octet-stream', agent, registration);
    const bundle = { protocol: PROTOCOL, statement, ...registration, certificate: null };
    await save('registration.json', registration);
    await save('producer-bundle.json', bundle);

    const result = await verifyBundle(canonical(bundle));
    const originalMatches = await verifyArtifact(result, bytes);
    if (!originalMatches) throw new Error('The supplied original does not match the signed digest and size.');
    console.log(JSON.stringify({
      output_directory: directory,
      artifact_integrity: result.artifact_integrity,
      original_matches: originalMatches,
      certificate_scope: result.certificate_scope,
      issuer_trust: result.issuer_trust,
      organization_binding: result.organization_binding,
      content_truth: result.content_truth,
    }, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Offline example failed.');
    process.exitCode = 1;
  }
}
