package apostille

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBrowserGoRejectNoncanonicalSignedPayload(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for browser interoperability")
	}
	for _, tc := range []struct{ name, prefix string }{{"UTF8_BOM", "\xef\xbb\xbf"}, {"whitespace", " "}} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, _, _, issuer := fixture(t)
			payload, err := rawURL.DecodeString(bundle.Certificate.Payload)
			if err != nil {
				t.Fatal(err)
			}
			payload = append([]byte(tc.prefix), payload...)
			// This signature is correct over the noncanonical bytes: rejection
			// must come from encoding validation, not an incidental bad signature.
			signature := ed25519.Sign(issuer.key, signingInput(KindCertificate, payload))
			bundle.Certificate.Payload = rawURL.EncodeToString(payload)
			bundle.Certificate.PayloadSHA256 = Hash(payload)
			bundle.Certificate.Signature.Value = rawURL.EncodeToString(signature)
			if !ed25519.Verify(issuer.key.Public().(ed25519.PublicKey), signingInput(KindCertificate, payload), signature) {
				t.Fatal("invalid test signature")
			}
			raw, err := json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(raw, VerifyOptions{}); err == nil {
				t.Fatal("Go accepted a noncanonical signed payload")
			}
			file := filepath.Join(t.TempDir(), "noncanonical-bundle.json")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			script := `import assert from 'node:assert/strict'; import {readFile} from 'node:fs/promises';
 import {verifyBundle} from '../web/apostille-core.mjs';
 await assert.rejects(verifyBundle(await readFile(process.argv[1],'utf8')));`
			if output, err := exec.Command(node, "--input-type=module", "-e", script, file).CombinedOutput(); err != nil {
				t.Fatalf("browser did not reject noncanonical payload: %v: %s", err, output)
			}
		})
	}
}

func TestBrowserGoBidirectionalInterop(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for browser interoperability")
	}
	script := `import * as a from '../web/apostille-core.mjs';
 const admin=await a.importKeyFile(await a.generateKeyFile());
 const agent=await a.importKeyFile(await a.generateKeyFile());
 const reg=await a.createRegistration(admin,agent,'https://issuer.example/apostille');
 const statement=await a.createStatement(new TextEncoder().encode('互通\n'),'text/plain',agent,reg);
 console.log(JSON.stringify({protocol:a.PROTOCOL,statement,...reg,certificate:null}));`
	raw, err := exec.Command(node, "--input-type=module", "-e", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	var b Bundle
	if err := StrictJSON(raw, &b); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(raw, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t, 3)
	issued, err := Issue(b, signer, exampleIssuer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	check := `import * as a from '../web/apostille-core.mjs'; import {readFile} from 'node:fs/promises';
 const v=await a.verifyBundle(await readFile(process.argv[1],'utf8'),{issuer:process.argv[2],keyIDs:[process.argv[3]],at:new Date()});
 if(v.issuer_trust!=='accepted_by_policy'||!await a.verifyArtifact(v,new TextEncoder().encode('互通\n'))) process.exit(1);`
	if output, err := exec.Command(node, "--input-type=module", "-e", check, file, exampleIssuer, signer.KeyID()).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
}
