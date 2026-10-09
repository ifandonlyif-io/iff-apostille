package apostille

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Go/JS interoperability at Core 0.2 and 0.3, in the style of interop_test.go:
// the Go known-answer vectors verified in the browser modules, bundles signed in
// JS verified, granted and issued in Go and then verified again in JS, and key
// files and login proofs crossing the language boundary.

func requireNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for browser interoperability")
	}
	return node
}

func runNodeScript(t *testing.T, node, script string, args ...string) []byte {
	t.Helper()
	return diffRunNode(t, node, script, args...)
}

// resultWithoutStatement is a Verification as JSON with its statement dropped,
// so Go's and JS's results compare by value.
func resultWithoutStatement(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "statement")
	return m
}

func TestBrowserVerifiesGoVectors(t *testing.T) {
	node := requireNode(t)
	dir := filepath.Join("..", "testdata", "apostille")
	for _, name := range []string{"core-0.1.json", "core-0.2.json", "core-0.3.json", "core-0.3-hedged.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			var vector struct {
				Issuer         string          `json:"issuer"`
				IssuerKeyID    string          `json:"issuer_key_id"`
				EvaluationTime string          `json:"evaluation_time"`
				Bundle         json.RawMessage `json:"bundle"`
			}
			if err := json.Unmarshal(raw, &vector); err != nil {
				t.Fatal(err)
			}
			opts := VerifyOptions{}
			if vector.Issuer != "" {
				at, err := time.Parse(TimestampLayout, vector.EvaluationTime)
				if err != nil {
					t.Fatal(err)
				}
				opts = VerifyOptions{ExpectedIssuer: vector.Issuer, TrustedKeyIDs: []string{vector.IssuerKeyID}, Now: at}
			}
			want, err := Verify(vector.Bundle, opts)
			if err != nil {
				t.Fatal(err)
			}
			wantJSON, _ := json.Marshal(want)
			script := `import {readFile} from 'node:fs/promises'; import {verifyBundle} from '../web/apostille-core.mjs';
 const vector=JSON.parse(await readFile(process.argv[1],'utf8'));
 const options=vector.issuer?{issuer:vector.issuer,keyIDs:[vector.issuer_key_id],at:vector.evaluation_time}:{};
 process.stdout.write(JSON.stringify(await verifyBundle(JSON.stringify(vector.bundle),options)));`
			got := runNodeScript(t, node, script, filepath.Join(dir, name))
			if !reflect.DeepEqual(resultWithoutStatement(t, got), resultWithoutStatement(t, wantJSON)) {
				t.Fatalf("browser and Go verification results differ:\nbrowser %s\ngo      %s", got, wantJSON)
			}
		})
	}
}

// jsBuild signs a delegated statement, a publication grant and a JS-issued
// certificate (JS issuer key) under protocol, and prints them as JSON.
const jsBuildScript = `import * as a from '../web/apostille-core.mjs';
 const [protocol, algorithm] = process.argv.slice(1), audience = 'https://issuer.example/apostille';
 const make = async () => a.importKeyFile(await a.generateKeyFile({algorithm}));
 const admin = await make(), agent = await make(), issuerKey = await make();
 const reg = await a.createRegistration(admin, agent, audience, 30, protocol);
 const bytes = new TextEncoder().encode('interop 互通\n');
 const statement = await a.createStatement(bytes, 'text/plain', agent, reg);
 const grant = await a.createGrant(statement, reg, admin, audience, 'private');
 const source = {protocol, statement, ...reg, certificate: null};
 const issuedByJS = await a.issueBundle(source, issuerKey, audience);
 process.stdout.write(JSON.stringify({source, grant, adminKeyID: admin.keyID, issuerKeyID: issuerKey.keyID, issuedByJS}));`

func TestBrowserGoBidirectionalInterop0203(t *testing.T) {
	node := requireNode(t)
	for _, tc := range []struct {
		name, protocol, algorithm string
	}{
		{"0.1", Protocol, Algorithm},
		{"0.2", Protocol02, Algorithm},
		{"0.3", Protocol03, Algorithm03},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := runNodeScript(t, node, jsBuildScript, tc.protocol, tc.algorithm)
			var built struct {
				Source      json.RawMessage `json:"source"`
				Grant       Envelope        `json:"grant"`
				AdminKeyID  string          `json:"adminKeyID"`
				IssuerKeyID string          `json:"issuerKeyID"`
				IssuedByJS  json.RawMessage `json:"issuedByJS"`
			}
			if err := json.Unmarshal(raw, &built); err != nil {
				t.Fatal(err)
			}
			// JS-signed, Go-verified.
			source, err := Verify(built.Source, VerifyOptions{AcceptedProtocols: []string{tc.protocol}})
			if err != nil {
				t.Fatal(err)
			}
			if source.Protocol != tc.protocol || source.AgentBinding != "admin_key_delegation" {
				t.Fatalf("unexpected result %+v", source)
			}
			var bundle Bundle
			if err := StrictJSON(built.Source, &bundle); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateGrant(built.Grant, bundle.Statement, *bundle.Delegation, built.AdminKeyID, exampleIssuer, time.Now()); err != nil {
				t.Fatalf("Go rejected the JS-signed grant: %v", err)
			}
			if _, err := Verify(built.Source, VerifyOptions{AcceptedProtocols: []string{}}); err == nil {
				t.Fatal("an empty accepted list must reject every version")
			}
			// JS-issued certificate, Go-verified with the exact issuer and key pin.
			if v, err := Verify(built.IssuedByJS, VerifyOptions{ExpectedIssuer: exampleIssuer, TrustedKeyIDs: []string{built.IssuerKeyID}, Now: time.Now()}); err != nil || v.IssuerTrust != "accepted_by_policy" || v.Protocol != tc.protocol {
				t.Fatalf("Go did not accept the JS-issued certificate: %+v %v", v, err)
			}
			// JS-signed, Go-issued, JS-verified.
			var issuer *Signer
			if tc.protocol == Protocol03 {
				seed, _, err := GenerateMLDSAKey()
				if err != nil {
					t.Fatal(err)
				}
				issuer, err = NewMLDSASigner(seed)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				seed, _, err := GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				issuer, err = NewSigner(seed)
				if err != nil {
					t.Fatal(err)
				}
			}
			issued, err := Issue(bundle, issuer, exampleIssuer, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if issued.Certificate.Protocol != tc.protocol || issued.Certificate.Signature.Algorithm != tc.algorithm {
				t.Fatalf("Go certificate carries %s / %s", issued.Certificate.Protocol, issued.Certificate.Signature.Algorithm)
			}
			issuedRaw, err := json.Marshal(issued)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(file, issuedRaw, 0600); err != nil {
				t.Fatal(err)
			}
			check := `import * as a from '../web/apostille-core.mjs'; import {readFile} from 'node:fs/promises';
 const v=await a.verifyBundle(await readFile(process.argv[1],'utf8'),{issuer:process.argv[2],keyIDs:[process.argv[3]],at:new Date(),acceptedProtocols:[process.argv[4]]});
 if(v.issuer_trust!=='accepted_by_policy'||v.protocol!==process.argv[4]||!await a.verifyArtifact(v,new TextEncoder().encode('interop 互通\n'))) process.exit(1);`
			if out, err := exec.Command(node, "--input-type=module", "-e", check, file, exampleIssuer, issuer.KeyID(), tc.protocol).CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
}

func TestBrowserGoKeyFilesAndLogin(t *testing.T) {
	node := requireNode(t)
	// JS-generated key files of both algorithms parse in Go and derive the same key.
	script := `import * as a from '../web/apostille-core.mjs';
 const files = {}; for (const algorithm of ['Ed25519', 'ML-DSA-65']) { const file = await a.generateKeyFile({algorithm}); const signer = await a.importKeyFile({...file, role: 'interop'}); files[algorithm] = {file: {...file, role: 'interop'}, keyID: signer.keyID};
   if (algorithm === 'ML-DSA-65') { const message = a.LOGIN_PREFIX_03 + 'issuer:https://issuer.example/apostille\nchallenge:x'; files.login = {message, signature: await a.signLogin03(message, signer), publicKey: signer.publicKey}; } }
 process.stdout.write(JSON.stringify(files));`
	var out struct {
		Ed25519 struct {
			File  KeyFile `json:"file"`
			KeyID string  `json:"keyID"`
		}
		MLDSA struct {
			File  KeyFile `json:"file"`
			KeyID string  `json:"keyID"`
		} `json:"ML-DSA-65"`
		Login struct{ Message, Signature, PublicKey string }
	}
	if err := json.Unmarshal(runNodeScript(t, node, script), &out); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		file     KeyFile
		keyID    string
		wantAlgo string
	}{"Ed25519": {out.Ed25519.File, out.Ed25519.KeyID, Algorithm}, "ML-DSA-65": {out.MLDSA.File, out.MLDSA.KeyID, Algorithm03}} {
		raw, err := json.Marshal(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		signer, stored, err := ParseKeyFile(raw)
		if err != nil {
			t.Fatalf("%s: Go rejected the JS key file: %v", name, err)
		}
		if signer.Algorithm() != tc.wantAlgo || signer.KeyID() != tc.keyID || stored.Role != "interop" {
			t.Fatalf("%s: Go derived %s %s", name, signer.Algorithm(), signer.KeyID())
		}
	}
	if !VerifyChallenge03(out.Login.PublicKey, out.Login.Message, out.Login.Signature) {
		t.Fatal("Go rejected the JS 0.3 login signature")
	}

	// Go-generated key files import in JS; a Go 0.3 login signature verifies in JS.
	goML, err := GenerateMLDSAKeyFile("go")
	if err != nil {
		t.Fatal(err)
	}
	edSeed, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := NewSigner(edSeed)
	if err != nil {
		t.Fatal(err)
	}
	goEd := KeyFile{Protocol: Protocol, KeyID: edSigner.KeyID(), PublicKey: edSigner.PublicKey(), Seed: edSeed, Role: "go"}
	mlSigner, _, err := ParseKeyFile(mustJSON(t, goML))
	if err != nil {
		t.Fatal(err)
	}
	message := LoginPrefix03 + "issuer:https://issuer.example/apostille\nchallenge:y"
	signature, err := mlSigner.SignChallenge03(message)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "go.json")
	if err := os.WriteFile(input, mustJSON(t, map[string]any{"ed": goEd, "ml": goML, "message": message, "signature": signature}), 0600); err != nil {
		t.Fatal(err)
	}
	check := `import * as a from '../web/apostille-core.mjs'; import {readFile} from 'node:fs/promises';
 const v = JSON.parse(await readFile(process.argv[1], 'utf8'));
 const ed = await a.importKeyFile(v.ed), ml = await a.importKeyFile(v.ml);
 if (ed.algorithm !== 'Ed25519' || ml.algorithm !== 'ML-DSA-65' || ml.keyID !== v.ml.key_id) process.exit(2);
 if (!a.verifyLogin03(v.ml.public_key, v.message, v.signature)) process.exit(3);`
	if output, err := exec.Command(node, "--input-type=module", "-e", check, input).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestBrowserAndGoRejectRelabelledBundles: a Go-issued bundle whose
// version label is changed after signing fails in JS exactly as it does in Go.
func TestBrowserAndGoRejectRelabelledBundles(t *testing.T) {
	node := requireNode(t)
	for _, tc := range []struct{ from, to string }{{Protocol02, Protocol}, {Protocol, Protocol02}, {Protocol03, Protocol02}, {Protocol02, Protocol03}} {
		b, _, _, _ := fixtureFor(t, tc.from)
		raw := bytes.Replace(mustJSON(t, b), []byte(`"protocol":"`+tc.from+`","statement"`), []byte(`"protocol":"`+tc.to+`","statement"`), 1)
		if bytes.Equal(raw, mustJSON(t, b)) {
			t.Fatal("relabelling did not change the bundle")
		}
		if _, err := Verify(raw, VerifyOptions{}); err == nil {
			t.Fatalf("Go accepted a %s bundle relabelled %s", tc.from, tc.to)
		}
		file := filepath.Join(t.TempDir(), "bundle.json")
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		script := `import assert from 'node:assert/strict'; import {readFile} from 'node:fs/promises'; import {verifyBundle} from '../web/apostille-core.mjs';
 await assert.rejects(verifyBundle(await readFile(process.argv[1],'utf8')));`
		if output, err := exec.Command(node, "--input-type=module", "-e", script, file).CombinedOutput(); err != nil {
			t.Fatalf("browser accepted %s relabelled %s: %v: %s", tc.from, tc.to, err, output)
		}
	}
}
