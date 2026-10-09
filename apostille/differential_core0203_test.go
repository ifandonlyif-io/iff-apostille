package apostille

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Go/JS envelope differential at Core 0.2 and 0.3. The corpus builders of
// differential_test.go take a caseGen, so each version gets the same payload
// substitutions and envelope mutations, re-signed under its own profile, plus
// every envelope of the committed conformance case file that differs from the
// known-answer bundle (the Ed25519 point vectors at 0.2, the ML-DSA
// encodings, contexts and Wycheproof signatures at 0.3).
//
// Both tables are the target: empty. A divergence here is not a retained
// helper difference; it must be fixed or turned into a specification decision.
// ---------------------------------------------------------------------------

// knownDivergences02 and knownDivergences03 list every envelope on which the
// two reference verifiers disagree at that version (value: Go's verdict). They
// are exact like knownDivergences: an unlisted divergence fails and so does a
// listed one that stops reproducing.
var knownDivergences02 = map[string]bool{}
var knownDivergences03 = map[string]bool{}

var (
	diffCaseFiles   = map[string]conformanceFile{}
	diffCaseFilesMu sync.Mutex
)

// diffCommittedCases reads the committed case file of g's version (cached). It
// panics rather than failing a test so that package-level dictionaries can use it.
func diffCommittedCases(g caseGen) conformanceFile {
	diffCaseFilesMu.Lock()
	defer diffCaseFilesMu.Unlock()
	if file, ok := diffCaseFiles[g.protocol]; ok {
		return file
	}
	raw, err := os.ReadFile(g.casesPath())
	if err != nil {
		panic(err)
	}
	var file conformanceFile
	if err := json.Unmarshal(raw, &file); err != nil {
		panic(err)
	}
	diffCaseFiles[g.protocol] = file
	return file
}

// diffIssuerValues0203 is diffIssuerValues followed by every identifier of the
// committed issuer cases that it does not already hold.
func diffIssuerValues0203(g caseGen) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range diffIssuerValues {
		seen[value] = true
		out = append(out, value)
	}
	for _, c := range diffCommittedCases(g).IssuerCases {
		if !seen[c.Value] {
			seen[c.Value] = true
			out = append(out, c.Value)
		}
	}
	return out
}

// diffCaseEnvelopeItems returns every distinct envelope of the committed bundle
// cases, labelled by the first case and member that carries it. Cases whose
// input is not a JSON object with envelopes (the whole-input and strict-JSON
// shapes) contribute nothing.
func diffCaseEnvelopeItems(t *testing.T, g caseGen) []differentialItem {
	t.Helper()
	seen := map[string]bool{}
	var corpus differentialCorpus
	for _, c := range diffCommittedCases(g).BundleCases {
		if c.InputB64 == nil {
			continue
		}
		raw, err := rawURL.DecodeString(*c.InputB64)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		var bundle Bundle
		if json.Unmarshal(raw, &bundle) != nil {
			continue
		}
		for _, member := range []struct {
			name string
			env  *Envelope
		}{{"statement", &bundle.Statement}, {"delegation", bundle.Delegation}, {"acceptance", bundle.Acceptance}, {"certificate", bundle.Certificate}} {
			if member.env == nil || member.env.Kind == "" {
				continue
			}
			key, err := json.Marshal(member.env)
			if err != nil {
				t.Fatal(err)
			}
			if seen[string(key)] {
				continue
			}
			seen[string(key)] = true
			corpus.add("case/"+c.Name+"/"+member.name, member.env.Kind, *member.env)
		}
	}
	return corpus.items
}

func diffEnvelopeCorpus(t *testing.T, g caseGen) (items []differentialItem, edgeStart int) {
	t.Helper()
	items = append(items, diffPayloadSubstitutionItems(t, g)...)
	items = append(items, diffEnvelopeMutationItems(t, g)...)
	edgeStart = len(items)
	if g.prof.algorithm == Algorithm {
		items = append(items, diffEd25519EdgeCaseItems(t, g)...)
	}
	items = append(items, diffCaseEnvelopeItems(t, g)...)
	return items, edgeStart
}

const diffEnvelopeScript = `import { readFile } from 'node:fs/promises';
import { verifyEnvelope } from '../web/apostille-core.mjs';
const items = JSON.parse(await readFile(process.argv[1], 'utf8'));
const results = [];
for (const item of items) {
  try { await verifyEnvelope(item.envelope, item.kind); results.push(true); }
  catch { results.push(false); }
}
process.stdout.write(JSON.stringify(results));`

func runEnvelopeDifferential(t *testing.T, g caseGen, known map[string]bool) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for Go/JS differential testing")
	}
	items, edgeStart := diffEnvelopeCorpus(t, g)
	labels := make([]string, len(items))
	for i, it := range items {
		labels[i] = it.Label
	}
	diffCheckUniqueStrings(t, labels)

	goAccept := make([]bool, len(items))
	for i, item := range items {
		_, err := VerifyEnvelope(item.Envelope)
		goAccept[i] = err == nil
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "envelopes.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out := diffRunNode(t, node, diffEnvelopeScript, file)
	var jsAccept []bool
	if err := json.Unmarshal(out, &jsAccept); err != nil {
		t.Fatalf("parsing node output: %v\noutput: %.200s", err, out)
	}
	if len(jsAccept) != len(items) {
		t.Fatalf("node returned %d results for %d items", len(jsAccept), len(items))
	}

	agree, goN, jsN := diffSummary(goAccept, jsAccept)
	t.Logf("core %s envelope corpus=%d agree=%d known_divergences=%d go_accept=%d/%d js_accept=%d/%d",
		g.version(), len(items), agree, len(known), goN, len(items), jsN, len(items))
	if g.prof.algorithm == Algorithm {
		for i := edgeStart; i < edgeStart+len(diffEd25519EdgeCaseLabels); i++ {
			t.Logf("ed25519 edge case %s: go=%v js=%v", items[i].Label, goAccept[i], jsAccept[i])
		}
	}
	// A corpus that rejects everything or accepts everything tests nothing.
	if goN == 0 || goN == len(items) {
		t.Fatalf("degenerate corpus: Go accepts %d of %d", goN, len(items))
	}
	if problems := diffFindDivergences(labels, goAccept, jsAccept, known); len(problems) > 0 {
		t.Errorf("%d unexpected divergence(s) or stale table entries:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}

func TestGoJSDifferential02(t *testing.T) { runEnvelopeDifferential(t, gen02, knownDivergences02) }

func TestGoJSDifferential03(t *testing.T) { runEnvelopeDifferential(t, gen03, knownDivergences03) }

// TestGoJSStrictJSONFixtures0203 replays the non-generated strict_json_cases
// of the 0.2 and 0.3 case files through Go and JS. The strict-JSON layer is
// version independent, so these agree wherever the 0.1 fixtures do.
func TestGoJSStrictJSONFixtures0203(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for Go/JS differential testing")
	}
	var items []diffStrictItem
	for _, g := range []caseGen{gen02, gen03} {
		for _, c := range diffCommittedCases(g).StrictJSONCases {
			if c.InputGen != nil || c.InputB64 == nil {
				continue
			}
			decoded, err := rawURL.DecodeString(*c.InputB64)
			if err != nil {
				t.Fatalf("%s %s: %v", g.version(), c.Name, err)
			}
			items = append(items, diffStrictItem{fmt.Sprintf("fixture-%s/%s", g.version(), c.Name), decoded})
		}
	}
	if len(items) == 0 {
		t.Fatal("no strict JSON fixtures")
	}
	type wireItem struct {
		Label  string `json:"label"`
		RawB64 string `json:"raw_b64"`
	}
	wire := make([]wireItem, len(items))
	labels := make([]string, len(items))
	goAccept := make([]bool, len(items))
	for i, it := range items {
		wire[i] = wireItem{it.Label, rawURL.EncodeToString(it.Raw)}
		labels[i] = it.Label
		var dst any
		goAccept[i] = StrictJSON(it.Raw, &dst) == nil
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "strict-json.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	script := `import { readFile } from 'node:fs/promises';
import { parseStrict, decodeBytes } from '../web/apostille-core.mjs';
const items = JSON.parse(await readFile(process.argv[1], 'utf8'));
const results = [];
for (const item of items) {
  try { parseStrict(decodeBytes(Buffer.from(item.raw_b64, 'base64url'))); results.push(true); } catch { results.push(false); }
}
process.stdout.write(JSON.stringify(results));`
	var jsAccept []bool
	if err := json.Unmarshal(diffRunNode(t, node, script, file), &jsAccept); err != nil || len(jsAccept) != len(items) {
		t.Fatalf("node output: %v", err)
	}
	if problems := diffFindDivergences(labels, goAccept, jsAccept, nil); len(problems) > 0 {
		t.Errorf("%d divergence(s):\n%s", len(problems), strings.Join(problems, "\n"))
	}
}
