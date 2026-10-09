package apostille

import (
	"strings"
	"testing"
)

// Core 0.2 identifier verdicts. Every expectation is written from the grammar
// in core-0.2.md, never from the validator's output; the generator fails if
// ValidIssuer02 disagrees.

type identifierRow struct {
	value  string
	accept bool
}

// hostOfLen is a dotted host of exactly n bytes made of 'a' labels of at most
// 63 bytes, whose last label is never empty.
func hostOfLen(n int) string {
	var labels []string
	remaining := n
	for remaining > 64 {
		labels = append(labels, strings.Repeat("a", 63))
		remaining -= 64
	}
	labels = append(labels, strings.Repeat("a", remaining))
	return strings.Join(labels, ".")
}

func identifierRows(t testing.TB) []identifierRow {
	t.Helper()
	backslash := string(rune(0x5C))
	var rows []identifierRow
	add := func(accept bool, values ...string) {
		for _, v := range values {
			rows = append(rows, identifierRow{v, accept})
		}
	}

	// Illustrative verdicts of the specification.
	add(true,
		"https://issuer.example/apostille", "https://issuer.example:8443/a", "https://127.0.0.1/a", "https://[::1]/a",
		"https://issuer.example/a!b", "https://issuer.example/a(b)", "urn:example:private-issuer", "urn:example:a/b")
	add(false,
		"HTTPS://issuer.example/a", "URN:example:x", "urn:EXAMPLE:x", "https://Issuer.example/a",
		"https://issuer.example:443/a", "https://issuer.example:0/a", "https://issuer.example:08443/a",
		"https://issuer.example./a", "https://issuer_example/a", "https://-issuer.example/a", "https://issuer.9x/a",
		"https://issuer.example/a|b", "https://issuer.example/a[b]", "https://issuer.example/a/../b",
		"https://issuer.example/./a", "https://issuer.example/a%20b", "https://user@issuer.example/a", "urn:x",
		"urn:example:x y")

	// Scheme and overall shape.
	add(true, "https://issuer.example", "https://a", "https://a.b", "urn:apostille:key:sha256:"+strings.Repeat("0", 64))
	add(false, "", "https://", "https:///a", "https:/issuer.example/a", "https//issuer.example/a", "httpss://issuer.example/a",
		"Https://issuer.example/a", "http://issuer.example/a", "ftp://issuer.example/a", "issuer.example/a", "//issuer.example/a",
		" https://issuer.example/a", "https://issuer.example/a ", "https://issuer.example/a\tb", "https://issuer.example/a\nb",
		"https://issuer.example/a\x7fb", "https://issuer.example/a\x00b", "https://issuer.example/é", "https://é.example/a")

	// Length: 256 bytes is the limit.
	add(true, "https://issuer.example/"+strings.Repeat("a", 233), "urn:example:"+strings.Repeat("a", 244))
	add(false, "https://issuer.example/"+strings.Repeat("a", 234), "urn:example:"+strings.Repeat("a", 245))

	// Port: 1 to 65535, no leading zero, never 443.
	add(true, "https://issuer.example:1/a", "https://issuer.example:80", "https://issuer.example:8443", "https://issuer.example:65535/a",
		"https://issuer.example:10000/a", "https://issuer.example:442/a", "https://issuer.example:444/a")
	add(false, "https://issuer.example:0/a", "https://issuer.example:00/a", "https://issuer.example:65536/a", "https://issuer.example:99999/a",
		"https://issuer.example:100000/a", "https://issuer.example:443/a", "https://issuer.example:443", "https://issuer.example:0443/a",
		"https://issuer.example:01/a", "https://issuer.example:+8443/a", "https://issuer.example:-1/a", "https://issuer.example:/a",
		"https://issuer.example:80:90/a", "https://issuer.example:8o/a", "https://issuer.example:8443:/a")

	// Host labels.
	add(true, "https://a-b.example/a", "https://a--b.example/a", "https://1.example/a", "https://1a.example/a", "https://issuer.x9/a",
		"https://xn--bcher-kva.example/a", "https://"+strings.Repeat("a", 63)+".example/a")
	add(false, "https://"+strings.Repeat("a", 64)+".example/a", "https://a-.example/a", "https://-a.example/a", "https://a..example/a",
		"https://.example/a", "https://example./a", "https://Example.com/a", "https://exAmple.com/a", "https://exa_mple.com/a",
		"https://exa mple.com/a", "https://exa%6dple.com/a", "https://exa.mple.1/a", "https://a.1/a", "https://issuer.9/a",
		"https://user:pw@issuer.example/a", "https://issuer.example@evil.example/a", "https://issuer.example?x/a", "https://issuer.example#x")

	// Host length: the 256-byte identifier limit is reached first, so a
	// 249-byte host already fails and 253 and 254 are covered by it.
	add(true, "https://"+hostOfLen(248))
	add(false, "https://"+hostOfLen(249), "https://"+hostOfLen(253), "https://"+hostOfLen(254))

	// IPv4: four canonical decimal octets, otherwise the final-label rule rejects.
	add(true, "https://0.0.0.0/a", "https://127.0.0.1/a", "https://255.255.255.255/a", "https://10.20.30.40:8443/a", "https://1.2.3.4",
		"https://100.200.250.249/a", "https://1.2.3.4.example/a", "https://1.2.3.a/a")
	add(false, "https://256.0.0.1/a", "https://256.1.1.1/a", "https://1.2.3.256/a", "https://01.2.3.4/a", "https://1.2.3.04/a", "https://127.0.0.01/a",
		"https://0177.0.0.1/a", "https://0x7f.0.0.1/a", "https://127.1/a", "https://1.2.3/a", "https://1.2.3.4.5/a", "https://2130706433/a",
		"https://1.2.3.4./a", "https://1.2.3.-4/a", "https://300.300.300.300/a")

	// IPv6, every example of the specification and each canonical-form rule.
	for _, text := range []string{
		"2001:db8:1:2:3:4:5:6", "2001:db8:0:1:1:1:1:1", "::", "::1", "1::", "2001:db8::1:0:0:1", "1:2:3:4:5:6:7:8", "2001:db8::",
		"1::2:0:0:3:4", "1:0:0:2::3", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "abcd:ef01:2345:6789:abcd:ef01:2345:6789",
		"0:1:2:3:4:5:6:7", "1:2:3:4:5:6:7:0",
	} {
		add(true, "https://["+text+"]/a")
	}
	add(true, "https://[::1]", "https://[::1]:8443/a", "https://[2001:db8::1]:8443")
	for _, text := range []string{
		"2001:db8::1:1:1:1:1", "2001:db8:0:0:1:1:1:1", "2001:db8:1::0:0:1", "2001:DB8::1", "2001:0db8::1", "::ffff:1.2.3.4", "fe80::1%eth0",
		"0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:0", "1:0:0:0:0:0:0:0", "1::2::3", ":::", "::1:", ":1::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "1::2:3:4:5:6:7:8",
		"12345::", "g::1", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "1:0:0:2::3:4", "1::2:0:0:0:3", "1:0:0:0:2::3", "2001:db8:0::1", "00::1", "::0", "2001:db8:0:0:1::1", "::1:2:3:4:5:6:7", "1:2:3:4:5:6:7::",
		"", ":", "1:", ":1", "1:2", "::1.2.3.4", "1.2.3.4",
	} {
		add(false, "https://["+text+"]/a")
	}
	add(false, "https://[::1/a", "https://::1]/a", "https://[::1]x/a", "https://[::1]:/a", "https://[::1]:443/a", "https://[::1]:0/a", "https://[]/a",
		"https://[::1][::1]/a", "https://[fe80::1%25eth0]/a", "https://[v1.x]/a", "https://[::1]a", "https://::1/a")

	// Path: every pchar accepted, every other printable ASCII byte rejected;
	// empty segments are valid and dot segments are not.
	for _, c := range "-._~!$&'()*+,;=:@0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		add(true, "https://issuer.example/a"+string(c)+"b")
	}
	for _, c := range "\"#%<>?[]^`{|}" + backslash {
		add(false, "https://issuer.example/a"+string(c)+"b")
	}
	add(true, "https://a.example/", "https://a.example/x/", "https://a.example//x", "https://a.example///", "https://a.example/a//b", "https://a.example/...",
		"https://a.example/.a", "https://a.example/a.", "https://a.example/..a", "https://a.example/a/.../b", "https://a.example/x:y", "https://a.example/@x",
		"https://a.example/:")
	add(false, "https://a.example/.", "https://a.example/..", "https://a.example/./", "https://a.example/../", "https://a.example/a/.", "https://a.example/a/..",
		"https://a.example/a/./b", "https://a.example/a/../b", "https://a.example/./a", "https://a.example//..", "https://a.example/a%2e%2e/b",
		"https://a.example/a%00", "https://a.example/a%zz")

	// URN: lowercase nid of 2 to 32 bytes, non-empty nss that does not start with "/".
	add(true, "urn:ab:x", "urn:"+strings.Repeat("a", 32)+":x", "urn:a-b:x", "urn:a--b:x", "urn:123:x", "urn:a1:x", "urn:example:a/", "urn:example:a//b",
		"urn:example::x", "urn:example:a:b:c", "urn:example:a@b", "urn:example:!$&'()*+,;=-._~", "urn:example:ABC", "urn:isbn:0451450523")
	add(false, "urn:a:x", "urn:"+strings.Repeat("a", 33)+":x", "urn:-a:x", "urn:a-:x", "urn:ab-:x", "urn:Example:x", "urn:eXample:x", "urn::x", "urn:example",
		"urn:example:", "urn:example:/a", "urn:example:/", "urn:example:a%41", "urn:example:a?b", "urn:example:a#b", "urn:example:a b", "urn:ex_ample:x",
		"urn:ex.ample:x", "urn:ex ample:x", "urn:example:a[b]", "urn:example:a|b", "urn:example:a"+backslash+"b", "urn:example:é", "urn:", "urn", "UrN:example:x",
		"urn: example:x", "urn:example:x\ty")
	return rows
}

// identifierConformanceCases returns the 0.2 identifier table, skipping values
// the shared list already holds. Each verdict is asserted against the
// profile's validator.
func (g caseGen) identifierConformanceCases(t *testing.T) []issuerConformanceCase {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range g.issuerConformanceCaseList(t) {
		seen[c.Value] = true
	}
	var out []issuerConformanceCase
	for _, row := range identifierRows(t) {
		if seen[row.value] {
			continue
		}
		seen[row.value] = true
		if got := g.prof.validIssuer(row.value); got != row.accept {
			t.Fatalf("identifier %q: validIssuer(%s) = %v, want %v", row.value, g.version(), got, row.accept)
		}
		expect := "reject"
		if row.accept {
			expect = "accept"
		}
		out = append(out, issuerConformanceCase{Value: row.value, Expect: expect})
	}
	return out
}
