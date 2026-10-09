package apostille

import "strings"

// ValidIssuer02 decides the Core 0.2 identifier grammar ("Identifier grammar"
// in docs/apostille/spec/core-0.2.md) over the bytes as written, for issuer and
// service_audience values. It is a hand-written byte scanner: it never
// normalizes, resolves or parses with a URL library, so every implementation
// can return the same verdict.
func ValidIssuer02(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	switch {
	case strings.HasPrefix(value, "https://"):
		return validHTTPSIdentifier(value[len("https://"):])
	case strings.HasPrefix(value, "urn:"):
		return validURNIdentifier(value[len("urn:"):])
	}
	return false
}

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isLowerAlnum(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'z') }

// isPchar is RFC 3986 pchar without pct-encoded.
func isPchar(c byte) bool {
	if isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
		return true
	}
	return strings.IndexByte("-._~!$&'()*+,;=:@", c) >= 0
}

// validHTTPSIdentifier checks host [ ":" port ] *( "/" segment ) after the scheme.
func validHTTPSIdentifier(rest string) bool {
	var host string
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 || !canonicalIPv6(rest[1:end]) {
			return false
		}
		host, rest = rest[:end+1], rest[end+1:]
	} else {
		end := strings.IndexAny(rest, ":/")
		if end < 0 {
			end = len(rest)
		}
		host, rest = rest[:end], rest[end:]
		if !validIPv4(host) && !validRegName(host) {
			return false
		}
	}
	if strings.HasPrefix(rest, ":") {
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		if !validPort(rest[1:end]) {
			return false
		}
		rest = rest[end:]
	}
	if rest == "" {
		return true
	}
	// rest is now *( "/" segment ): it starts with "/" or the host was followed
	// by something the grammar does not allow.
	if rest[0] != '/' {
		return false
	}
	for _, segment := range strings.Split(rest[1:], "/") {
		if segment == "." || segment == ".." {
			return false
		}
		for i := 0; i < len(segment); i++ {
			if !isPchar(segment[i]) {
				return false
			}
		}
	}
	return true
}

// validPort is %x31-39 *4DIGIT, at most 65535, and not 443.
func validPort(port string) bool {
	if len(port) == 0 || len(port) > 5 || port[0] < '1' || port[0] > '9' {
		return false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if !isDigit(port[i]) {
			return false
		}
		n = n*10 + int(port[i]-'0')
	}
	return n <= 65535 && n != 443
}

func validIPv4(host string) bool {
	octets := strings.Split(host, ".")
	if len(octets) != 4 {
		return false
	}
	for _, octet := range octets {
		if len(octet) == 0 || len(octet) > 3 || (len(octet) > 1 && octet[0] == '0') {
			return false
		}
		n := 0
		for i := 0; i < len(octet); i++ {
			if !isDigit(octet[i]) {
				return false
			}
			n = n*10 + int(octet[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// validRegName is label *( "." label ) of at most 253 bytes whose final label
// does not start with a digit.
func validRegName(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !validLabel(label) {
			return false
		}
	}
	return !isDigit(labels[len(labels)-1][0])
}

// validLabel is lower-alnum [ *( lower-alnum / "-" ) lower-alnum ], 1 to 63 bytes.
func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !isLowerAlnum(c) && (c != '-' || i == 0 || i == len(label)-1) {
			return false
		}
	}
	return true
}

// canonicalIPv6 parses text as eight hexadecimal groups, re-serializes them by
// RFC 5952 sections 4.1 to 4.3 and requires the result to equal the input.
func canonicalIPv6(text string) bool {
	groups, ok := parseIPv6Groups(text)
	return ok && formatIPv6(groups) == text
}

func parseIPv6Groups(text string) ([8]uint16, bool) {
	var out [8]uint16
	head, tail, compressed := strings.Cut(text, "::")
	if compressed && strings.Contains(tail, "::") {
		return out, false
	}
	headGroups, ok := parseHexGroups(head)
	if !ok {
		return out, false
	}
	var tailGroups []uint16
	if compressed {
		if tailGroups, ok = parseHexGroups(tail); !ok {
			return out, false
		}
		if len(headGroups)+len(tailGroups) > 7 {
			return out, false
		}
	} else if len(headGroups) != 8 {
		return out, false
	}
	copy(out[:], headGroups)
	copy(out[8-len(tailGroups):], tailGroups)
	return out, true
}

// parseHexGroups splits colon-separated groups of 1 to 4 lowercase hex digits;
// the empty string is no groups.
func parseHexGroups(text string) ([]uint16, bool) {
	if text == "" {
		return nil, true
	}
	var groups []uint16
	for _, group := range strings.Split(text, ":") {
		if len(group) == 0 || len(group) > 4 {
			return nil, false
		}
		var n uint16
		for i := 0; i < len(group); i++ {
			c := group[i]
			switch {
			case isDigit(c):
				n = n<<4 | uint16(c-'0')
			case c >= 'a' && c <= 'f':
				n = n<<4 | uint16(c-'a'+10)
			default:
				return nil, false
			}
		}
		groups = append(groups, n)
	}
	return groups, true
}

// formatIPv6 writes lowercase groups without leading zeros and replaces the
// longest run of two or more zero groups, the leftmost on a tie, with "::".
func formatIPv6(groups [8]uint16) string {
	bestStart, bestLen := -1, 1
	for i := 0; i < len(groups); {
		if groups[i] != 0 {
			i++
			continue
		}
		j := i
		for j < len(groups) && groups[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	const digits = "0123456789abcdef"
	var b strings.Builder
	group := func(n uint16) {
		started := false
		for shift := 12; shift >= 0; shift -= 4 {
			d := n >> uint(shift) & 0xf
			if d != 0 || started || shift == 0 {
				b.WriteByte(digits[d])
				started = true
			}
		}
	}
	for i := 0; i < len(groups); i++ {
		if i == bestStart {
			b.WriteString("::")
			i += bestLen - 1
			continue
		}
		if i > 0 && i != bestStart+bestLen {
			b.WriteByte(':')
		}
		group(groups[i])
	}
	return b.String()
}

// validURNIdentifier checks nid ":" nss after "urn:". The nid is lowercase
// only (a profile tightening over RFC 8141) and is not converted.
func validURNIdentifier(rest string) bool {
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return false
	}
	nid, nss := rest[:colon], rest[colon+1:]
	if len(nid) < 2 || len(nid) > 32 || !validLabel(nid) || len(nss) == 0 || !isPchar(nss[0]) {
		return false
	}
	for i := 1; i < len(nss); i++ {
		if !isPchar(nss[i]) && nss[i] != '/' {
			return false
		}
	}
	return true
}
