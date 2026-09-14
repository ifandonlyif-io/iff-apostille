package util

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLValidator_ValidateURL(t *testing.T) {
	validator := NewURLValidator()

	t.Run("valid public URLs", func(t *testing.T) {
		// Only use URLs that can actually be resolved
		validURLs := []string{
			"https://example.com",
			"https://example.com/path",
			"https://example.com:443/path",
			"http://example.com",
			"https://google.com",
			"https://www.google.com/search",
		}
		for _, url := range validURLs {
			err := validator.ValidateURL(url)
			assert.NoError(t, err, "URL should be valid: %s", url)
		}
	})

	t.Run("invalid schemes", func(t *testing.T) {
		invalidSchemes := []string{
			"ftp://example.com",
			"file:///etc/passwd",
			"gopher://example.com",
			"dict://example.com",
			"ldap://example.com",
			"sftp://example.com",
		}
		for _, url := range invalidSchemes {
			err := validator.ValidateURL(url)
			assert.ErrorIs(t, err, ErrDisallowedScheme, "URL should have disallowed scheme: %s", url)
		}
	})

	t.Run("localhost variants blocked", func(t *testing.T) {
		localhostURLs := []string{
			"http://localhost",
			"http://localhost:8080",
			"http://localhost:8080/path",
			"https://localhost",
			"http://127.0.0.1",
			"http://127.0.0.1:8080",
			"http://127.0.0.1:8080/api",
			"http://0.0.0.0",
			"http://0.0.0.0:8080",
		}
		for _, url := range localhostURLs {
			err := validator.ValidateURL(url)
			assert.ErrorIs(t, err, ErrPrivateIPNotAllowed, "localhost should be blocked: %s", url)
		}
	})

	t.Run("invalid URLs", func(t *testing.T) {
		invalidURLs := []string{
			"",
			"not-a-url",
			"://missing-scheme.com",
			"http://",
			"https://",
		}
		for _, url := range invalidURLs {
			err := validator.ValidateURL(url)
			assert.Error(t, err, "URL should be invalid: %s", url)
		}
	})
}

func TestURLValidator_AllowPrivateIPs(t *testing.T) {
	t.Run("localhost allowed when enabled", func(t *testing.T) {
		validator := NewURLValidator().AllowPrivateIPs(true)
		err := validator.ValidateURL("http://localhost:8080")
		assert.NoError(t, err)
	})

	t.Run("127.0.0.1 allowed when enabled", func(t *testing.T) {
		validator := NewURLValidator().AllowPrivateIPs(true)
		err := validator.ValidateURL("http://127.0.0.1:8080")
		assert.NoError(t, err)
	})
}

func TestURLValidator_isPrivateIP(t *testing.T) {
	validator := NewURLValidator()

	testCases := []struct {
		ip        string
		isPrivate bool
		name      string
	}{
		// Loopback
		{"127.0.0.1", true, "IPv4 loopback"},
		{"127.255.255.255", true, "IPv4 loopback end"},
		{"::1", true, "IPv6 loopback"},

		// Private IPv4
		{"10.0.0.1", true, "10.x.x.x private"},
		{"10.255.255.255", true, "10.x.x.x private end"},
		{"172.16.0.1", true, "172.16.x.x private"},
		{"172.31.255.255", true, "172.31.x.x private end"},
		{"192.168.0.1", true, "192.168.x.x private"},
		{"192.168.255.255", true, "192.168.x.x private end"},

		// Link-local
		{"169.254.0.1", true, "IPv4 link-local"},
		{"169.254.255.255", true, "IPv4 link-local end"},
		{"fe80::1", true, "IPv6 link-local"},

		// Unspecified
		{"0.0.0.0", true, "IPv4 unspecified"},
		{"::", true, "IPv6 unspecified"},

		// CGNAT (Shared address space)
		{"100.64.0.1", true, "CGNAT start"},
		{"100.127.255.255", true, "CGNAT end"},
		{"100.63.255.255", false, "Before CGNAT"},
		{"100.128.0.0", false, "After CGNAT"},

		// Test networks
		{"192.0.2.1", true, "TEST-NET-1"},
		{"198.51.100.1", true, "TEST-NET-2"},
		{"203.0.113.1", true, "TEST-NET-3"},
		{"198.18.0.1", true, "benchmark network start"},
		{"198.19.255.255", true, "benchmark network end"},
		{"192.88.99.1", true, "deprecated 6to4 relay"},

		// Multicast
		{"224.0.0.1", true, "IPv4 multicast"},
		{"239.255.255.255", true, "IPv4 multicast end"},

		// Reserved
		{"240.0.0.1", true, "IPv4 reserved"},
		{"255.255.255.255", true, "IPv4 broadcast"},

		// Public IPs (should not be blocked)
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"93.184.216.34", false, "example.com IP"},
		{"2606:2800:220:1:248:1893:25c8:1946", false, "IPv6 public"},

		// IPv6 private (ULA)
		{"fc00::1", true, "IPv6 ULA"},
		{"fd00::1", true, "IPv6 ULA"},
		{"100::1", true, "IPv6 discard-only"},
		{"2001:db8::1", true, "IPv6 documentation"},
		{"3fff::1", true, "IPv6 documentation 2"},
		{"2002:c000:0201::1", true, "deprecated IPv6 6to4"},

		// Current network
		{"0.1.2.3", true, "0.x.x.x current network"},

		// IETF protocol assignments
		{"192.0.0.1", true, "IETF protocol assignments"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			require.NotNil(t, ip, "failed to parse IP: %s", tc.ip)
			result := validator.isPrivateIP(ip)
			assert.Equal(t, tc.isPrivate, result, "IP %s: expected isPrivate=%v, got %v", tc.ip, tc.isPrivate, result)
		})
	}
}

func TestURLValidator_isLocalhost(t *testing.T) {
	validator := NewURLValidator()

	testCases := []struct {
		hostname    string
		isLocalhost bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"LocalHost", true},
		{"localhost.localdomain", true},
		{"local", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"[::1]", true},
		{"example.com", false},
		{"localhost.example.com", false},
		{"mylocalhostserver.com", false},
	}

	for _, tc := range testCases {
		t.Run(tc.hostname, func(t *testing.T) {
			result := validator.isLocalhost(tc.hostname)
			assert.Equal(t, tc.isLocalhost, result, "hostname %s: expected isLocalhost=%v, got %v", tc.hostname, tc.isLocalhost, result)
		})
	}
}

func TestURLValidator_isAllowedScheme(t *testing.T) {
	validator := NewURLValidator()

	testCases := []struct {
		scheme  string
		allowed bool
	}{
		{"http", true},
		{"HTTP", true},
		{"https", true},
		{"HTTPS", true},
		{"ftp", false},
		{"file", false},
		{"gopher", false},
		{"dict", false},
		{"ldap", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.scheme, func(t *testing.T) {
			result := validator.isAllowedScheme(tc.scheme)
			assert.Equal(t, tc.allowed, result)
		})
	}
}

func TestValidateEndpointURL(t *testing.T) {
	t.Run("valid URL", func(t *testing.T) {
		err := ValidateEndpointURL("https://example.com/api")
		assert.NoError(t, err)
	})

	t.Run("localhost blocked", func(t *testing.T) {
		err := ValidateEndpointURL("http://localhost:8080")
		assert.ErrorIs(t, err, ErrPrivateIPNotAllowed)
	})

	t.Run("invalid scheme", func(t *testing.T) {
		err := ValidateEndpointURL("ftp://example.com")
		assert.ErrorIs(t, err, ErrDisallowedScheme)
	})
}
