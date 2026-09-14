package util

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidatePublicHTTPSURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr error
	}{
		{name: "valid", url: "https://example.com/paid"},
		{name: "valid strict public ipv4", url: "https://8.8.8.8/paid"},
		{name: "http", url: "http://example.com/paid", wantErr: ErrHTTPSRequired},
		{name: "userinfo", url: "https://user:pass@example.com/paid", wantErr: ErrCredentialsInURL},
		{name: "query", url: "https://example.com/paid?token=secret", wantErr: ErrQueryNotAllowed},
		{name: "empty query delimiter", url: "https://example.com/paid?", wantErr: ErrQueryNotAllowed},
		{name: "fragment", url: "https://example.com/paid#section", wantErr: ErrFragmentNotAllowed},
		{name: "port", url: "https://example.com:8443/paid", wantErr: ErrPortNotAllowed},
		{name: "loopback ipv4", url: "https://127.0.0.1/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "loopback ipv6", url: "https://[::1]/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "localhost", url: "https://api.localhost/paid", wantErr: ErrPrivateIPNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidatePublicHTTPSURL(test.url, false)
			if test.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.True(t, errors.Is(err, test.wantErr), "got %v", err)
		})
	}
}

func TestSafeHTTPClientRedirectPolicy(t *testing.T) {
	redirectClient := NewSafeHTTPClient(SafeHTTPClientConfig{MaxRedirects: 5})
	redirectRequest := func(t *testing.T, rawURL string) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		require.NoError(t, err)
		return req
	}
	via := func(count int) []*http.Request {
		requests := make([]*http.Request, count)
		for i := range requests {
			requests[i] = redirectRequest(t, "https://origin.example/robots.txt")
		}
		return requests
	}

	require.NoError(t, redirectClient.CheckRedirect(
		redirectRequest(t, "https://other.example/robots.txt"), via(1),
	), "a safe cross-authority robots redirect is allowed")

	tests := []struct {
		name    string
		url     string
		via     int
		wantErr error
	}{
		{name: "downgrade", url: "http://other.example/robots.txt", via: 1, wantErr: ErrHTTPSRequired},
		{name: "query", url: "https://other.example/robots.txt?token=secret", via: 1, wantErr: ErrQueryNotAllowed},
		{name: "empty query delimiter", url: "https://other.example/robots.txt?", via: 1, wantErr: ErrQueryNotAllowed},
		{name: "credentials", url: "https://user:pass@other.example/robots.txt", via: 1, wantErr: ErrCredentialsInURL},
		{name: "fragment", url: "https://other.example/robots.txt#policy", via: 1, wantErr: ErrFragmentNotAllowed},
		{name: "private literal", url: "https://127.0.0.1/robots.txt", via: 1, wantErr: ErrPrivateIPNotAllowed},
		{name: "reserved literal", url: "https://203.0.113.9/robots.txt", via: 1, wantErr: ErrPrivateIPNotAllowed},
		{name: "nonstandard port", url: "https://other.example:8443/robots.txt", via: 1, wantErr: ErrPortNotAllowed},
		{name: "more than five hops", url: "https://other.example/robots.txt", via: 6, wantErr: ErrRedirectNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := redirectClient.CheckRedirect(redirectRequest(t, test.url), via(test.via))
			require.ErrorIs(t, err, test.wantErr)
		})
	}

	defaultClient := NewSafeHTTPClient(SafeHTTPClientConfig{})
	err := defaultClient.CheckRedirect(
		redirectRequest(t, "https://other.example/robots.txt"), via(1),
	)
	require.ErrorIs(t, err, ErrRedirectNotAllowed, "all non-robots clients remain no-redirect by default")
}

// TestValidatePublicHTTPSURL_RejectionCorpus is the required regression
// corpus for finding 10 of the 2026-08-29 audit: every one of these forms
// must fail AT VALIDATION (ValidatePublicHTTPSURL returning an error, which
// handlers turn into 400) rather than surface later as a 404 from a DB
// lookup or, worse, an outbound connection attempt. "127.0.0.1.nip.io"
// depends on live DNS resolving to 127.0.0.1 (nip.io is a public wildcard-
// DNS rebinding service), the same way TestURLValidator_ValidateURL's
// "valid public URLs" subtest already depends on live DNS for example.com.
func TestValidatePublicHTTPSURL_RejectionCorpus(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "dotted-decimal loopback", url: "https://127.0.0.1/x"},
		{name: "dotted-decimal RFC1918 10/8", url: "https://10.1.2.3/x"},
		{name: "dotted-decimal RFC1918 172.16/12", url: "https://172.16.0.1/x"},
		{name: "dotted-decimal RFC1918 192.168/16", url: "https://192.168.1.1/x"},
		{name: "dotted-decimal link-local metadata address", url: "https://169.254.169.254/x"},
		{name: "decimal-integer host", url: "https://2130706433/x"},
		{name: "hex-integer host", url: "https://0x7f000001/x"},
		{name: "two-component decimal loopback", url: "https://127.1/x"},
		{name: "three-component decimal loopback", url: "https://127.0.1/x"},
		{name: "two-component hex loopback", url: "https://0x7f.1/x"},
		{name: "mixed-radix loopback", url: "https://127.0x0.0.1/x"},
		{name: "octal loopback", url: "https://0177.1/x"},
		{name: "octal RFC1918", url: "https://0300.0250.0001.0001/x"},
		{name: "nip.io-style DNS-rebinding name", url: "https://127.0.0.1.nip.io/x"},
		{name: "ipv6 loopback", url: "https://[::1]/x"},
		{name: "ipv6 ULA fc00::/7", url: "https://[fc00::1]/x"},
		{name: "ipv6 ULA fd00::/8", url: "https://[fd12:3456::1]/x"},
		{name: "ipv6 link-local", url: "https://[fe80::1]/x"},
		{name: "non-443 port", url: "https://example.com:8443/x"},
		{name: "credentials in URL", url: "https://user:pass@example.com/x"},
		{name: "query string", url: "https://example.com/x?token=secret"},
		{name: "fragment", url: "https://example.com/x#section"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			normalized, err := ValidatePublicHTTPSURL(test.url, false)
			require.Error(t, err, "expected validation to reject %s, got normalized=%q", test.url, normalized)
		})
	}
}

func TestIsAmbiguousIPv4HostLiteral(t *testing.T) {
	positive := []string{
		"2130706433", "0x7f000001", "017700000001", "0", "0x0",
		"127.1", "127.0.1", "0x7f.1", "127.0x0.0.1", "0177.1",
		"0300.0250.0001.0001", "8.8",
	}
	for _, host := range positive {
		require.True(t, isAmbiguousIPv4HostLiteral(host), host)
	}
	negative := []string{
		"example.com", "0x7f000001.example.com", "api-2130706433.example.com",
		"8.8.8.8", "127.0.0.1", "1.2.3.4.5", "127.0.0.example", "",
	}
	for _, host := range negative {
		require.False(t, isAmbiguousIPv4HostLiteral(host), host)
	}
}

func TestNormalizePublicHTTPSURLDoesNotRequireLiveDNS(t *testing.T) {
	normalized, err := NormalizePublicHTTPSURL("https://Offline.Example.Invalid.:443/paid", false)
	require.NoError(t, err)
	require.Equal(t, "https://offline.example.invalid/paid", normalized)
}

func TestNormalizePublicHTTPSURLRejectsInvalidLookupURLsWithoutDNS(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr error
	}{
		{name: "fragment", url: "https://example.invalid/paid#fragment", wantErr: ErrFragmentNotAllowed},
		{name: "private ipv4", url: "https://10.0.0.1/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "reserved ipv4", url: "https://203.0.113.9/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "local name", url: "https://service.local/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "too long", url: "https://example.invalid/" + strings.Repeat("a", MaxPublicHTTPSURLLength), wantErr: ErrURLTooLong},
		// Legacy one- to four-component inet_aton hosts must be rejected here
		// without a DNS lookup: net.ParseIP recognizes only strict dotted-
		// decimal/colon syntax, so these forms previously slipped past the
		// literal-IP check and normalized successfully (finding 10 of the
		// 2026-08-29 audit -- reproduced live against the read-only
		// GET /api/v3/evidence/check?url= endpoint, which uses exactly this
		// function and returned a misleading 404 instead of 400).
		{name: "decimal-integer host", url: "https://2130706433/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "hex-integer host", url: "https://0x7f000001/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "two-component decimal host", url: "https://127.1/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "three-component decimal host", url: "https://127.0.1/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "two-component hex host", url: "https://0x7f.1/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "mixed-radix host", url: "https://127.0x0.0.1/paid", wantErr: ErrPrivateIPNotAllowed},
		{name: "octal host", url: "https://0177.1/paid", wantErr: ErrPrivateIPNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizePublicHTTPSURL(test.url, false)
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}
