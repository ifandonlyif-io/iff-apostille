package util

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	ErrInvalidURL           = errors.New("invalid URL")
	ErrDisallowedScheme     = errors.New("URL scheme not allowed")
	ErrPrivateIPNotAllowed  = errors.New("private/internal IP addresses not allowed")
	ErrHostResolutionFailed = errors.New("failed to resolve host")
)

// URLValidator validates URLs to prevent SSRF attacks.
type URLValidator struct {
	allowedSchemes  []string
	allowPrivateIPs bool
}

// NewURLValidator creates a new URL validator with default settings.
// By default, only http and https schemes are allowed, and private IPs are blocked.
func NewURLValidator() *URLValidator {
	return &URLValidator{
		allowedSchemes:  []string{"http", "https"},
		allowPrivateIPs: false,
	}
}

// AllowPrivateIPs sets whether private IP addresses should be allowed.
// This should only be enabled for testing purposes.
func (v *URLValidator) AllowPrivateIPs(allow bool) *URLValidator {
	v.allowPrivateIPs = allow
	return v
}

// ValidateURL validates a URL for safe probing.
// It checks the scheme, resolves the hostname, and verifies the IP is not private.
func (v *URLValidator) ValidateURL(rawURL string) error {
	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	// Check scheme
	if !v.isAllowedScheme(parsedURL.Scheme) {
		return fmt.Errorf("%w: %s (allowed: %v)", ErrDisallowedScheme, parsedURL.Scheme, v.allowedSchemes)
	}

	// Extract hostname (without port)
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return fmt.Errorf("%w: empty hostname", ErrInvalidURL)
	}

	// Check for localhost variants
	if v.isLocalhost(hostname) {
		if !v.allowPrivateIPs {
			return fmt.Errorf("%w: localhost not allowed", ErrPrivateIPNotAllowed)
		}
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHostResolutionFailed, err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("%w: no IP addresses found for host", ErrHostResolutionFailed)
	}

	// Check all resolved IPs
	if !v.allowPrivateIPs {
		for _, ip := range ips {
			if v.isPrivateIP(ip) {
				return fmt.Errorf("%w: %s resolves to private IP %s", ErrPrivateIPNotAllowed, hostname, ip.String())
			}
		}
	}

	return nil
}

// isAllowedScheme checks if the URL scheme is allowed.
func (v *URLValidator) isAllowedScheme(scheme string) bool {
	scheme = strings.ToLower(scheme)
	for _, allowed := range v.allowedSchemes {
		if scheme == allowed {
			return true
		}
	}
	return false
}

// isLocalhost checks if the hostname is a localhost variant.
func (v *URLValidator) isLocalhost(hostname string) bool {
	hostname = strings.ToLower(hostname)
	localhostVariants := []string{
		"localhost",
		"localhost.localdomain",
		"local",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"[::1]",
	}
	for _, local := range localhostVariants {
		if hostname == local {
			return true
		}
	}
	return false
}

// isPrivateIP checks if an IP address is private/internal.
func (v *URLValidator) isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Ranges the standard library already classifies: unspecified (0.0.0.0, ::),
	// loopback (127.x.x.x, ::1), RFC1918 private (10/8, 172.16/12, 192.168/16,
	// fc00::/7), and link-local (169.254/16, fe80::/10).
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Additional reserved ranges the stdlib does not flag. To4() is non-nil for
	// both 4-byte IPv4 and IPv4-mapped IPv6 addresses.
	if ip4 := ip.To4(); ip4 != nil {
		return isReservedIPv4(ip4)
	}
	return isReservedIPv6(ip)
}

// isReservedIPv4 reports whether an IPv4 address falls in a reserved or
// special-use range that should be blocked for SSRF protection (beyond the
// private ranges already covered by the net.IP helpers).
func isReservedIPv4(ip4 net.IP) bool {
	switch {
	case ip4[0] == 0: // 0.0.0.0/8 - current network
		return true
	case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // 100.64.0.0/10 - CGNAT
		return true
	case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0: // 192.0.0.0/24 - IETF protocol assignments
		return true
	case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2: // 192.0.2.0/24 - TEST-NET-1
		return true
	case ip4[0] == 192 && ip4[1] == 88 && ip4[2] == 99: // 192.88.99.0/24 - deprecated 6to4 relay anycast
		return true
	case ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19): // 198.18.0.0/15 - benchmark testing
		return true
	case ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100: // 198.51.100.0/24 - TEST-NET-2
		return true
	case ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113: // 203.0.113.0/24 - TEST-NET-3
		return true
	case ip4[0] >= 224 && ip4[0] <= 239: // 224.0.0.0/4 - multicast
		return true
	case ip4[0] >= 240: // 240.0.0.0/4 - reserved
		return true
	default:
		return false
	}
}

// isReservedIPv6 reports whether an IPv6 address falls in a reserved range
// (site-local or multicast) that should be blocked.
func isReservedIPv6(ip net.IP) bool {
	if len(ip) != net.IPv6len {
		return true
	}
	// Site-local fec0::/10 - deprecated but still blocked.
	if ip[0] == 0xfe && (ip[1]&0xc0) == 0xc0 {
		return true
	}
	// 100::/64 is discard-only; 2001:db8::/32 and 3fff::/20 are
	// documentation ranges; 2002::/16 is the deprecated 6to4 range. None is a
	// valid production monitor target, and 6to4 can indirectly encode IPv4.
	if isIPv6Prefix(ip, net.ParseIP("100::"), 64) ||
		isIPv6Prefix(ip, net.ParseIP("2001:db8::"), 32) ||
		isIPv6Prefix(ip, net.ParseIP("3fff::"), 20) ||
		isIPv6Prefix(ip, net.ParseIP("2002::"), 16) {
		return true
	}
	// Multicast ff00::/8.
	return ip.IsMulticast()
}

func isIPv6Prefix(ip, network net.IP, prefixBits int) bool {
	mask := net.CIDRMask(prefixBits, net.IPv6len*8)
	return network != nil && ip.Mask(mask).Equal(network.Mask(mask))
}

// ValidateEndpointURL is a convenience function to validate an endpoint URL.
// It uses the default validator settings (no private IPs allowed).
func ValidateEndpointURL(rawURL string) error {
	return NewURLValidator().ValidateURL(rawURL)
}
