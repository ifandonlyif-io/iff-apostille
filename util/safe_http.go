package util

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	ErrHTTPSRequired      = errors.New("HTTPS is required")
	ErrCredentialsInURL   = errors.New("URL credentials are not allowed")
	ErrFragmentNotAllowed = errors.New("URL fragments are not allowed")
	ErrQueryNotAllowed    = errors.New("URL query parameters are not allowed")
	ErrPortNotAllowed     = errors.New("only port 443 is allowed")
	ErrRedirectNotAllowed = errors.New("redirects are not followed")
	ErrURLTooLong         = errors.New("URL exceeds maximum length")
)

const MaxPublicHTTPSURLLength = 2048

// ambiguousIPv4HostLiteralPattern matches the legacy inet_aton family of
// one- to four-component IPv4 spellings. Components may be decimal/octal-like
// digits or 0x-prefixed hex, so this covers 2130706433, 017700000001, 127.1,
// 127.0.1, and 0x7f.1. Resolvers disagree on these forms, while Go's strict
// net.ParseIP intentionally does not recognize them; accepting one as DNS and
// later connecting through a resolver that treats it as an IP is unsafe.
var ambiguousIPv4HostLiteralPattern = regexp.MustCompile(
	`^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$`,
)

// isAmbiguousIPv4HostLiteral is a pure syntax check with no DNS dependency,
// so it is safe on read-only lookup paths as well as outbound request paths.
func isAmbiguousIPv4HostLiteral(hostname string) bool {
	return net.ParseIP(hostname) == nil && ambiguousIPv4HostLiteralPattern.MatchString(hostname)
}

// ValidatePublicHTTPSURL applies the narrower v3 product policy on top of the
// generic SSRF validator. It returns a normalized URL suitable for uniqueness
// checks and public display.
func ValidatePublicHTTPSURL(rawURL string, allowQuery bool) (string, error) {
	normalized, err := NormalizePublicHTTPSURL(rawURL, allowQuery)
	if err != nil {
		return "", err
	}
	if err := NewURLValidator().ValidateURL(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// NormalizePublicHTTPSURL applies syntax and product-policy checks without a
// DNS lookup. Use it for read-only evidence lookup so evidence remains
// available when a monitored endpoint is currently offline. Outbound requests
// and registration must use ValidatePublicHTTPSURL or NewSafeHTTPClient.
//
// This intentionally does NOT resolve or DNS-screen an ordinary hostname
// (e.g. a DNS-rebinding name like "127.0.0.1.nip.io"): doing so would give
// the public, unauthenticated read path a per-request DNS dependency, which
// is itself a new denial-of-service surface (a caller could force a lookup
// per request just by varying the query string). That screening already
// happens, without adding cost to this path, in ValidatePublicHTTPSURL
// below via URLValidator.ValidateURL, which only runs on registration and
// outbound-probing paths that already pay for a DNS round trip; those are
// also the only paths where a rebinding name is actually dangerous, since
// this read-only path never makes an outbound request with the URL it
// normalizes -- it is purely a database key lookup, so an unresolved
// rebinding-style hostname here can 404, never reach an internal address
// (see the corrected finding 10 of the 2026-08-29 audit). An ambiguous
// inet_aton-style IP literal (e.g. "2130706433", "127.1", or "0x7f.1") is
// different: it needs no DNS lookup to classify, so it is rejected
// syntactically below on every path, including this one.
func NormalizePublicHTTPSURL(rawURL string, allowQuery bool) (string, error) {
	if len(rawURL) == 0 || len(rawURL) > MaxPublicHTTPSURLLength {
		return "", ErrURLTooLong
	}
	// url.ParseRequestURI treats fragments differently because fragments are
	// not part of an HTTP request target. Here the input is an endpoint URL
	// embedded in JSON or a query parameter, so url.Parse is the correct parser
	// and lets us reject fragments explicitly.
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", ErrHTTPSRequired
	}
	if parsed.User != nil {
		return "", ErrCredentialsInURL
	}
	if parsed.Fragment != "" {
		return "", ErrFragmentNotAllowed
	}
	if !allowQuery && (parsed.RawQuery != "" || parsed.ForceQuery) {
		return "", ErrQueryNotAllowed
	}
	hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if hostname == "" {
		return "", fmt.Errorf("%w: empty hostname", ErrInvalidURL)
	}
	validator := NewURLValidator()
	if validator.isLocalhost(hostname) || strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".local") {
		return "", fmt.Errorf("%w: localhost not allowed", ErrPrivateIPNotAllowed)
	}
	// Read-only lookup deliberately does not resolve ordinary hostnames: public
	// evidence must remain retrievable while an endpoint is offline. Literal
	// addresses can still be classified without DNS and must never make a
	// private/reserved URL look like a valid public endpoint.
	if literalIP := net.ParseIP(hostname); literalIP != nil && validator.isPrivateIP(literalIP) {
		return "", fmt.Errorf("%w: literal private/reserved address", ErrPrivateIPNotAllowed)
	}
	// net.ParseIP only recognizes strict dotted-decimal/colon syntax, so
	// legacy one- to four-component inet_aton spellings slip past the literal
	// check above. Reject the whole ambiguous syntax family, even when a given
	// resolver would currently treat one member as an ordinary DNS name.
	if isAmbiguousIPv4HostLiteral(hostname) {
		return "", fmt.Errorf("%w: ambiguous IPv4 host literal not allowed", ErrPrivateIPNotAllowed)
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return "", ErrPortNotAllowed
	}
	parsed.Scheme = "https"
	parsed.Host = hostname
	if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	}
	if parsed.Port() == "443" {
		parsed.Host = net.JoinHostPort(hostname, "443")
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), nil
}

type SafeHTTPClientConfig struct {
	Timeout          time.Duration
	AllowPrivateIPs  bool
	AllowNonTLS      bool
	AllowNonStandard bool
	// MaxRedirects is the maximum number of redirect responses the client
	// follows. Zero keeps the default fail-closed policy used by probes,
	// adapters, and webhooks. Callers that opt in still get the same URL and
	// connection-time SSRF checks for every redirect hop.
	MaxRedirects int
	MaxIdleConns int
	Resolver     *net.Resolver
}

// NewSafeHTTPClient returns a client that validates the address at connection
// time and dials the validated IP directly. This closes the DNS validation /
// connection TOCTOU used by DNS rebinding attacks. Environment proxy settings
// are intentionally disabled. Redirects are rejected unless the caller sets a
// positive MaxRedirects; each followed hop is validated before it is sent and
// is then resolved and dialed through the same safe transport.
func NewSafeHTTPClient(config SafeHTTPClientConfig) *http.Client {
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxIdleConns <= 0 {
		config.MaxIdleConns = 20
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	validator := NewURLValidator().AllowPrivateIPs(config.AllowPrivateIPs)
	dialer := &net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		Proxy:                  nil,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    config.Timeout,
		ResponseHeaderTimeout:  config.Timeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
		MaxIdleConns:           config.MaxIdleConns,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        4,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid dial address: %w", err)
			}
			if !config.AllowNonStandard && port != "443" {
				if !(config.AllowNonTLS && port == "80") {
					return nil, ErrPortNotAllowed
				}
			}
			addresses, err := resolver.LookupIPAddr(ctx, host)
			if err != nil || len(addresses) == 0 {
				return nil, fmt.Errorf("%w: %v", ErrHostResolutionFailed, err)
			}
			for _, candidate := range addresses {
				if !config.AllowPrivateIPs && validator.isPrivateIP(candidate.IP) {
					continue
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
			}
			return nil, fmt.Errorf("%w: %s has no permitted address", ErrPrivateIPNotAllowed, host)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if config.MaxRedirects <= 0 || len(via) > config.MaxRedirects {
				return ErrRedirectNotAllowed
			}
			return validateSafeRedirectURL(req.URL, config)
		},
	}
}

// validateSafeRedirectURL applies the request-target portions of the safe
// client policy before net/http follows a redirect. DNS and private/reserved
// address validation intentionally remain in DialContext so the exact address
// used for every hop is checked immediately before connection.
func validateSafeRedirectURL(target *url.URL, config SafeHTTPClientConfig) error {
	if target == nil || len(target.String()) == 0 || len(target.String()) > MaxPublicHTTPSURLLength {
		return ErrURLTooLong
	}
	if target.Host == "" {
		return fmt.Errorf("%w: empty hostname", ErrInvalidURL)
	}
	if target.User != nil {
		return ErrCredentialsInURL
	}
	if target.Fragment != "" {
		return ErrFragmentNotAllowed
	}
	if target.RawQuery != "" || target.ForceQuery {
		return ErrQueryNotAllowed
	}
	hostname := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if hostname == "" {
		return fmt.Errorf("%w: empty hostname", ErrInvalidURL)
	}
	if !config.AllowPrivateIPs {
		validator := NewURLValidator()
		if validator.isLocalhost(hostname) || strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".local") {
			return fmt.Errorf("%w: localhost not allowed", ErrPrivateIPNotAllowed)
		}
		if literalIP := net.ParseIP(hostname); literalIP != nil && validator.isPrivateIP(literalIP) {
			return fmt.Errorf("%w: literal private/reserved address", ErrPrivateIPNotAllowed)
		}
		if isAmbiguousIPv4HostLiteral(hostname) {
			return fmt.Errorf("%w: ambiguous IPv4 host literal not allowed", ErrPrivateIPNotAllowed)
		}
	}

	switch strings.ToLower(target.Scheme) {
	case "https":
		if !config.AllowNonStandard {
			if port := target.Port(); port != "" && port != "443" {
				return ErrPortNotAllowed
			}
		}
	case "http":
		if !config.AllowNonTLS {
			return ErrHTTPSRequired
		}
		if !config.AllowNonStandard {
			if port := target.Port(); port != "" && port != "80" {
				return ErrPortNotAllowed
			}
		}
	default:
		return ErrHTTPSRequired
	}
	return nil
}
