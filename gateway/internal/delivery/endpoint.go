package delivery

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Policy governs what endpoint URL this service will accept. The endpoint
// here is operator-set configuration (PRESENCE_EMITTER_ENDPOINT_URL), not a
// caller-supplied value accepted from any HTTP request — presence-platform
// has no API that registers or changes it at runtime. That is a materially
// different threat model from fhir-facade's Subscription registration
// (any authenticated caller could register any URL there), and this
// deliberately does not port that sibling's full defence: no per-dial fresh
// DNS re-resolution to close a rebinding window, because there is no window
// an adversary opens between "an operator sets this in config" and "the
// process starts using it" the way there is between "a caller registers a
// URL" and "a retry fires hours later." What DOES carry over, because it
// costs almost nothing and the reasoning is the same regardless of who
// supplied the URL: reject the scheme and address range up front (a config
// mistake is still worth catching at startup, fail-fast, same as
// config.Load already does for secrets), and never follow a redirect (a
// compromised or misconfigured endpoint answering with a 3xx to an internal
// address would otherwise defeat validation entirely regardless of threat
// model).
type Policy struct {
	// AllowInsecureHTTP permits a plain http:// endpoint. Off by default:
	// these payloads are attendance records about identified people —
	// personal data crossing a network — and HMAC signing gives origin and
	// integrity, not confidentiality. A plaintext endpoint means anyone who
	// can observe the traffic reads real people's attendance history. On
	// for local development only, and logged loudly at startup when set, so
	// a permissive deployment can never happen by omission — the same
	// explicit-opt-out shape fhir-facade uses for its own localhost escape
	// hatch (SUBSCRIPTION_ALLOW_PRIVATE_ENDPOINTS).
	AllowInsecureHTTP bool

	// AllowPrivateEndpoints permits an endpoint that resolves to a
	// loopback/link-local/private/unspecified address. Off by default, for
	// the same "config error or a compromised value should not silently
	// reach an internal address" reason the task asked for explicitly. On
	// for local development only (a subscriber running on localhost), and
	// likewise logged loudly at startup when set.
	AllowPrivateEndpoints bool
}

// ValidateEndpoint parses and checks rawURL against policy. Called once at
// startup (fail fast, same posture as config.Load) rather than per delivery
// — this is config, not a value that changes at runtime.
func ValidateEndpoint(policy Policy, rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("delivery: malformed endpoint URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		// always fine
	case "http":
		if !policy.AllowInsecureHTTP {
			return nil, fmt.Errorf("delivery: endpoint %q is http, not https (set PRESENCE_EMITTER_ALLOW_INSECURE_HTTP=true only for local development)", rawURL)
		}
	default:
		return nil, fmt.Errorf("delivery: endpoint scheme %q is not http or https", u.Scheme)
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("delivery: endpoint %q has no host", rawURL)
	}
	if !policy.AllowPrivateEndpoints {
		if err := checkNotPrivate(u.Hostname()); err != nil {
			return nil, fmt.Errorf("delivery: endpoint %q: %w (set PRESENCE_EMITTER_ALLOW_PRIVATE_ENDPOINTS=true only for local development)", rawURL, err)
		}
	}
	return u, nil
}

// checkNotPrivate resolves host and rejects it if ANY resolved address is
// loopback, link-local, private/unique-local, multicast, or unspecified —
// net.IP's own classifiers, not a hand-rolled CIDR table, matching the
// sibling facade's approach for the same category of check.
func checkNotPrivate(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		return checkAddr(ip)
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("could not resolve host: %w", err)
	}
	for _, ip := range addrs {
		if err := checkAddr(ip); err != nil {
			return err
		}
	}
	return nil
}

func checkAddr(ip net.IP) error {
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("resolves to a loopback address (%s)", ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("resolves to a link-local address (%s)", ip)
	case ip.IsPrivate():
		return fmt.Errorf("resolves to a private address (%s)", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("resolves to the unspecified address (%s)", ip)
	case ip.IsMulticast():
		return fmt.Errorf("resolves to a multicast address (%s)", ip)
	}
	return nil
}

// NewHTTPClient returns the client the worker delivers with: redirects are
// never followed. An endpoint that passed ValidateEndpoint but answers with
// a 3xx to a disallowed address would otherwise defeat that validation
// entirely; treating any 3xx as an ordinary delivery failure (subject to
// the usual retry/backoff) is simpler to audit than "follow only if the
// target also validates," for a case that isn't a legitimate use of a
// webhook endpoint to begin with.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
