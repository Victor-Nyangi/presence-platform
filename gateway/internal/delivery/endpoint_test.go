package delivery

import "testing"

func TestValidateEndpointRequiresHTTPSByDefault(t *testing.T) {
	if _, err := ValidateEndpoint(Policy{}, "http://example.com/webhook"); err == nil {
		t.Error("a plain http endpoint must be rejected by default: these payloads are personal data crossing a network")
	}
	if _, err := ValidateEndpoint(Policy{}, "https://example.com/webhook"); err != nil {
		t.Errorf("https must be accepted by default: %v", err)
	}
}

func TestValidateEndpointAllowInsecureHTTPOptOut(t *testing.T) {
	if _, err := ValidateEndpoint(Policy{AllowInsecureHTTP: true}, "http://example.com/webhook"); err != nil {
		t.Errorf("http must be accepted once explicitly opted into: %v", err)
	}
}

func TestValidateEndpointRejectsOtherSchemes(t *testing.T) {
	for _, u := range []string{"ftp://example.com/x", "file:///etc/passwd", "javascript:alert(1)"} {
		if _, err := ValidateEndpoint(Policy{AllowInsecureHTTP: true}, u); err == nil {
			t.Errorf("scheme in %q must be rejected", u)
		}
	}
}

func TestValidateEndpointRejectsPrivateAddressesByDefault(t *testing.T) {
	cases := []string{
		"https://127.0.0.1/webhook",
		"https://localhost/webhook",
		"https://169.254.169.254/webhook", // cloud metadata endpoint
		"https://10.0.0.5/webhook",
		"https://192.168.1.1/webhook",
		"https://0.0.0.0/webhook",
	}
	for _, u := range cases {
		if _, err := ValidateEndpoint(Policy{}, u); err == nil {
			t.Errorf("endpoint %q must be rejected by default", u)
		}
	}
}

func TestValidateEndpointAllowPrivateEndpointsOptOut(t *testing.T) {
	if _, err := ValidateEndpoint(Policy{AllowPrivateEndpoints: true}, "https://127.0.0.1/webhook"); err != nil {
		t.Errorf("localhost must be accepted once explicitly opted into: %v", err)
	}
}

func TestValidateEndpointAcceptsAnOrdinaryPublicHTTPSURL(t *testing.T) {
	// A literal public IP, not a hostname: this check has no business making
	// a real DNS query in a unit test, and the classification logic (which
	// is what's under test) doesn't care whether the host is a hostname or
	// a literal address.
	if _, err := ValidateEndpoint(Policy{}, "https://8.8.8.8/webhooks/presence"); err != nil {
		t.Errorf("an ordinary public https endpoint must be accepted: %v", err)
	}
}

func TestValidateEndpointRejectsMalformedURL(t *testing.T) {
	if _, err := ValidateEndpoint(Policy{}, "://not a url"); err == nil {
		t.Error("a malformed URL must be rejected")
	}
}
