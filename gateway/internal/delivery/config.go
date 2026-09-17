package delivery

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// LoadConfig reads the emitter's settings from the environment. Separate
// from internal/config.Load on purpose: that loader backs the always-on
// gateway and treats every setting as required, but the emitter is optional
// infrastructure — not every presence-platform deployment has a downstream
// consumer configured yet. The optionality is "don't run this binary," not
// "run it in some disabled state," so once cmd/deliver IS being started,
// its settings are required and it fails fast exactly like config.Load
// does for the gateway's own secrets.
func LoadConfig() (Config, error) {
	rawURL := os.Getenv("PRESENCE_EMITTER_ENDPOINT_URL")
	if rawURL == "" {
		return Config{}, fmt.Errorf("PRESENCE_EMITTER_ENDPOINT_URL is required")
	}

	rawSecret := os.Getenv("PRESENCE_EMITTER_SIGNING_SECRET")
	if rawSecret == "" {
		return Config{}, fmt.Errorf("PRESENCE_EMITTER_SIGNING_SECRET is required (format: hex)")
	}
	secret, err := hex.DecodeString(rawSecret)
	if err != nil {
		return Config{}, fmt.Errorf("PRESENCE_EMITTER_SIGNING_SECRET: %w", err)
	}
	if len(secret) < 32 {
		return Config{}, fmt.Errorf("PRESENCE_EMITTER_SIGNING_SECRET must be at least 32 bytes (64 hex chars), got %d", len(secret))
	}

	keyID := os.Getenv("PRESENCE_EMITTER_KEY_ID")
	if keyID == "" {
		return Config{}, fmt.Errorf("PRESENCE_EMITTER_KEY_ID is required")
	}

	policy := Policy{
		AllowInsecureHTTP:     envBool("PRESENCE_EMITTER_ALLOW_INSECURE_HTTP"),
		AllowPrivateEndpoints: envBool("PRESENCE_EMITTER_ALLOW_PRIVATE_ENDPOINTS"),
	}
	// Logged loudly at startup, mirroring fhir-facade's own posture for its
	// equivalent escape hatch: a permissive deployment must never happen by
	// omission or by a value nobody notices in an env file.
	if policy.AllowInsecureHTTP {
		fmt.Fprintln(os.Stderr, "WARNING: PRESENCE_EMITTER_ALLOW_INSECURE_HTTP=true — delivering attendance records over plaintext HTTP. Do not use this outside local development.")
	}
	if policy.AllowPrivateEndpoints {
		fmt.Fprintln(os.Stderr, "WARNING: PRESENCE_EMITTER_ALLOW_PRIVATE_ENDPOINTS=true — the configured endpoint may resolve to a loopback/private/link-local address. Do not use this outside local development.")
	}

	endpoint, err := ValidateEndpoint(policy, rawURL)
	if err != nil {
		return Config{}, err
	}

	return Config{
		Endpoint:     endpoint,
		Secret:       secret,
		KeyID:        keyID,
		PollInterval: envDuration("PRESENCE_EMITTER_POLL_INTERVAL", 5*time.Second),
		HTTPTimeout:  envDuration("PRESENCE_EMITTER_HTTP_TIMEOUT", 10*time.Second),
	}, nil
}

func envBool(k string) bool {
	return os.Getenv(k) == "true"
}

func envDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}
