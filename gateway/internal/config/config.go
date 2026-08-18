// Package config loads settings from the environment and fails fast.
//
// Deliberately no defaults for secrets: a gateway that silently starts with a
// development KEK in production is worse than one that refuses to boot.
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr          string
	DatabaseURL   string
	KEKPrimaryID  string
	KEKs          map[string][]byte
	TokenPepper   []byte
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	ShutdownGrace time.Duration
}

func Load() (Config, error) {
	c := Config{
		Addr:          env("PRESENCE_ADDR", ":8080"),
		DatabaseURL:   os.Getenv("PRESENCE_DATABASE_URL"),
		KEKPrimaryID:  env("PRESENCE_KEK_ID", "k1"),
		ReadTimeout:   envDuration("PRESENCE_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:  envDuration("PRESENCE_WRITE_TIMEOUT", 30*time.Second),
		ShutdownGrace: envDuration("PRESENCE_SHUTDOWN_GRACE", 20*time.Second),
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("PRESENCE_DATABASE_URL is required")
	}

	// PRESENCE_KEKS is "id:hex,id:hex" so old ciphertexts stay readable
	// through a key rotation.
	raw := os.Getenv("PRESENCE_KEKS")
	if raw == "" {
		return c, fmt.Errorf("PRESENCE_KEKS is required (format: id:hex64[,id:hex64])")
	}
	keys, err := parseKeys(raw)
	if err != nil {
		return c, err
	}
	c.KEKs = keys

	pepper := os.Getenv("PRESENCE_TOKEN_PEPPER")
	if pepper == "" {
		return c, fmt.Errorf("PRESENCE_TOKEN_PEPPER is required")
	}
	c.TokenPepper = []byte(pepper)
	return c, nil
}

func parseKeys(raw string) (map[string][]byte, error) {
	keys := map[string][]byte{}
	for _, part := range splitComma(raw) {
		id, hexKey, ok := cut(part, ':')
		if !ok {
			return nil, fmt.Errorf("PRESENCE_KEKS entry %q is not id:hex", part)
		}
		k, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("PRESENCE_KEKS entry %q: %w", id, err)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("PRESENCE_KEKS entry %q must be 32 bytes (64 hex chars), got %d", id, len(k))
		}
		keys[id] = k
	}
	return keys, nil
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func cut(s string, sep byte) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}
