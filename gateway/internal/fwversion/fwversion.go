// Package fwversion parses terminal firmware versions.
//
// A version is exactly MAJOR.MINOR.PATCH: decimal, 0-65535 each, no leading
// zeros, no sign, no pre-release suffix. The strictness is the point. The
// version is part of what the OTA release key signs, and the terminal refuses
// any image that is not strictly newer than both its running build and the
// highest version it has proved healthy on. Two spellings of one number, or a
// suffix one side ignores, would let the signer, the gateway and the terminal
// disagree about which image is newer.
//
// firmware/src/ota_verify.h (otaVersionCode) implements the same grammar, and
// both sides test the same table of cases.
package fwversion

import (
	"errors"
	"fmt"
)

var ErrInvalid = errors.New("fwversion: not MAJOR.MINOR.PATCH (0-65535 each, no leading zeros)")

// MaxLen is the longest valid version, "65535.65535.65535".
const MaxLen = 17

// Parse returns v packed as major<<32 | minor<<16 | patch, which orders the
// same way the versions do.
func Parse(v string) (uint64, error) {
	if len(v) == 0 || len(v) > MaxLen {
		return 0, ErrInvalid
	}
	var code uint64
	i := 0
	for part := 0; part < 3; part++ {
		if i >= len(v) || v[i] < '0' || v[i] > '9' {
			return 0, ErrInvalid
		}
		if v[i] == '0' && i+1 < len(v) && v[i+1] >= '0' && v[i+1] <= '9' {
			return 0, ErrInvalid
		}
		var n uint64
		digits := 0
		for i < len(v) && v[i] >= '0' && v[i] <= '9' {
			n = n*10 + uint64(v[i]-'0')
			i++
			digits++
			if digits > 5 {
				return 0, ErrInvalid
			}
		}
		if n > 65535 {
			return 0, ErrInvalid
		}
		code = code<<16 | n
		if part < 2 {
			if i >= len(v) || v[i] != '.' {
				return 0, ErrInvalid
			}
			i++
		}
	}
	if i != len(v) {
		return 0, ErrInvalid
	}
	return code, nil
}

// Valid reports whether v parses.
func Valid(v string) bool {
	_, err := Parse(v)
	return err == nil
}

// Format is the inverse of Parse.
func Format(code uint64) string {
	return fmt.Sprintf("%d.%d.%d", code>>32&0xFFFF, code>>16&0xFFFF, code&0xFFFF)
}

// Newer reports whether candidate is strictly newer than current. Either
// failing to parse is an error, never a guess.
func Newer(candidate, current string) (bool, error) {
	c, err := Parse(candidate)
	if err != nil {
		return false, fmt.Errorf("candidate %q: %w", candidate, err)
	}
	r, err := Parse(current)
	if err != nil {
		return false, fmt.Errorf("current %q: %w", current, err)
	}
	return c > r, nil
}
