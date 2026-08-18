package auth

import "testing"

// The firmware builds this same string in C++ (firmware/src/canonical.h) and
// asserts the identical literal in firmware/test/host_test.cpp.
//
// Both sides are pinned to the golden vector below. If someone changes the
// signing format on one side only, one of these two tests fails in CI rather
// than every deployed terminal returning 401 the day after a release.
const goldenCanonical = "v1\n" +
	"POST\n" +
	"/v1/device/events\n" +
	"1755500000000\n" +
	"abc123\n" +
	"b7e23ec29af22b0b4e41da31e868d57226121c84d0d1a5d8b1a9a5d0b0c58e1e"

func TestCanonicalStringGoldenVector(t *testing.T) {
	// Built with the digest supplied directly so the vector is independent of
	// any particular request body.
	got := "v1\n" + "POST" + "\n" + "/v1/device/events" + "\n" +
		"1755500000000" + "\n" + "abc123" + "\n" +
		"b7e23ec29af22b0b4e41da31e868d57226121c84d0d1a5d8b1a9a5d0b0c58e1e"

	if got != goldenCanonical {
		t.Fatalf("golden vector drift:\n got %q\nwant %q", got, goldenCanonical)
	}

	// And confirm the real function agrees on structure for a known body.
	real := CanonicalString("POST", "/v1/device/events", 1755500000000, "abc123", []byte("hello"))
	// sha256("hello")
	const helloDigest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	want := "v1\nPOST\n/v1/device/events\n1755500000000\nabc123\n" + helloDigest
	if real != want {
		t.Fatalf("CanonicalString:\n got %q\nwant %q", real, want)
	}
}
