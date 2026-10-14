package fwversion

import "testing"

// The same table is in firmware/test/host_test.cpp (testVersionGrammar).
// If the two grammars drift, the gateway can offer an image the terminal
// cannot compare, or call a build newer that the terminal calls older.
var cases = []struct {
	in   string
	ok   bool
	code uint64
}{
	{"0.0.0", true, 0},
	{"0.1.0", true, 1 << 16},
	{"1.2.3", true, 1<<32 | 2<<16 | 3},
	{"65535.65535.65535", true, 65535<<32 | 65535<<16 | 65535},
	{"10.0.1", true, 10<<32 | 1},
	{"", false, 0},
	{"1", false, 0},
	{"1.2", false, 0},
	{"1.2.3.4", false, 0},
	{"01.2.3", false, 0},
	{"1.02.3", false, 0},
	{"1.2.03", false, 0},
	{"65536.0.0", false, 0},
	{"1.2.3-dev", false, 0},
	{"0.0.0-dev", false, 0},
	{"v1.2.3", false, 0},
	{"+1.2.3", false, 0},
	{"-1.2.3", false, 0},
	{"1..3", false, 0},
	{"1.2.", false, 0},
	{".1.2", false, 0},
	{" 1.2.3", false, 0},
	{"1.2.3 ", false, 0},
	{"123456.0.0", false, 0},
	{"1.2.3\x00", false, 0},
}

func TestGrammar(t *testing.T) {
	for _, c := range cases {
		code, err := Parse(c.in)
		if (err == nil) != c.ok {
			t.Errorf("Parse(%q) ok=%v, want %v", c.in, err == nil, c.ok)
			continue
		}
		if c.ok && code != c.code {
			t.Errorf("Parse(%q) = %#x, want %#x", c.in, code, c.code)
		}
		if c.ok && Format(code) != c.in {
			t.Errorf("Format(Parse(%q)) = %q", c.in, Format(code))
		}
	}
}

func TestOrdering(t *testing.T) {
	ordered := []string{"0.0.0", "0.0.1", "0.0.9", "0.0.10", "0.1.0", "0.9.65535", "0.10.0", "1.0.0", "2.0.0", "10.0.0"}
	for i := 1; i < len(ordered); i++ {
		newer, err := Newer(ordered[i], ordered[i-1])
		if err != nil || !newer {
			t.Errorf("%s should be newer than %s (err %v)", ordered[i], ordered[i-1], err)
		}
		older, err := Newer(ordered[i-1], ordered[i])
		if err != nil || older {
			t.Errorf("%s should not be newer than %s", ordered[i-1], ordered[i])
		}
	}
	if same, _ := Newer("1.2.3", "1.2.3"); same {
		t.Error("an equal version is not newer")
	}
	if _, err := Newer("1.2.3", "1.2.3-dev"); err == nil {
		t.Error("an unparseable current version must be an error, not a guess")
	}
}
