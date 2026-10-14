package firmware

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"presence/internal/fwsign"
	"presence/internal/model"
)

// Publisher writes a release directory the way docs/ota-signing.md says to,
// with a key generated in memory for this test only.
type publisher struct {
	t    *testing.T
	dir  string
	priv ed25519.PrivateKey
}

func newPublisher(t *testing.T) *publisher {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &publisher{t: t, dir: t.TempDir(), priv: priv}
}

func image(version string, n int) []byte {
	img := bytes.Repeat([]byte("firmware "+version+" "), n)
	return append(img, []byte(fwsign.VersionMarker+version+"\x00")...)
}

// publish signs img as version and installs it on channel. It returns the
// manifest as fwsign wrote it.
func (p *publisher) publish(channel, version string, img []byte) model.FirmwareManifest {
	p.t.Helper()
	m, err := fwsign.Sign(p.priv, img, version, "")
	if err != nil {
		p.t.Fatal(err)
	}
	p.writeImage(m.SHA256, img)
	p.writeManifest(channel, m)
	return m
}

func (p *publisher) writeImage(name string, img []byte) {
	p.t.Helper()
	if err := os.MkdirAll(filepath.Join(p.dir, "images"), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.dir, "images", name+".bin"), img, 0o644); err != nil {
		p.t.Fatal(err)
	}
}

func (p *publisher) writeManifest(channel string, m model.FirmwareManifest) {
	p.t.Helper()
	var buf bytes.Buffer
	if err := fwsign.WriteManifest(&buf, m); err != nil {
		p.t.Fatal(err)
	}
	p.writeRaw(channel, buf.String())
}

func (p *publisher) writeRaw(channel, raw string) {
	p.t.Helper()
	if err := os.MkdirAll(filepath.Join(p.dir, channel), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.dir, channel, "manifest.json"), []byte(raw), 0o644); err != nil {
		p.t.Fatal(err)
	}
}

func (p *publisher) catalog() *Catalog {
	p.t.Helper()
	c, err := Open(p.dir)
	if err != nil {
		p.t.Fatal(err)
	}
	return c
}

func TestOpenRequiresADirectory(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("opened a missing directory")
	}
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, []byte("x"), 0o644)
	if _, err := Open(f); err == nil {
		t.Fatal("opened a file as a directory")
	}
}

func TestReleaseServesTheSignedManifestWithTheGatewayPath(t *testing.T) {
	p := newPublisher(t)
	img := image("0.2.0", 2000)
	signed := p.publish("stable", "0.2.0", img)

	got, err := p.catalog().Release("stable")
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != ImagePathPrefix+signed.SHA256 {
		t.Fatalf("url %q", got.URL)
	}
	// Everything the terminal verifies is the signer's, byte for byte.
	if got.Version != signed.Version || got.Size != signed.Size || got.SHA256 != signed.SHA256 || got.Signature != signed.Signature || !got.Available {
		t.Fatalf("manifest altered: %+v vs %+v", got, signed)
	}
	if err := fwsign.Verify(p.priv.Public().(ed25519.PublicKey), img, got); err != nil {
		t.Fatalf("served manifest no longer verifies: %v", err)
	}
}

func TestOfferIsStrictlyNewerOnly(t *testing.T) {
	p := newPublisher(t)
	p.publish("stable", "0.2.0", image("0.2.0", 100))
	c := p.catalog()

	for _, tc := range []struct {
		current string
		want    bool
	}{
		{"0.1.0", true},
		{"0.1.65535", true},
		{"0.2.0", false}, // equal: the device already runs it
		{"0.2.1", false},
		{"1.0.0", false},
	} {
		m, err := c.Offer("stable", tc.current)
		if err != nil {
			t.Fatalf("%s: %v", tc.current, err)
		}
		if m.Available != tc.want {
			t.Errorf("current %s: available=%v, want %v", tc.current, m.Available, tc.want)
		}
		if !m.Available && (m.Version != "" || m.Signature != "" || m.URL != "") {
			t.Errorf("current %s: available=false still carried a release: %+v", tc.current, m)
		}
	}
	if _, err := c.Offer("stable", "0.1.0-dev"); !errors.Is(err, ErrBadCurrent) {
		t.Errorf("unparseable current: %v", err)
	}
}

func TestChannelsAreIndependent(t *testing.T) {
	p := newPublisher(t)
	p.publish("stable", "0.2.0", image("0.2.0", 100))
	p.publish("beta", "0.3.0", image("0.3.0", 100))
	c := p.catalog()

	stable, _ := c.Offer("stable", "0.1.0")
	beta, _ := c.Offer("beta", "0.1.0")
	if stable.Version != "0.2.0" || beta.Version != "0.3.0" {
		t.Fatalf("stable %s beta %s", stable.Version, beta.Version)
	}
	none, err := c.Offer("canary", "0.1.0")
	if err != nil || none.Available {
		t.Fatalf("a channel nobody published to: %+v %v", none, err)
	}
	if _, err := c.Release("canary"); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("Release on an empty channel: %v", err)
	}
}

func TestChannelNamesCannotEscapeTheDirectory(t *testing.T) {
	p := newPublisher(t)
	p.publish("stable", "0.2.0", image("0.2.0", 100))
	c := p.catalog()
	for _, ch := range []string{"", "..", "../stable", "stable/../stable", "/etc", "Stable", "-x", "a b", strings.Repeat("a", 33)} {
		if _, err := c.Release(ch); err == nil || errors.Is(err, ErrNoRelease) {
			t.Errorf("channel %q: %v", ch, err)
		}
		if m, _ := c.Offer(ch, "0.1.0"); m.Available {
			t.Errorf("channel %q was offered a release", ch)
		}
	}
}

// A half-finished or inconsistent publish is refused at the gateway, not by
// every terminal after a 770 KB download.
func TestBrokenPublishesAreRefused(t *testing.T) {
	cases := map[string]func(p *publisher){
		"image missing": func(p *publisher) {
			m, _ := fwsign.Sign(p.priv, image("0.2.0", 100), "0.2.0", "")
			p.writeManifest("stable", m)
		},
		"image is a different file": func(p *publisher) {
			m, _ := fwsign.Sign(p.priv, image("0.2.0", 100), "0.2.0", "")
			p.writeImage(m.SHA256, image("0.2.0", 101))
			p.writeManifest("stable", m)
		},
		"same size, different bytes": func(p *publisher) {
			img := image("0.2.0", 100)
			m, _ := fwsign.Sign(p.priv, img, "0.2.0", "")
			bad := append([]byte(nil), img...)
			bad[10] ^= 1
			p.writeImage(m.SHA256, bad)
			p.writeManifest("stable", m)
		},
		"manifest has an external url": func(p *publisher) {
			img := image("0.2.0", 100)
			m, _ := fwsign.Sign(p.priv, img, "0.2.0", "https://elsewhere.example/fw.bin")
			p.writeImage(m.SHA256, img)
			p.writeManifest("stable", m)
		},
		"unknown field": func(p *publisher) {
			img := image("0.2.0", 100)
			m, _ := fwsign.Sign(p.priv, img, "0.2.0", "")
			p.writeImage(m.SHA256, img)
			var buf bytes.Buffer
			fwsign.WriteManifest(&buf, m)
			p.writeRaw("stable", strings.Replace(buf.String(), `"available"`, `"channel": "stable", "available"`, 1))
		},
		"bad version": func(p *publisher) {
			img := image("0.2.0", 100)
			m, _ := fwsign.Sign(p.priv, img, "0.2.0", "")
			m.Version = "0.2.0-rc1"
			p.writeImage(m.SHA256, img)
			p.writeManifest("stable", m)
		},
		"uppercase sha256": func(p *publisher) {
			img := image("0.2.0", 100)
			m, _ := fwsign.Sign(p.priv, img, "0.2.0", "")
			p.writeImage(m.SHA256, img)
			m.SHA256 = strings.ToUpper(m.SHA256)
			p.writeManifest("stable", m)
		},
		"truncated signature": func(p *publisher) {
			img := image("0.2.0", 100)
			m, _ := fwsign.Sign(p.priv, img, "0.2.0", "")
			m.Signature = m.Signature[:126]
			p.writeImage(m.SHA256, img)
			p.writeManifest("stable", m)
		},
		"available false": func(p *publisher) {
			p.writeRaw("stable", `{"available": false}`)
		},
		"not json": func(p *publisher) {
			p.writeRaw("stable", `{"available": true,`)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPublisher(t)
			setup(p)
			c := p.catalog()
			if m, err := c.Release("stable"); err == nil {
				t.Fatalf("served %+v", m)
			}
			if m, err := c.Offer("stable", "0.1.0"); err == nil || m.Available {
				t.Fatalf("offered %+v (err %v)", m, err)
			}
		})
	}
}

func TestOpenImageChecksTheFileAgainstItsName(t *testing.T) {
	p := newPublisher(t)
	img := image("0.2.0", 3000)
	m := p.publish("stable", "0.2.0", img)
	c := p.catalog()

	f, info, err := c.OpenImage(m.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, img) || info.Size() != int64(len(img)) {
		t.Fatal("served bytes differ from the published image")
	}

	if _, _, err := c.OpenImage(strings.Repeat("0", 64)); !errors.Is(err, ErrNoImage) {
		t.Errorf("unknown image: %v", err)
	}
	for _, bad := range []string{"", "../stable/manifest", m.SHA256 + ".bin", strings.ToUpper(m.SHA256), m.SHA256[:63]} {
		if _, _, err := c.OpenImage(bad); !errors.Is(err, ErrNoImage) {
			t.Errorf("%q: %v", bad, err)
		}
	}

	// Replace the file after it has been hashed and cached. The new
	// modification time forces a re-hash, and the mismatch is refused.
	tampered := append([]byte(nil), img...)
	tampered[len(tampered)/2] ^= 0x01
	path := filepath.Join(p.dir, "images", m.SHA256+".bin")
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	os.Chtimes(path, later, later)
	if f, _, err := c.OpenImage(m.SHA256); err == nil {
		f.Close()
		t.Fatal("served an image whose bytes no longer match its name")
	}
	if _, err := c.Release("stable"); err == nil {
		t.Fatal("offered a release whose image was replaced")
	}
}

// The handlers share one catalog across every request goroutine.
func TestConcurrentUse(t *testing.T) {
	p := newPublisher(t)
	img := image("0.2.0", 5000)
	m := p.publish("stable", "0.2.0", img)
	p.publish("beta", "0.3.0", image("0.3.0", 5000))
	c := p.catalog()
	want := sha256.Sum256(img)

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ch := []string{"stable", "beta"}[i%2]
			if o, err := c.Offer(ch, "0.1.0"); err != nil || !o.Available {
				errs <- errors.New("offer failed")
				return
			}
			f, _, err := c.OpenImage(m.SHA256)
			if err != nil {
				errs <- err
				return
			}
			h := sha256.New()
			io.Copy(h, f)
			f.Close()
			if hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(want[:]) {
				errs <- errors.New("wrong bytes")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
