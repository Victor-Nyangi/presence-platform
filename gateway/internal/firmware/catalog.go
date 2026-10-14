// Package firmware serves OTA releases from a directory the release process
// writes. It never builds, signs or alters an image: the gateway holds no
// signing key (docs/ota-signing.md), so the most a compromised gateway can do
// is withhold an update or offer one the terminal will refuse.
//
// Layout of PRESENCE_FIRMWARE_DIR:
//
//	<dir>/<channel>/manifest.json    output of `fwsign sign` without -url
//	<dir>/images/<sha256>.bin        the signed image, named by its sha256
//
// Images are content-addressed so that promoting a release from one channel
// to another is copying a 400-byte manifest, and an image can never be
// swapped under a manifest that names it. A device's channel is
// device.firmware_channel (default "stable").
//
// The manifest is re-read on every request, so publishing is a file write
// (write a temp file and rename it into place) and needs no restart. Image
// hashes are cached by size and modification time.
package firmware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"presence/internal/fwversion"
	"presence/internal/model"
)

// ImagePathPrefix is where the gateway serves images. The manifest carries
// it as a relative URL; the terminal resolves it against the API base it
// already uses and signs the download like any other device request.
const ImagePathPrefix = "/v1/device/firmware/images/"

var (
	// ErrNoRelease means the channel has no manifest. It is the normal state
	// of a channel nobody has published to, and is reported as available:false.
	ErrNoRelease = errors.New("firmware: no release published on this channel")
	// ErrNoImage means the requested image is not in the directory.
	ErrNoImage = errors.New("firmware: no such image")
	// ErrBadCurrent means the device's own version does not parse, so there
	// is nothing to compare against.
	ErrBadCurrent = errors.New("firmware: current version is not MAJOR.MINOR.PATCH")
)

var (
	channelRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sigRe     = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// ValidChannel matches the device.firmware_channel CHECK constraint. It is
// also what keeps a channel name from walking out of the directory.
func ValidChannel(ch string) bool { return channelRe.MatchString(ch) }

// ValidSHA256 reports whether s can name an image.
func ValidSHA256(s string) bool { return sha256Re.MatchString(s) }

type Catalog struct {
	dir string

	mu     sync.Mutex
	hashes map[string]hashEntry // image path -> last verified identity
}

type hashEntry struct {
	size    int64
	modTime time.Time
	sum     string
}

// Open returns a catalog over dir, which must exist. A missing directory is a
// configuration error, not "no updates": it fails the gateway's start.
func Open(dir string) (*Catalog, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("firmware dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("firmware dir %s is not a directory", dir)
	}
	return &Catalog{dir: dir, hashes: map[string]hashEntry{}}, nil
}

// Release returns the validated manifest published on channel, with URL set
// to the gateway path of its image. It fails unless the image is present
// with exactly the size and sha256 the manifest names, so a half-finished
// publish is refused here rather than by every terminal that downloads it.
func (c *Catalog) Release(channel string) (model.FirmwareManifest, error) {
	if !ValidChannel(channel) {
		return model.FirmwareManifest{}, fmt.Errorf("firmware: invalid channel %q", channel)
	}
	raw, err := os.ReadFile(filepath.Join(c.dir, channel, "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return model.FirmwareManifest{}, ErrNoRelease
	}
	if err != nil {
		return model.FirmwareManifest{}, err
	}

	var m model.FirmwareManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return model.FirmwareManifest{}, fmt.Errorf("firmware: %s manifest: %w", channel, err)
	}
	switch {
	case !m.Available:
		return model.FirmwareManifest{}, fmt.Errorf("firmware: %s manifest has available=false; delete it instead", channel)
	case !fwversion.Valid(m.Version):
		return model.FirmwareManifest{}, fmt.Errorf("firmware: %s manifest version %q: %w", channel, m.Version, fwversion.ErrInvalid)
	case m.Size <= 0:
		return model.FirmwareManifest{}, fmt.Errorf("firmware: %s manifest size %d", channel, m.Size)
	case !ValidSHA256(m.SHA256):
		return model.FirmwareManifest{}, fmt.Errorf("firmware: %s manifest sha256 is not 64 lowercase hex", channel)
	case !sigRe.MatchString(m.Signature):
		return model.FirmwareManifest{}, fmt.Errorf("firmware: %s manifest signature is not 128 lowercase hex", channel)
	case m.URL != "":
		// The gateway serves the image it can check. An external URL would
		// send terminals somewhere this directory says nothing about.
		return model.FirmwareManifest{}, fmt.Errorf("firmware: %s manifest has a url; sign gateway-hosted releases without -url", channel)
	}

	size, sum, err := c.imageIdentity(m.SHA256)
	if errors.Is(err, ErrNoImage) {
		return model.FirmwareManifest{}, fmt.Errorf("firmware: %s manifest names images/%s.bin, which is missing", channel, m.SHA256)
	}
	if err != nil {
		return model.FirmwareManifest{}, err
	}
	if size != m.Size || sum != m.SHA256 {
		return model.FirmwareManifest{}, fmt.Errorf("firmware: images/%s.bin is %d bytes with sha256 %s, manifest says %d bytes", m.SHA256, size, sum, m.Size)
	}
	m.URL = ImagePathPrefix + m.SHA256
	return m, nil
}

// Offer answers GET /v1/device/firmware for a device on channel running
// current: the release if it is strictly newer, otherwise available=false.
// The terminal makes the final call: it also refuses anything at or below its
// stored floor, which the gateway does not know.
func (c *Catalog) Offer(channel, current string) (model.FirmwareManifest, error) {
	if !fwversion.Valid(current) {
		return model.FirmwareManifest{Available: false}, ErrBadCurrent
	}
	rel, err := c.Release(channel)
	if errors.Is(err, ErrNoRelease) {
		return model.FirmwareManifest{Available: false}, nil
	}
	if err != nil {
		return model.FirmwareManifest{Available: false}, err
	}
	newer, err := fwversion.Newer(rel.Version, current)
	if err != nil || !newer {
		return model.FirmwareManifest{Available: false}, err
	}
	return rel, nil
}

// OpenImage opens the image named by sha. The file is checked against its
// name (through the hash cache) before it is returned, so a corrupted or
// replaced file is refused rather than streamed to a fleet.
func (c *Catalog) OpenImage(sha string) (*os.File, os.FileInfo, error) {
	if !ValidSHA256(sha) {
		return nil, nil, ErrNoImage
	}
	_, sum, err := c.imageIdentity(sha)
	if err != nil {
		return nil, nil, err
	}
	if sum != sha {
		return nil, nil, fmt.Errorf("firmware: images/%s.bin has sha256 %s", sha, sum)
	}
	f, err := os.Open(c.imagePath(sha))
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	// The file could have been replaced between hashing and opening. Serve
	// only the identity that was hashed.
	if !c.cached(c.imagePath(sha), info, sha) {
		f.Close()
		return nil, nil, fmt.Errorf("firmware: images/%s.bin changed while being opened", sha)
	}
	return f, info, nil
}

func (c *Catalog) imagePath(sha string) string {
	return filepath.Join(c.dir, "images", sha+".bin")
}

func (c *Catalog) cached(path string, info os.FileInfo, sum string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.hashes[path]
	return ok && e.size == info.Size() && e.modTime.Equal(info.ModTime()) && e.sum == sum
}

// imageIdentity returns the size and sha256 of images/<sha>.bin, hashing it
// only when its size or modification time changed since the last look.
func (c *Catalog) imageIdentity(sha string) (int64, string, error) {
	path := c.imagePath(sha)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", ErrNoImage
	}
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() {
		return 0, "", fmt.Errorf("firmware: images/%s.bin is not a regular file", sha)
	}

	c.mu.Lock()
	e, ok := c.hashes[path]
	c.mu.Unlock()
	if ok && e.size == info.Size() && e.modTime.Equal(info.ModTime()) {
		return e.size, e.sum, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	after, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	if after.Size() != n || !after.ModTime().Equal(info.ModTime()) {
		return 0, "", fmt.Errorf("firmware: images/%s.bin changed while being hashed", sha)
	}
	sum := hex.EncodeToString(h.Sum(nil))

	c.mu.Lock()
	c.hashes[path] = hashEntry{size: n, modTime: after.ModTime(), sum: sum}
	c.mu.Unlock()
	return n, sum, nil
}
