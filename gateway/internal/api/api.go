// Package api wires HTTP to the store. Handlers validate, delegate, and
// shape responses; they contain no SQL and no crypto.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"presence/internal/auth"
	"presence/internal/firmware"
	"presence/internal/model"
	"presence/internal/store"
)

const maxBodyBytes = 1 << 20 // 1 MiB; a 100-event batch is ~30 KiB

// imageWriteTimeout replaces the server's WriteTimeout for an image download.
// 30 s covers every JSON response; it does not cover ~770 KB to a terminal
// on a school's uplink.
const imageWriteTimeout = 10 * time.Minute

type Server struct {
	st     *store.Store
	nonces auth.NonceCache
	log    *slog.Logger
	now    func() time.Time  // injectable for tests
	fw     *firmware.Catalog // nil: no releases published; every device is told available=false
}

func NewServer(st *store.Store, nonces auth.NonceCache, log *slog.Logger) *Server {
	return &Server{st: st, nonces: nonces, log: log, now: time.Now}
}

// SetClock overrides the time source. Test-only.
func (s *Server) SetClock(f func() time.Time) { s.now = f }

// SetFirmware enables GET /v1/device/firmware from a release directory.
// Call it before serving.
func (s *Server) SetFirmware(c *firmware.Catalog) { s.fw = c }

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated. Signing needs a roughly-correct clock, and a device
	// with a dead RTC has no way to produce one — so this endpoint cannot
	// itself be signed. Rate-limit it at the edge.
	mux.HandleFunc("GET /v1/device/time", s.handleTime)
	mux.HandleFunc("POST /v1/device/provision", s.handleProvision)

	// Signed.
	mux.Handle("POST /v1/device/heartbeat", s.signed(s.handleHeartbeat))
	mux.Handle("POST /v1/device/events", s.signed(s.handleEvents))
	mux.Handle("GET /v1/device/commands", s.signed(s.handleCommands))
	mux.Handle("POST /v1/device/commands/{id}/result", s.signed(s.handleCommandResult))
	mux.Handle("GET /v1/device/roster", s.signed(s.handleRoster))
	mux.Handle("GET /v1/device/firmware", s.signed(s.handleFirmware))
	mux.Handle("GET /v1/device/firmware/images/{sha256}", s.signed(s.handleFirmwareImage))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// ---------------------------------------------------------------------
// Signing middleware
// ---------------------------------------------------------------------

type ctxKey struct{}

type handlerFunc func(http.ResponseWriter, *http.Request, *store.Device, []byte)

func (s *Server) signed(next handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := s.now()

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			s.problem(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large", now)
			return
		}

		creds, err := auth.Extract(r)
		if err != nil {
			s.problem(w, http.StatusUnauthorized, "bad_signature", err.Error(), now)
			return
		}

		dev, err := s.st.LoadDevice(r.Context(), creds.DeviceID)
		switch {
		case errors.Is(err, store.ErrDeviceUnknown):
			s.problem(w, http.StatusUnauthorized, "device_unknown", "unknown device", now)
			return
		case errors.Is(err, store.ErrDeviceSuspended):
			s.problem(w, http.StatusForbidden, "device_suspended", "device suspended", now)
			return
		case err != nil:
			s.log.Error("load device", "err", err, "device", creds.DeviceID)
			s.problem(w, http.StatusInternalServerError, "", "internal error", now)
			return
		}

		// r.URL.Path excludes the query string on purpose: device and server
		// would otherwise have to agree on parameter ordering to agree on a
		// signature.
		verr := auth.Verify(creds, now, r.Method, r.URL.Path, body, s.nonces, dev.Secrets)
		switch {
		case errors.Is(verr, auth.ErrClockSkew):
			// Recoverable, and the response carries the fix: the device
			// resets its RTC from server_time_ms and retries once.
			s.problem(w, http.StatusUnauthorized, "clock_skew", "timestamp outside accepted window", now)
			return
		case errors.Is(verr, auth.ErrNonceReplay):
			s.problem(w, http.StatusUnauthorized, "nonce_replay", "nonce already used", now)
			return
		case verr != nil:
			s.problem(w, http.StatusUnauthorized, "bad_signature", "signature mismatch", now)
			return
		}

		next(w, r, dev, body)
	})
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

func (s *Server) handleTime(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, model.TimeResponse{ServerTimeMS: s.now().UnixMilli()})
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	// Provisioning is authenticated by a one-time token rather than HMAC,
	// because the device has no secret yet. Implemented in store.Provision;
	// left as an explicit 501 here until the installer flow is built, so it
	// cannot be mistaken for a working open endpoint.
	s.problem(w, http.StatusNotImplemented, "", "provisioning flow not enabled in this build", s.now())
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, dev *store.Device, body []byte) {
	var req model.HeartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.problem(w, http.StatusBadRequest, "", "malformed json", s.now())
		return
	}
	resp, err := s.st.Heartbeat(r.Context(), dev, req, s.now())
	if err != nil {
		s.log.Error("heartbeat", "err", err, "device", dev.ID)
		s.problem(w, http.StatusInternalServerError, "", "internal error", s.now())
		return
	}
	resp.FirmwareAvailable = s.firmwareAvailable(dev, req.FirmwareVersion)
	s.writeJSON(w, http.StatusOK, resp)
}

// firmwareAvailable is the heartbeat's cheap answer to "is there a newer
// image for me?". A broken release directory must never fail a heartbeat,
// which is the device's liveness signal, so errors are logged and read as no.
func (s *Server) firmwareAvailable(dev *store.Device, current string) bool {
	if s.fw == nil {
		return false
	}
	m, err := s.fw.Offer(dev.FirmwareChannel, current)
	if err != nil && !errors.Is(err, firmware.ErrBadCurrent) {
		s.log.Error("firmware release", "err", err, "channel", dev.FirmwareChannel)
	}
	return err == nil && m.Available
}

// handleFirmware serves the manifest for the device's channel when its
// release is newer than `current`. The manifest is the signer's output read
// from disk; the gateway adds only the image path. Whether to install is the
// terminal's decision: it also checks the signature, and a floor the gateway
// does not know.
func (s *Server) handleFirmware(w http.ResponseWriter, r *http.Request, dev *store.Device, body []byte) {
	current := r.URL.Query().Get("current")
	if current == "" {
		s.problem(w, http.StatusBadRequest, "", "current is required", s.now())
		return
	}
	if s.fw == nil {
		s.writeJSON(w, http.StatusOK, model.FirmwareManifest{Available: false})
		return
	}
	m, err := s.fw.Offer(dev.FirmwareChannel, current)
	switch {
	case errors.Is(err, firmware.ErrBadCurrent):
		s.problem(w, http.StatusBadRequest, "", "current is not MAJOR.MINOR.PATCH", s.now())
		return
	case err != nil:
		// A half-published release: say no rather than hand out a manifest
		// whose image is missing or wrong. The device asks again next time.
		s.log.Error("firmware release", "err", err, "channel", dev.FirmwareChannel, "device", dev.ID)
		m = model.FirmwareManifest{Available: false}
	}
	s.writeJSON(w, http.StatusOK, m)
}

// handleFirmwareImage streams a published image. Images are named by their
// sha256 and checked against it before a byte is sent; they are files the
// release process wrote, never generated here.
func (s *Server) handleFirmwareImage(w http.ResponseWriter, r *http.Request, dev *store.Device, body []byte) {
	if s.fw == nil {
		s.problem(w, http.StatusNotFound, "", "no such image", s.now())
		return
	}
	sha := r.PathValue("sha256")
	f, info, err := s.fw.OpenImage(sha)
	switch {
	case errors.Is(err, firmware.ErrNoImage):
		s.problem(w, http.StatusNotFound, "", "no such image", s.now())
		return
	case err != nil:
		s.log.Error("firmware image", "err", err, "sha256", sha, "device", dev.ID)
		s.problem(w, http.StatusInternalServerError, "", "image unavailable", s.now())
		return
	}
	defer f.Close()

	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(imageWriteTimeout)); err != nil {
		s.log.Warn("firmware image: cannot extend write deadline", "err", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+sha+`"`)
	s.log.Info("firmware image", "device", dev.ID, "sha256", sha, "bytes", info.Size())
	http.ServeContent(w, r, "", info.ModTime(), f)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, dev *store.Device, body []byte) {
	var req model.EventsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.problem(w, http.StatusBadRequest, "", "malformed json", s.now())
		return
	}
	if len(req.Events) == 0 {
		s.problem(w, http.StatusBadRequest, "", "empty batch", s.now())
		return
	}
	if len(req.Events) > 100 {
		s.problem(w, http.StatusRequestEntityTooLarge, "payload_too_large", "batch exceeds 100 events", s.now())
		return
	}
	resp, err := s.st.IngestBatch(r.Context(), dev, req, s.now())
	if err != nil {
		// Deliberately a 500, not a partial success: the device keeps its
		// buffer and retries. Losing punches is worse than a retry.
		s.log.Error("ingest", "err", err, "device", dev.ID, "request_id", req.RequestID)
		s.problem(w, http.StatusInternalServerError, "", "internal error", s.now())
		return
	}
	s.log.Info("ingest",
		"device", dev.ID, "accepted", len(resp.Accepted),
		"duplicates", len(resp.Duplicates), "rejected", len(resp.Rejected),
		"ack_through", resp.AckThrough)
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request, dev *store.Device, body []byte) {
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 50 {
			limit = n
		}
	}
	cmds, err := s.st.PendingCommands(r.Context(), dev, limit)
	if err != nil {
		s.log.Error("commands", "err", err, "device", dev.ID)
		s.problem(w, http.StatusInternalServerError, "", "internal error", s.now())
		return
	}
	s.writeJSON(w, http.StatusOK, model.CommandsResponse{Commands: cmds})
}

func (s *Server) handleCommandResult(w http.ResponseWriter, r *http.Request, dev *store.Device, body []byte) {
	var res model.CommandResult
	if err := json.Unmarshal(body, &res); err != nil {
		s.problem(w, http.StatusBadRequest, "", "malformed json", s.now())
		return
	}
	if err := s.st.RecordCommandResult(r.Context(), dev, r.PathValue("id"), res); err != nil {
		s.log.Error("command result", "err", err, "device", dev.ID)
		s.problem(w, http.StatusInternalServerError, "", "internal error", s.now())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRoster(w http.ResponseWriter, r *http.Request, dev *store.Device, body []byte) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	resp, err := s.st.RosterDelta(r.Context(), dev, since)
	if err != nil {
		s.log.Error("roster", "err", err, "device", dev.ID)
		s.problem(w, http.StatusInternalServerError, "", "internal error", s.now())
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------

func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Error("write response", "err", err)
	}
}

// problem always includes server_time_ms. That is what makes a clock_skew
// rejection self-healing rather than a permanent lockout.
func (s *Server) problem(w http.ResponseWriter, code int, errCode, detail string, now time.Time) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(model.Problem{
		Title:        http.StatusText(code),
		Status:       code,
		Code:         errCode,
		Detail:       detail,
		ServerTimeMS: now.UnixMilli(),
	})
}
