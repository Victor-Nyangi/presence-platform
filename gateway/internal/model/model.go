// Package model holds the wire types shared by handlers, store and the
// device simulator. They mirror docs/openapi.yaml exactly; if you change one,
// change both.
package model

import "time"

type CredentialKind string

const (
	CredFingerprint CredentialKind = "fingerprint"
	CredRFIDCard    CredentialKind = "rfid_card"
	CredNFCTag      CredentialKind = "nfc_tag"
	CredPIN         CredentialKind = "pin"
	CredQR          CredentialKind = "qr"
)

type Direction string

const (
	DirIn      Direction = "in"
	DirOut     Direction = "out"
	DirUnknown Direction = "unknown"
)

type TimeSource string

const (
	TimeRTCSynced   TimeSource = "rtc_synced"
	TimeRTCUnsynced TimeSource = "rtc_unsynced"
	TimeUptimeOnly  TimeSource = "uptime_only"
	TimeServer      TimeSource = "server_assigned"
)

type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// Rejection reasons. A rejected event is still stored; see EventsResponse.
const (
	ReasonUnknownSlot       = "unknown_slot"
	ReasonCredentialRevoked = "credential_revoked"
	ReasonPersonInactive    = "person_inactive"
	ReasonMalformed         = "malformed"
	ReasonFutureTimestamp   = "future_timestamp"
)

// PunchEvent is one capture at a reader, as the device reports it.
type PunchEvent struct {
	Seq              int64          `json:"seq"`
	EventUUID        string         `json:"event_uuid"`
	CapturedAt       time.Time      `json:"captured_at"`
	CapturedUptimeMS int64          `json:"captured_uptime_ms,omitempty"`
	TimeSource       TimeSource     `json:"time_source"`
	CredentialKind   CredentialKind `json:"credential_kind"`
	SlotNo           *int           `json:"slot_no,omitempty"`
	CredentialRef    string         `json:"credential_ref,omitempty"`
	MatchScore       *int           `json:"match_score,omitempty"`
	DirectionHint    Direction      `json:"direction_hint,omitempty"`
	DeviceMode       string         `json:"device_mode,omitempty"`
}

type EventsRequest struct {
	RequestID string `json:"request_id"`
	// DeviceUptimeMS is the device's uptime at the moment of upload. It is
	// what makes uptime_only events recoverable: wall time is reconstructed
	// as received_at - (DeviceUptimeMS - CapturedUptimeMS).
	DeviceUptimeMS int64        `json:"device_uptime_ms,omitempty"`
	BufferDepth    int          `json:"buffer_depth,omitempty"`
	Events         []PunchEvent `json:"events"`
}

type Rejection struct {
	Seq    int64  `json:"seq"`
	Reason string `json:"reason"`
}

type EventsResponse struct {
	// AckThrough is the highest CONTIGUOUS device_seq durably stored. The
	// device may truncate its buffer only up to this point.
	//
	// Rejected events advance AckThrough too, because they are still stored.
	// Otherwise a single unresolvable event wedges the buffer forever and
	// every later punch is stuck behind it.
	AckThrough   int64       `json:"ack_through"`
	Accepted     []int64     `json:"accepted"`
	Duplicates   []int64     `json:"duplicates"`
	Rejected     []Rejection `json:"rejected"`
	ServerTimeMS int64       `json:"server_time_ms"`
}

type HeartbeatRequest struct {
	FirmwareVersion string `json:"firmware_version"`
	UptimeMS        int64  `json:"uptime_ms"`
	BufferDepth     int    `json:"buffer_depth"`
	LastSeq         int64  `json:"last_seq,omitempty"`
	RSSI            *int   `json:"rssi,omitempty"`
	FreeHeap        *int   `json:"free_heap,omitempty"`
	SensorOK        *bool  `json:"sensor_ok,omitempty"`
	RTCOK           *bool  `json:"rtc_ok,omitempty"`
}

// HeartbeatResponse deliberately returns version counters, not data. The
// device compares them and only fetches a delta when one actually moves, so
// the 60-second poll stays tiny.
type HeartbeatResponse struct {
	ServerTimeMS      int64 `json:"server_time_ms"`
	ConfigVersion     int   `json:"config_version"`
	RosterVersion     int64 `json:"roster_version"`
	CommandsPending   int   `json:"commands_pending"`
	AckThrough        int64 `json:"ack_through"`
	BackoffS          int   `json:"backoff_s,omitempty"`
	FirmwareAvailable bool  `json:"firmware_available"`
}

type Command struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Payload   map[string]any `json:"payload"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
}

type CommandsResponse struct {
	Commands []Command `json:"commands"`
}

type CommandResult struct {
	Status string         `json:"status"`
	Result map[string]any `json:"result,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// RosterEntry carries display name and slot only. No payroll numbers, no
// admission numbers, no national IDs: a stolen terminal should be an
// inconvenience, not a data breach.
type RosterEntry struct {
	SlotNo      int    `json:"slot_no"`
	DisplayName string `json:"display_name"`
	PersonRef   string `json:"person_ref"`
}

type RosterResponse struct {
	RosterVersion int64         `json:"roster_version"`
	FullResync    bool          `json:"full_resync"`
	Upserts       []RosterEntry `json:"upserts"`
	Removals      []int         `json:"removals"`
}

type ProvisionRequest struct {
	Serial          string `json:"serial"`
	FirmwareVersion string `json:"firmware_version"`
	HWRevision      string `json:"hw_revision,omitempty"`
}

type ProvisionResponse struct {
	DeviceID string `json:"device_id"`
	// DeviceSecret is returned exactly once and never retrievable again.
	DeviceSecret string       `json:"device_secret"`
	KeyVersion   int          `json:"key_version"`
	OrgID        string       `json:"org_id"`
	SiteID       string       `json:"site_id"`
	Config       DeviceConfig `json:"config"`
	ServerTimeMS int64        `json:"server_time_ms"`
}

type DeviceConfig struct {
	ConfigVersion int    `json:"config_version"`
	Mode          string `json:"mode"`
	Timezone      string `json:"timezone"`
	HeartbeatS    int    `json:"heartbeat_s"`
	FlushS        int    `json:"flush_s"`
	MaxBatch      int    `json:"max_batch"`
	// DebounceMS suppresses repeat reads of the SAME slot inside the window.
	// That is a finger left on the platen, not a second punch. Anything
	// outside the window is recorded raw.
	DebounceMS          int  `json:"debounce_ms"`
	MatchThreshold      int  `json:"match_threshold"`
	AllowOfflineUnknown bool `json:"allow_offline_unknown"`
}

func DefaultConfig() DeviceConfig {
	return DeviceConfig{
		ConfigVersion:       1,
		Mode:                "bidirectional",
		Timezone:            "Africa/Nairobi",
		HeartbeatS:          60,
		FlushS:              30,
		MaxBatch:            50,
		DebounceMS:          5000,
		MatchThreshold:      60,
		AllowOfflineUnknown: true,
	}
}

type EnrollmentRequest struct {
	CommandID string `json:"command_id"`
	SlotNo    int    `json:"slot_no"`
	// TemplateB64 is a vendor-proprietary byte blob, never a fingerprint
	// image. The server encrypts it before it touches Postgres.
	TemplateB64 string `json:"template_b64"`
	Vendor      string `json:"vendor"`
	Quality     int    `json:"quality,omitempty"`
}

type EnrollmentResponse struct {
	CredentialID  string `json:"credential_id"`
	RosterVersion int64  `json:"roster_version"`
}

type TimeResponse struct {
	ServerTimeMS int64 `json:"server_time_ms"`
}

// Problem is an RFC 9457-shaped error body.
type Problem struct {
	Type         string `json:"type,omitempty"`
	Title        string `json:"title"`
	Status       int    `json:"status"`
	Code         string `json:"code,omitempty"`
	Detail       string `json:"detail,omitempty"`
	ServerTimeMS int64  `json:"server_time_ms,omitempty"`
}
