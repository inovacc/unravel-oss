package capture

import (
	"encoding/json"
	"time"
)

// FormatVersion is the current capture file format version.
const FormatVersion = "1.0"

// EventType identifies the kind of captured event.
type EventType string

const (
	EventNetworkRequest  EventType = "network_request"
	EventNetworkResponse EventType = "network_response"
	EventIPCMessage      EventType = "ipc_message"
	EventConsoleLog      EventType = "console_log"
	EventWindowState     EventType = "window_state"
	EventStorageWrite    EventType = "storage_write"
	EventStorageDelete   EventType = "storage_delete"
	EventDOMEvent        EventType = "dom_event"

	// Android-specific event types.
	EventAndroidIntent    EventType = "android_intent"
	EventAndroidBroadcast EventType = "android_broadcast"
	EventAndroidLogcat    EventType = "android_logcat"
	EventAndroidPrefs     EventType = "android_prefs"
	EventAndroidNetwork   EventType = "android_network"
)

// EventSource identifies where the event was captured from.
type EventSource string

const (
	SourceCDP     EventSource = "cdp"
	SourceFSWatch EventSource = "fswatch"
	SourceADB     EventSource = "adb"
)

// AppInfo describes the application being captured.
type AppInfo struct {
	Name            string `json:"name"`
	Path            string `json:"path"`
	Framework       string `json:"framework"`
	ElectronVersion string `json:"electron_version,omitempty"`
	PID             int    `json:"pid"`
}

// CaptureMetadata holds timing and environment information for a capture session.
type CaptureMetadata struct {
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	DurationMs  int64     `json:"duration_ms"`
	Host        string    `json:"host"`
	ToolVersion string    `json:"tool_version"`
}

// Event is a single captured event in the session timeline.
type Event struct {
	Seq    int             `json:"seq"`
	TS     time.Time       `json:"ts"`
	Type   EventType       `json:"type"`
	Source EventSource     `json:"source"`
	Data   json.RawMessage `json:"data"`
}

// NetworkRequestData holds data for a captured network request.
type NetworkRequestData struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// NetworkResponseData holds data for a captured network response.
type NetworkResponseData struct {
	Status  int               `json:"status"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// IPCMessageData holds data for a captured IPC message.
type IPCMessageData struct {
	Channel   string `json:"channel"`
	Args      []any  `json:"args,omitempty"`
	Direction string `json:"direction"`
}

// ConsoleLogData holds data for a captured console log entry.
type ConsoleLogData struct {
	Level   string   `json:"level"`
	Message string   `json:"message"`
	Args    []string `json:"args,omitempty"`
}

// WindowStateData holds data for a captured window state change.
type WindowStateData struct {
	Property string `json:"property"`
	Value    string `json:"value"`
}

// StorageEventData holds data for a captured storage filesystem event.
type StorageEventData struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Category  string `json:"category"`
	SizeDelta int64  `json:"size_delta"`
}

// DOMEventData holds data for a captured DOM event.
type DOMEventData struct {
	EventName string `json:"event_name"`
	Selector  string `json:"selector,omitempty"`
	Value     string `json:"value,omitempty"`
}

// AndroidIntentData holds data for a captured Android intent.
type AndroidIntentData struct {
	Action    string            `json:"action"`
	Component string            `json:"component,omitempty"`
	Data      string            `json:"data,omitempty"`
	Extras    map[string]string `json:"extras,omitempty"`
	Flags     string            `json:"flags,omitempty"`
}

// AndroidBroadcastData holds data for a captured Android broadcast.
type AndroidBroadcastData struct {
	Action    string            `json:"action"`
	Component string            `json:"component,omitempty"`
	Extras    map[string]string `json:"extras,omitempty"`
}

// AndroidLogcatData holds data for a captured Android logcat entry.
type AndroidLogcatData struct {
	Priority string `json:"priority"`
	Tag      string `json:"tag"`
	Message  string `json:"message"`
	PID      string `json:"pid,omitempty"`
}

// AndroidPrefsData holds data for a shared preferences snapshot or change.
type AndroidPrefsData struct {
	File    string            `json:"file"`
	Entries map[string]string `json:"entries,omitempty"`
}

// AndroidNetworkData holds data for a captured tcpdump network packet.
type AndroidNetworkData struct {
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
	Dest     string `json:"dest"`
	Length   int    `json:"length"`
	Info     string `json:"info,omitempty"`
}

// ViewportSpec is the manifest-side viewport descriptor used inside CapturedState.
// Mirrors pkg/capture/visual.Viewport but avoids the cross-package import: the
// visual package populates this struct by value at write time.
type ViewportSpec struct {
	W     int     `json:"w"`
	H     int     `json:"h"`
	Scale float64 `json:"scale,omitempty"`
}

// CapturedState mirrors the JSON written into manifest.json's Captures field
// (D-16, Phase 8 additive extension). The entry references the four sibling
// artifacts written per (state, viewport) tuple.
type CapturedState struct {
	RunID             string       `json:"run_id"`
	Component         string       `json:"component"`
	StateSlug         string       `json:"state_slug"`
	Viewport          ViewportSpec `json:"viewport"`
	ScreenshotPath    string       `json:"screenshot_path"`
	TreePath          string       `json:"tree_path"`
	LayoutPath        string       `json:"layout_path"`
	MetaPath          string       `json:"meta_path"`
	FrameworkTreePath string       `json:"framework_tree_path,omitempty"`
}

// CaptureSession is the top-level structure for a capture file.
type CaptureSession struct {
	Version string          `json:"version"`
	App     AppInfo         `json:"app"`
	Capture CaptureMetadata `json:"capture"`
	Events  []Event         `json:"events"`
}
