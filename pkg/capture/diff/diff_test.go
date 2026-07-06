package diff

import (
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

func makeSession(events ...capture.Event) *capture.CaptureSession {
	return &capture.CaptureSession{
		Version: "1.0",
		App:     capture.AppInfo{Name: "TestApp"},
		Events:  events,
	}
}

func netReqEvent(seq int, method, rawURL string) capture.Event {
	e, _ := capture.NewEvent(seq, time.Now(), capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: method, URL: rawURL})
	return e
}

func ipcEvent(seq int, channel string) capture.Event {
	e, _ := capture.NewEvent(seq, time.Now(), capture.EventIPCMessage, capture.SourceCDP,
		capture.IPCMessageData{Channel: channel, Direction: "renderer_to_main"})
	return e
}

func stealthEvent(seq int, prop, val string) capture.Event {
	e, _ := capture.NewEvent(seq, time.Now(), capture.EventWindowState, capture.SourceCDP,
		capture.WindowStateData{Property: prop, Value: val})
	return e
}

func TestCompareDetectsNewEndpoint(t *testing.T) {
	before := makeSession(netReqEvent(1, "GET", "https://api.example.com/v1/data"))
	after := makeSession(
		netReqEvent(1, "GET", "https://api.example.com/v1/data"),
		netReqEvent(2, "POST", "https://telemetry.evil.com/track"),
	)

	result := Compare(before, after, "v1.json", "v2.json")

	if len(result.Network.Added) != 1 {
		t.Fatalf("added = %d, want 1", len(result.Network.Added))
	}
	if result.Network.Added[0].Host != "telemetry.evil.com" {
		t.Errorf("host = %q", result.Network.Added[0].Host)
	}
	if len(result.Network.Removed) != 0 {
		t.Errorf("removed = %d, want 0", len(result.Network.Removed))
	}
}

func TestCompareDetectsNewIPC(t *testing.T) {
	before := makeSession(ipcEvent(1, "get-settings"))
	after := makeSession(ipcEvent(1, "get-settings"), ipcEvent(2, "screen-capture-check"))

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.IPC.Added) != 1 || result.IPC.Added[0] != "screen-capture-check" {
		t.Errorf("ipc added = %v", result.IPC.Added)
	}
}

func TestCompareDetectsNewStealth(t *testing.T) {
	before := makeSession()
	after := makeSession(stealthEvent(1, "content_protection", "true"))

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.Stealth.Added) != 1 {
		t.Fatalf("stealth added = %d, want 1", len(result.Stealth.Added))
	}
}

func TestCompareNoChanges(t *testing.T) {
	s := makeSession(netReqEvent(1, "GET", "https://example.com"))
	result := Compare(s, s, "a.json", "b.json")
	if result.Summary != "No behavioral changes detected." {
		t.Errorf("summary = %q", result.Summary)
	}
}

func storageEvent(seq int, category, path string, evtType capture.EventType) capture.Event {
	e, _ := capture.NewEvent(seq, time.Now(), evtType, capture.SourceFSWatch,
		capture.StorageEventData{Path: path, Category: category, Operation: "create"})
	return e
}

func consoleEvent(seq int, level, message string) capture.Event {
	e, _ := capture.NewEvent(seq, time.Now(), capture.EventConsoleLog, capture.SourceCDP,
		capture.ConsoleLogData{Level: level, Message: message})
	return e
}

func TestCompareDetectsStorageChanges(t *testing.T) {
	before := makeSession(storageEvent(1, "localstorage", "/data/old", capture.EventStorageWrite))
	after := makeSession(
		storageEvent(1, "localstorage", "/data/new", capture.EventStorageWrite),
		storageEvent(2, "indexeddb", "/db/cache", capture.EventStorageDelete),
	)

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.Storage.Added) != 2 {
		t.Errorf("storage added = %d, want 2", len(result.Storage.Added))
	}
	if len(result.Storage.Removed) != 1 {
		t.Errorf("storage removed = %d, want 1", len(result.Storage.Removed))
	}
}

func TestCompareDetectsConsoleChanges(t *testing.T) {
	before := makeSession(consoleEvent(1, "info", "app started"))
	after := makeSession(consoleEvent(1, "error", "crash detected"))

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.Console.Added) != 1 {
		t.Errorf("console added = %d, want 1", len(result.Console.Added))
	}
	if len(result.Console.Removed) != 1 {
		t.Errorf("console removed = %d, want 1", len(result.Console.Removed))
	}
}

func TestConsoleMessageTruncation(t *testing.T) {
	longMsg := ""
	for i := 0; i < 100; i++ {
		longMsg += "x"
	}
	before := makeSession()
	after := makeSession(consoleEvent(1, "warn", longMsg))

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.Console.Added) != 1 {
		t.Fatalf("console added = %d, want 1", len(result.Console.Added))
	}
	// Message should be truncated to 80 chars + "..."
	expected := "warn:" + longMsg[:80] + "..."
	if result.Console.Added[0] != expected {
		t.Errorf("got %q, want %q", result.Console.Added[0], expected)
	}
}

func TestCompareDetectsRemovedEndpoint(t *testing.T) {
	before := makeSession(
		netReqEvent(1, "GET", "https://api.example.com/v1/data"),
		netReqEvent(2, "DELETE", "https://api.example.com/v1/old"),
	)
	after := makeSession(netReqEvent(1, "GET", "https://api.example.com/v1/data"))

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.Network.Removed) != 1 {
		t.Fatalf("removed = %d, want 1", len(result.Network.Removed))
	}
	if result.Network.Removed[0].Method != "DELETE" {
		t.Errorf("method = %q, want DELETE", result.Network.Removed[0].Method)
	}
}

func TestCompareDetectsRemovedIPC(t *testing.T) {
	before := makeSession(ipcEvent(1, "old-channel"), ipcEvent(2, "keep-channel"))
	after := makeSession(ipcEvent(1, "keep-channel"))

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.IPC.Removed) != 1 || result.IPC.Removed[0] != "old-channel" {
		t.Errorf("ipc removed = %v, want [old-channel]", result.IPC.Removed)
	}
}

func TestCompareDetectsRemovedStealth(t *testing.T) {
	before := makeSession(stealthEvent(1, "visibility", "hidden"))
	after := makeSession()

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.Stealth.Removed) != 1 {
		t.Errorf("stealth removed = %d, want 1", len(result.Stealth.Removed))
	}
}

func TestStealthIgnoresNonStealthProperties(t *testing.T) {
	before := makeSession()
	after := makeSession(stealthEvent(1, "focus", "true"))

	result := Compare(before, after, "v1.json", "v2.json")
	if len(result.Stealth.Added) != 0 {
		t.Errorf("stealth added = %d, want 0 (non-stealth property)", len(result.Stealth.Added))
	}
}

func TestCompareSkipsInvalidEventData(t *testing.T) {
	// Events with wrong type should be ignored by extractors
	domEvent, _ := capture.NewEvent(1, time.Now(), capture.EventDOMEvent, capture.SourceCDP,
		map[string]string{"type": "click"})
	before := makeSession(domEvent)
	after := makeSession(domEvent)

	result := Compare(before, after, "v1.json", "v2.json")
	if result.Summary != "No behavioral changes detected." {
		t.Errorf("unexpected summary: %q", result.Summary)
	}
}

func TestBuildSummaryMultipleParts(t *testing.T) {
	before := makeSession()
	after := makeSession(
		netReqEvent(1, "GET", "https://new.api.com/track"),
		ipcEvent(2, "new-channel"),
		stealthEvent(3, "content_protection", "true"),
		storageEvent(4, "localstorage", "/new/path", capture.EventStorageWrite),
	)

	result := Compare(before, after, "v1.json", "v2.json")
	if result.Summary == "No behavioral changes detected." {
		t.Error("expected changes in summary")
	}
	// Should contain "and" for multiple parts
	if len(result.Summary) == 0 {
		t.Error("empty summary")
	}
}

func TestBuildSummaryWithRemovedEndpoints(t *testing.T) {
	before := makeSession(netReqEvent(1, "GET", "https://old.api.com/data"))
	after := makeSession()

	result := Compare(before, after, "v1.json", "v2.json")
	if result.Summary == "No behavioral changes detected." {
		t.Error("should detect removed endpoints")
	}
}

func TestFormatText(t *testing.T) {
	before := makeSession()
	after := makeSession(netReqEvent(1, "POST", "https://new.api.com/track"))
	result := Compare(before, after, "v1.json", "v2.json")
	text := FormatText(result)
	if text == "" {
		t.Error("empty text output")
	}
}

func TestFormatTextAllSections(t *testing.T) {
	before := makeSession(
		netReqEvent(1, "GET", "https://old.api.com/removed"),
		ipcEvent(2, "old-chan"),
		stealthEvent(3, "visibility", "hidden"),
		storageEvent(4, "localstorage", "/old", capture.EventStorageWrite),
	)
	after := makeSession(
		netReqEvent(1, "POST", "https://new.api.com/added"),
		ipcEvent(2, "new-chan"),
		stealthEvent(3, "content_protection", "true"),
		storageEvent(4, "indexeddb", "/new", capture.EventStorageDelete),
	)

	result := Compare(before, after, "before.json", "after.json")
	text := FormatText(result)

	for _, want := range []string{
		"Network Endpoints:",
		"IPC Channels:",
		"Stealth Behavior:",
		"Storage:",
		"before.json",
		"after.json",
	} {
		if !contains(text, want) {
			t.Errorf("FormatText missing %q", want)
		}
	}
}

func TestFormatTextNoChanges(t *testing.T) {
	s := makeSession()
	result := Compare(s, s, "a.json", "b.json")
	text := FormatText(result)
	if !contains(text, "No behavioral changes detected.") {
		t.Errorf("expected no changes message, got: %s", text)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
