package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteReadRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	reqData := NetworkRequestData{
		Method:  "GET",
		URL:     "https://api.example.com/data",
		Headers: map[string]string{"Authorization": "Bearer tok"},
	}

	evt, err := NewEvent(1, now, EventNetworkRequest, SourceCDP, reqData)
	if err != nil {
		t.Fatalf("NewEvent: %v", err)
	}

	session := &CaptureSession{
		Version: FormatVersion,
		App: AppInfo{
			Name:      "TestApp",
			Path:      "/opt/testapp",
			Framework: "electron",
			PID:       1234,
		},
		Capture: CaptureMetadata{
			StartedAt:   now,
			EndedAt:     now.Add(5 * time.Second),
			DurationMs:  5000,
			Host:        "localhost",
			ToolVersion: "0.1.0",
		},
		Events: []Event{evt},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "capture.json")

	if err := WriteFile(path, session); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if got.Version != FormatVersion {
		t.Errorf("version = %q, want %q", got.Version, FormatVersion)
	}
	if got.App.Name != "TestApp" {
		t.Errorf("app name = %q, want %q", got.App.Name, "TestApp")
	}
	if got.App.PID != 1234 {
		t.Errorf("app pid = %d, want %d", got.App.PID, 1234)
	}
	if got.Capture.DurationMs != 5000 {
		t.Errorf("duration = %d, want %d", got.Capture.DurationMs, 5000)
	}
	if len(got.Events) != 1 {
		t.Fatalf("events count = %d, want 1", len(got.Events))
	}
	if got.Events[0].Type != EventNetworkRequest {
		t.Errorf("event type = %q, want %q", got.Events[0].Type, EventNetworkRequest)
	}

	var decoded NetworkRequestData
	if err := DecodeEventData(got.Events[0], &decoded); err != nil {
		t.Fatalf("DecodeEventData: %v", err)
	}
	if decoded.URL != reqData.URL {
		t.Errorf("decoded URL = %q, want %q", decoded.URL, reqData.URL)
	}
	if decoded.Method != reqData.Method {
		t.Errorf("decoded Method = %q, want %q", decoded.Method, reqData.Method)
	}
}

func TestReadFileErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		setup   func(t *testing.T) string
	}{
		{
			name: "missing file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent.json")
			},
		},
		{
			name:    "corrupt JSON",
			content: `{not valid json`,
			setup: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "corrupt.json")
				if err := os.WriteFile(p, []byte(`{not valid json`), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
		},
		{
			name: "missing version",
			setup: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "noversion.json")
				if err := os.WriteFile(p, []byte(`{"app":{},"capture":{},"events":[]}`), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			_, err := ReadFile(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestSortEvents(t *testing.T) {
	now := time.Now()
	events := []Event{
		{Seq: 3, TS: now.Add(2 * time.Second), Type: EventConsoleLog, Source: SourceCDP},
		{Seq: 1, TS: now, Type: EventConsoleLog, Source: SourceCDP},
		{Seq: 2, TS: now.Add(1 * time.Second), Type: EventConsoleLog, Source: SourceCDP},
	}

	SortEvents(events)

	for i, e := range events {
		if e.Seq != i+1 {
			t.Errorf("events[%d].Seq = %d, want %d", i, e.Seq, i+1)
		}
	}
}

func TestNewEventDecodeRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := ConsoleLogData{
		Level:   "warn",
		Message: "something happened",
		Args:    []string{"detail1", "detail2"},
	}

	evt, err := NewEvent(42, now, EventConsoleLog, SourceCDP, original)
	if err != nil {
		t.Fatalf("NewEvent: %v", err)
	}

	if evt.Seq != 42 {
		t.Errorf("seq = %d, want 42", evt.Seq)
	}
	if evt.Type != EventConsoleLog {
		t.Errorf("type = %q, want %q", evt.Type, EventConsoleLog)
	}

	var decoded ConsoleLogData
	if err := DecodeEventData(evt, &decoded); err != nil {
		t.Fatalf("DecodeEventData: %v", err)
	}
	if decoded.Level != original.Level {
		t.Errorf("level = %q, want %q", decoded.Level, original.Level)
	}
	if decoded.Message != original.Message {
		t.Errorf("message = %q, want %q", decoded.Message, original.Message)
	}
	if len(decoded.Args) != len(original.Args) {
		t.Fatalf("args len = %d, want %d", len(decoded.Args), len(original.Args))
	}
}
