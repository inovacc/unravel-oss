package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// WriteFile marshals the session to indented JSON and writes it to the given path.
func WriteFile(path string, session *CaptureSession) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write capture file: %w", err)
	}
	return nil
}

// ReadFile reads a capture session from a JSON file and validates the format version.
func ReadFile(path string) (*CaptureSession, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read capture file: %w", err)
	}

	var session CaptureSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("unmarshal capture file: %w", err)
	}

	if session.Version == "" {
		return nil, fmt.Errorf("capture file missing version field")
	}

	return &session, nil
}

// SortEvents sorts events by their timestamp.
func SortEvents(events []Event) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].TS.Before(events[j].TS)
	})
}

// NewEvent creates a new Event, marshaling the given data to JSON.
func NewEvent(seq int, ts time.Time, typ EventType, source EventSource, data any) (Event, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return Event{}, fmt.Errorf("marshal event data: %w", err)
	}
	return Event{
		Seq:    seq,
		TS:     ts,
		Type:   typ,
		Source: source,
		Data:   raw,
	}, nil
}

// DecodeEventData unmarshals the event's Data field into the given target.
func DecodeEventData(e Event, target any) error {
	if err := json.Unmarshal(e.Data, target); err != nil {
		return fmt.Errorf("decode event data: %w", err)
	}
	return nil
}
