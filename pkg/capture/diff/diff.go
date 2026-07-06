package diff

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// Result holds the full behavioral diff between two capture sessions.
type Result struct {
	Before  FileSummary `json:"before"`
	After   FileSummary `json:"after"`
	Network NetworkDiff `json:"network"`
	IPC     SetDiff     `json:"ipc"`
	Storage SetDiff     `json:"storage"`
	Stealth StealthDiff `json:"stealth"`
	Console ConsoleDiff `json:"console"`
	Summary string      `json:"summary"`
}

// FileSummary describes one side of the comparison.
type FileSummary struct {
	File       string `json:"file"`
	AppName    string `json:"app_name"`
	EventCount int    `json:"event_count"`
}

// NetworkDiff lists added, removed, and changed network endpoints.
type NetworkDiff struct {
	Added   []EndpointInfo `json:"added"`
	Removed []EndpointInfo `json:"removed"`
	Changed []ChangeDetail `json:"changed,omitempty"`
}

// EndpointInfo describes a single network endpoint.
type EndpointInfo struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Path   string `json:"path"`
}

// ChangeDetail describes a modification to an existing endpoint.
type ChangeDetail struct {
	URL    string `json:"url"`
	Detail string `json:"detail"`
}

// SetDiff lists added and removed string values.
type SetDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// StealthDiff lists added and removed stealth behaviors.
type StealthDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// ConsoleDiff lists added and removed console log patterns.
type ConsoleDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// Compare produces a behavioral diff between two capture sessions.
func Compare(before, after *capture.CaptureSession, beforeFile, afterFile string) *Result {
	result := &Result{
		Before: FileSummary{File: beforeFile, AppName: before.App.Name, EventCount: len(before.Events)},
		After:  FileSummary{File: afterFile, AppName: after.App.Name, EventCount: len(after.Events)},
	}

	beforeEndpoints := extractEndpoints(before)
	afterEndpoints := extractEndpoints(after)
	result.Network = diffEndpoints(beforeEndpoints, afterEndpoints)

	beforeIPC := extractIPCChannels(before)
	afterIPC := extractIPCChannels(after)
	result.IPC = diffStringSets(beforeIPC, afterIPC)

	beforeStorage := extractStoragePaths(before)
	afterStorage := extractStoragePaths(after)
	result.Storage = diffStringSets(beforeStorage, afterStorage)

	beforeStealth := extractStealthEvents(before)
	afterStealth := extractStealthEvents(after)
	result.Stealth = StealthDiff(diffStringSets(beforeStealth, afterStealth))

	beforeConsole := extractConsolePatterns(before)
	afterConsole := extractConsolePatterns(after)
	result.Console = ConsoleDiff(diffStringSets(beforeConsole, afterConsole))

	result.Summary = buildSummary(result)
	return result
}

func extractEndpoints(s *capture.CaptureSession) map[string]EndpointInfo {
	endpoints := make(map[string]EndpointInfo)
	for _, evt := range s.Events {
		if evt.Type != capture.EventNetworkRequest {
			continue
		}
		var req capture.NetworkRequestData
		if err := json.Unmarshal(evt.Data, &req); err != nil {
			continue
		}
		parsed, err := url.Parse(req.URL)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%s %s%s", req.Method, parsed.Host, parsed.Path)
		endpoints[key] = EndpointInfo{Method: req.Method, URL: req.URL, Host: parsed.Host, Path: parsed.Path}
	}
	return endpoints
}

func extractIPCChannels(s *capture.CaptureSession) map[string]bool {
	channels := make(map[string]bool)
	for _, evt := range s.Events {
		if evt.Type != capture.EventIPCMessage {
			continue
		}
		var ipc capture.IPCMessageData
		if err := json.Unmarshal(evt.Data, &ipc); err != nil {
			continue
		}
		channels[ipc.Channel] = true
	}
	return channels
}

func extractStoragePaths(s *capture.CaptureSession) map[string]bool {
	paths := make(map[string]bool)
	for _, evt := range s.Events {
		if evt.Type != capture.EventStorageWrite && evt.Type != capture.EventStorageDelete {
			continue
		}
		var storage capture.StorageEventData
		if err := json.Unmarshal(evt.Data, &storage); err != nil {
			continue
		}
		paths[storage.Category+":"+storage.Path] = true
	}
	return paths
}

func extractStealthEvents(s *capture.CaptureSession) map[string]bool {
	stealth := make(map[string]bool)
	for _, evt := range s.Events {
		if evt.Type != capture.EventWindowState {
			continue
		}
		var ws capture.WindowStateData
		if err := json.Unmarshal(evt.Data, &ws); err != nil {
			continue
		}
		if ws.Property == "content_protection" || ws.Property == "visibility" {
			stealth[fmt.Sprintf("%s=%s", ws.Property, ws.Value)] = true
		}
	}
	return stealth
}

func extractConsolePatterns(s *capture.CaptureSession) map[string]bool {
	patterns := make(map[string]bool)
	for _, evt := range s.Events {
		if evt.Type != capture.EventConsoleLog {
			continue
		}
		var log capture.ConsoleLogData
		if err := json.Unmarshal(evt.Data, &log); err != nil {
			continue
		}
		msg := log.Message
		if len(msg) > 80 {
			msg = msg[:80] + "..."
		}
		patterns[log.Level+":"+msg] = true
	}
	return patterns
}

func diffEndpoints(before, after map[string]EndpointInfo) NetworkDiff {
	var d NetworkDiff
	for key, info := range after {
		if _, ok := before[key]; !ok {
			d.Added = append(d.Added, info)
		}
	}
	for key, info := range before {
		if _, ok := after[key]; !ok {
			d.Removed = append(d.Removed, info)
		}
	}
	return d
}

func diffStringSets(before, after map[string]bool) SetDiff {
	var d SetDiff
	for key := range after {
		if !before[key] {
			d.Added = append(d.Added, key)
		}
	}
	for key := range before {
		if !after[key] {
			d.Removed = append(d.Removed, key)
		}
	}
	return d
}

func buildSummary(r *Result) string {
	var parts []string
	if n := len(r.Network.Added); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new network endpoint(s)", n))
	}
	if n := len(r.Network.Removed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d removed endpoint(s)", n))
	}
	if n := len(r.IPC.Added); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new IPC channel(s)", n))
	}
	if n := len(r.Stealth.Added); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new stealth behavior(s)", n))
	}
	if n := len(r.Storage.Added); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new storage path(s)", n))
	}
	if len(parts) == 0 {
		return "No behavioral changes detected."
	}
	return fmt.Sprintf("Changes: %s.", joinComma(parts))
}

func joinComma(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	result := ""
	for i, p := range parts {
		if i > 0 && i == len(parts)-1 {
			result += ", and "
		} else if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}
