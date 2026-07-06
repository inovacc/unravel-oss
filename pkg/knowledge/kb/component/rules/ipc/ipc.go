/*
Copyright (c) 2026 Security Research

Package ipc registers positive rules that classify modules into the ipc
taxonomy bucket.
*/
package ipc

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathIPC = regexp.MustCompile(`(?i)(^|/)(ipc|bridge|preload)/`)
	nameIPC = regexp.MustCompile(`(?i)(Ipc|Bridge|Preload|Postmessage|Channel)`)
)

func init() {
	component.Register(component.Rule{
		Name: "ipc/path-name-symbol", Component: "ipc", Confidence: 0.95, Priority: 4,
		PathRegex: pathIPC, NameRegex: nameIPC,
		SymbolKeywords: []string{"ipcRenderer", "ipcMain", "contextBridge", "postMessage", "MessageChannel", "BroadcastChannel"},
	})
	component.Register(component.Rule{
		Name: "ipc/name-symbol", Component: "ipc", Confidence: 0.80, Priority: 4,
		NameRegex:      nameIPC,
		SymbolKeywords: []string{"ipcRenderer", "ipcMain", "contextBridge", "postMessage"},
	})
	component.Register(component.Rule{
		Name: "ipc/path-symbol", Component: "ipc", Confidence: 0.80, Priority: 4,
		PathRegex:      pathIPC,
		SymbolKeywords: []string{"ipcRenderer", "contextBridge", "MessageChannel"},
	})
}
