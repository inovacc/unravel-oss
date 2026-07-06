/*
Copyright (c) 2026 Security Research

Package communication registers positive rules that classify modules into the
communication taxonomy bucket.
*/
package communication

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathComm = regexp.MustCompile(`(?i)(^|/)(net|http|client|api|rest|websocket|ws)/`)
	nameComm = regexp.MustCompile(`(?i)(Http|Client|Request|Response|Fetch|Api|Rest|Websocket)`)
)

func init() {
	component.Register(component.Rule{
		Name: "communication/path-name-symbol", Component: "communication", Confidence: 0.95, Priority: 5,
		PathRegex: pathComm, NameRegex: nameComm,
		SymbolKeywords: []string{"http.Client", "fetch", "axios", "websocket", "ws://", "wss://", "grpc.Dial"},
	})
	component.Register(component.Rule{
		Name: "communication/name-symbol", Component: "communication", Confidence: 0.80, Priority: 5,
		NameRegex:      nameComm,
		SymbolKeywords: []string{"http.Client", "fetch", "axios", "websocket"},
	})
	component.Register(component.Rule{
		Name: "communication/path-symbol", Component: "communication", Confidence: 0.80, Priority: 5,
		PathRegex:      pathComm,
		SymbolKeywords: []string{"http.Client", "fetch", "websocket", "grpc.Dial"},
	})
}
