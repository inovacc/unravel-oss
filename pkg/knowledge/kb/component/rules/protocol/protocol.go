/*
Copyright (c) 2026 Security Research

Package protocol registers positive rules that classify modules into the
protocol taxonomy bucket.
*/
package protocol

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathProto = regexp.MustCompile(`(?i)(^|/)(protocol|proto|codec|marshal|serialize|encode)/`)
	nameProto = regexp.MustCompile(`(?i)(Protocol|Codec|Marshal|Encoder|Decoder|Proto|Pb)`)
)

func init() {
	component.Register(component.Rule{
		Name: "protocol/path-name-symbol", Component: "protocol", Confidence: 0.95, Priority: 2,
		PathRegex: pathProto, NameRegex: nameProto,
		SymbolKeywords: []string{"proto.Marshal", "proto.Unmarshal", "json.Marshal", "json.Unmarshal", "gob", "msgpack", "cbor", "protobuf"},
	})
	component.Register(component.Rule{
		Name: "protocol/name-symbol", Component: "protocol", Confidence: 0.80, Priority: 2,
		NameRegex:      nameProto,
		SymbolKeywords: []string{"proto.Marshal", "proto.Unmarshal", "msgpack", "cbor", "protobuf"},
	})
	component.Register(component.Rule{
		Name: "protocol/path-symbol", Component: "protocol", Confidence: 0.80, Priority: 2,
		PathRegex:      pathProto,
		SymbolKeywords: []string{"proto.Marshal", "msgpack", "cbor", "protobuf"},
	})
}
