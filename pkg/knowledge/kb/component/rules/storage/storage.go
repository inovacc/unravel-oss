/*
Copyright (c) 2026 Security Research

Package storage registers positive rules that classify modules into the
storage taxonomy bucket.
*/
package storage

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathStore = regexp.MustCompile(`(?i)(^|/)(storage|persist|cache|db|database|leveldb|sqlite)/`)
	nameStore = regexp.MustCompile(`(?i)(Storage|Persist|Cache|Database|LevelDB|Sqlite|Repository|Dao)`)
)

func init() {
	component.Register(component.Rule{
		Name: "storage/path-name-symbol", Component: "storage", Confidence: 0.95, Priority: 6,
		PathRegex: pathStore, NameRegex: nameStore,
		SymbolKeywords: []string{"leveldb", "sqlite", "indexeddb", "localStorage", "sessionStorage", "FileSystem", "kvstore"},
	})
	component.Register(component.Rule{
		Name: "storage/name-symbol", Component: "storage", Confidence: 0.80, Priority: 6,
		NameRegex:      nameStore,
		SymbolKeywords: []string{"leveldb", "sqlite", "indexeddb", "kvstore"},
	})
	component.Register(component.Rule{
		Name: "storage/path-symbol", Component: "storage", Confidence: 0.80, Priority: 6,
		PathRegex:      pathStore,
		SymbolKeywords: []string{"leveldb", "sqlite", "indexeddb"},
	})
}
