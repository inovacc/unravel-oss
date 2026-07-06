/*
Copyright (c) 2026 Security Research

Package eval scores the rule-based classifier against a hand-labeled corpus.
Precision is the merge gate per D-31-PRECISION-GATE.

The active runner is RunCorpusV2 (corpus_v2.go). The legacy v1 Corpus and
LabeledModule types remain solely as the input shape for
MigrateCorpusV1ToV2.
*/
package eval

// LabeledModule is a v1 corpus entry. Retained for MigrateCorpusV1ToV2.
type LabeledModule struct {
	Name              string `json:"name"`
	Path              string `json:"path"`
	SymbolsJSON       string `json:"symbols_json"`
	ExpectedComponent string `json:"expected_component"`
	Notes             string `json:"notes,omitempty"`
}

// Corpus is the v1 on-disk schema. Retained for MigrateCorpusV1ToV2.
type Corpus struct {
	Version int             `json:"version"`
	Modules []LabeledModule `json:"modules"`
}
