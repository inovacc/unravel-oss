/*
Copyright (c) 2026 Security Research
*/

// Package backfill provides pure-Go, no-AI helpers for the
// `knowledge backfill-static` command.
//
// Extract wraps the langs registry to turn raw body bytes into the
// (Imports, SymbolsJSON) pair the command needs to upsert module_deps
// and refresh noisy symbols_json values.
package backfill

import (
	"path/filepath"
	"strings"

	kblangs "github.com/inovacc/unravel-oss/pkg/knowledge/kb/langs"
)

// Extract runs the appropriate langs extractor for the given module name
// and body bytes and returns the resulting import list and symbols JSON.
//
// lang is the value of modules.lang (may be empty). name is the value of
// modules.name (used to derive the file extension when lang is empty).
//
// The function never returns an error from the extractor itself — parse
// failures fall back to DefaultExtractor so callers always get a usable
// (possibly empty) result.
func Extract(body []byte, name, lang string) (imports []string, symbolsJSON string, err error) {
	extract, resolvedLang := resolveExtractor(name, lang)
	_ = resolvedLang

	mod, extractErr := extract(name, body)
	if extractErr != nil {
		// Parse failure: fall back to the generic extractor so we never
		// propagate a hard error from a single malformed file.
		mod, _ = kblangs.DefaultExtractor(name, body)
	}
	return mod.Imports, mod.SymbolsJSON, nil
}

// resolveExtractor picks the best ExtractFn for a module given its stored
// name (filename) and lang tag. Priority:
//  1. Extension of the name → langs.Lookup(".ext")
//  2. lang tag → langs.Lookup("."+lang)
//  3. JS heuristic — the corpus contains many extensionless minified JS bundles
//     (Teams, WhatsApp, Discord …) stored without a lang tag; treat them as JS
//     so the beautifier pass can recover imports and symbols.
//  4. DefaultExtractor (generic fallback — empty symbols, no imports)
func resolveExtractor(name, lang string) (kblangs.ExtractFn, string) {
	ext := strings.ToLower(filepath.Ext(name))
	if ext != "" {
		if fn, l, ok := kblangs.Lookup(ext); ok {
			return fn, l
		}
	}
	if lang != "" {
		if fn, l, ok := kblangs.Lookup("." + strings.ToLower(lang)); ok {
			return fn, l
		}
	}
	// Heuristic: extensionless modules with no lang tag in this corpus are almost
	// always minified JS bundles (Teams/WhatsApp/Discord store modules by logical
	// name, not filename).  Attempt JS extraction; if it yields nothing, the
	// caller's empty-result guard prevents any write.
	if ext == "" && lang == "" {
		if fn, l, ok := kblangs.Lookup(".js"); ok {
			return fn, l
		}
	}
	return kblangs.DefaultExtractor, ""
}
