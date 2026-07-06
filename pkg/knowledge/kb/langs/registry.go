package langs

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"sync"
)

// registryEntry pairs a language tag with its extractor for fast lookup.
type registryEntry struct {
	Lang    string
	Extract ExtractFn
}

var (
	mu       sync.RWMutex
	registry = map[string]registryEntry{}
)

// Register associates a file extension (e.g. ".go") with a language tag
// (e.g. "go") and an extractor. Extension is normalised to lowercase and
// must include the leading dot. Subsequent registrations for the same
// extension overwrite the previous one — last writer wins, which lets
// downstream callers monkey-patch the registry from tests.
func Register(ext, lang string, fn ExtractFn) {
	if ext == "" || fn == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	registry[strings.ToLower(ext)] = registryEntry{Lang: lang, Extract: fn}
}

// Lookup returns the extractor + language tag for the given file extension
// and a boolean indicating whether one was registered. The extension can
// be passed with or without a leading dot.
func Lookup(ext string) (ExtractFn, string, bool) {
	if ext == "" {
		return nil, "", false
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	mu.RLock()
	defer mu.RUnlock()
	e, ok := registry[strings.ToLower(ext)]
	if !ok {
		return nil, "", false
	}
	return e.Extract, e.Lang, true
}

// Registered returns the set of currently-registered file extensions.
// Helpful for the walker's --lang filter and for stats output.
func Registered() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]string, len(registry))
	for ext, e := range registry {
		out[ext] = e.Lang
	}
	return out
}

// DefaultExtractor is the catch-all extractor used when no language is
// registered for a file extension. It captures the filename as the module
// name and stores up to the first 4 KB of the body as the excerpt. The
// full body is sha256-hashed so the (app, body_sha256) UNIQUE on modules
// dedupes identical files.
//
// This deliberately produces an empty SymbolsJSON / Imports list — the
// generic extractor has no syntactic knowledge of the file.
func DefaultExtractor(path string, body []byte) (Module, error) {
	const excerptCap = 4096
	excerpt := body
	if len(excerpt) > excerptCap {
		excerpt = excerpt[:excerptCap]
	}
	sum := sha256.Sum256(body)
	return Module{
		Name:        filepath.Base(path),
		BodyExcerpt: string(excerpt),
		BodySHA256:  hex.EncodeToString(sum[:]),
		FullBody:    body,
		Lang:        "",
		Size:        len(body),
	}, nil
}
