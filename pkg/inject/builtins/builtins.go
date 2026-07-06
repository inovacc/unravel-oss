/*
Copyright (c) 2026 Security Research
*/

// Package builtins ships unravel's embedded analysis-instrumentation
// scripts. Scripts are checked in as plain JS and embedded at compile
// time; SHA-256 hashes are exposed for forensic logging by Phase 46-02.
package builtins

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.js
var fsys embed.FS

// ErrBuiltinNotFound is returned by Get/Hash for unknown script names.
var ErrBuiltinNotFound = errors.New("builtins: not found")

// nameToFile maps a logical name to an embedded filename.
func nameToFile(name string) string {
	return name + ".js"
}

// Get returns the embedded bytes for the named built-in script.
// Names use the bare slug, e.g. "devtools", "ipc-logger", "network".
func Get(name string) ([]byte, error) {
	b, err := fsys.ReadFile(nameToFile(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrBuiltinNotFound, name)
		}
		return nil, err
	}
	return b, nil
}

// List returns the sorted slugs of all embedded built-in scripts.
func List() []string {
	entries, err := fsys.ReadDir(".")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".js") {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ".js"))
	}
	sort.Strings(out)
	return out
}

// Hash returns the SHA-256 of the named script formatted as
// "sha256:<hex>" for forensic logging.
func Hash(name string) (string, error) {
	b, err := Get(name)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
