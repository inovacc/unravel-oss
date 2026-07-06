/*
Copyright (c) 2026 Security Research
*/

package identity

import "sync"

// PackageIDResolver extracts a stable per-platform identifier (PFN, bundle
// id, package name, etc.) from an analyzer artifact. Resolvers are
// registered via init() in their analyzer subpackage and wired into the
// binary by blank-import from pkg/knowledge/kb/identity/runtime.
type PackageIDResolver func(ctx ResolverContext) (packageID string, err error)

// ResolverContext carries the analyzer-side inputs a resolver needs. Path
// is typically a directory or file path; Extra is reserved for callers that
// already parsed structured data and want to short-circuit re-parse.
type ResolverContext struct {
	Platform string
	Path     string
	Extra    map[string]any
}

var (
	resolversMu sync.RWMutex
	resolvers   = map[string]PackageIDResolver{}
)

// Register associates a resolver with a platform key (member of
// D-29-PLATFORM-SET). Last-write-wins. Intended to be called from analyzer
// init() funcs only.
func Register(platform string, fn PackageIDResolver) {
	resolversMu.Lock()
	defer resolversMu.Unlock()
	resolvers[platform] = fn
}

// Resolve dispatches to the registered resolver for ctx.Platform. When no
// resolver is registered for that platform, returns ("", nil) so the caller
// can fall back to canonical_name derivation.
func Resolve(ctx ResolverContext) (string, error) {
	resolversMu.RLock()
	fn, ok := resolvers[ctx.Platform]
	resolversMu.RUnlock()
	if !ok {
		return "", nil
	}
	return fn(ctx)
}
