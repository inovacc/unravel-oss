package plugin

import (
	"fmt"
	"slices"
	"sync"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

// Registry manages registered analyzer plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Analyzer
}

// NewRegistry creates an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Analyzer),
	}
}

// Register adds a plugin to the registry. Returns an error if a plugin
// with the same name is already registered.
func (r *Registry) Register(p Analyzer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[p.Name()]; exists {
		return fmt.Errorf("plugin %q already registered", p.Name())
	}
	r.plugins[p.Name()] = p
	return nil
}

// Get returns a plugin by name.
func (r *Registry) Get(name string) (Analyzer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.plugins[name]
	return p, ok
}

// FindForType returns all plugins that can handle a given file type.
func (r *Registry) FindForType(ft detect.FileType) []Analyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Analyzer
	for _, p := range r.plugins {
		if slices.Contains(p.SupportedTypes(), ft) {
			result = append(result, p)
		}
	}
	return result
}

// FindForFile returns the best plugin for a given file based on detect result.
// It iterates registered plugins and returns the first one whose CanHandle
// returns true. Returns nil if no plugin matches.
func (r *Registry) FindForFile(path string, result *detect.DetectResult) Analyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.plugins {
		if p.CanHandle(path, result) {
			return p
		}
	}
	return nil
}

// List returns manifests for all registered plugins.
func (r *Registry) List() []Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()

	manifests := make([]Manifest, 0, len(r.plugins))
	for _, p := range r.plugins {
		manifests = append(manifests, ManifestFrom(p))
	}
	return manifests
}

// Count returns the number of registered plugins.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.plugins)
}
