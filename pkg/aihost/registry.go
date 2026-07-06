/*
Copyright (c) 2026 Security Research
*/

package aihost

// All returns every registered host. Add new hosts here so cmd/ can
// dispatch install/uninstall across all of them when --host=all is set.
//
// Registry intentionally lives in its own file (not host.go) so adding
// a host means touching exactly two places: this file + a new
// pkg/aihost/<name>/ package.
//
// Wired lazily via a factory func to avoid a circular import: hosts
// import aihost for the interface; aihost can only import them back
// through a registration callback.
type factory func() Host

var registry []factory

// Register adds a host factory. Called from each host package's init().
func Register(f factory) { registry = append(registry, f) }

// All instantiates every registered host.
func All() []Host {
	out := make([]Host, 0, len(registry))
	for _, f := range registry {
		out = append(out, f())
	}
	return out
}

// ByName returns the host with matching Name() (case-sensitive).
func ByName(name string) (Host, bool) {
	for _, h := range All() {
		if h.Name() == name {
			return h, true
		}
	}
	return nil, false
}
