package diff

import "fmt"

// FormatText renders a diff result as a human-readable string.
func FormatText(r *Result) string {
	var s string

	s += fmt.Sprintf("Capture Diff: %s vs %s\n", r.Before.File, r.After.File)
	s += fmt.Sprintf("  Before: %s (%d events)\n", r.Before.AppName, r.Before.EventCount)
	s += fmt.Sprintf("  After:  %s (%d events)\n\n", r.After.AppName, r.After.EventCount)

	if len(r.Network.Added) > 0 || len(r.Network.Removed) > 0 {
		s += "Network Endpoints:\n"
		for _, e := range r.Network.Added {
			s += fmt.Sprintf("  + %s %s\n", e.Method, e.URL)
		}
		for _, e := range r.Network.Removed {
			s += fmt.Sprintf("  - %s %s\n", e.Method, e.URL)
		}
		s += "\n"
	}

	if len(r.IPC.Added) > 0 || len(r.IPC.Removed) > 0 {
		s += "IPC Channels:\n"
		for _, ch := range r.IPC.Added {
			s += fmt.Sprintf("  + %s\n", ch)
		}
		for _, ch := range r.IPC.Removed {
			s += fmt.Sprintf("  - %s\n", ch)
		}
		s += "\n"
	}

	if len(r.Stealth.Added) > 0 || len(r.Stealth.Removed) > 0 {
		s += "Stealth Behavior:\n"
		for _, b := range r.Stealth.Added {
			s += fmt.Sprintf("  + %s\n", b)
		}
		for _, b := range r.Stealth.Removed {
			s += fmt.Sprintf("  - %s\n", b)
		}
		s += "\n"
	}

	if len(r.Storage.Added) > 0 || len(r.Storage.Removed) > 0 {
		s += "Storage:\n"
		for _, p := range r.Storage.Added {
			s += fmt.Sprintf("  + %s\n", p)
		}
		for _, p := range r.Storage.Removed {
			s += fmt.Sprintf("  - %s\n", p)
		}
		s += "\n"
	}

	s += r.Summary + "\n"
	return s
}
