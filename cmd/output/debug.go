/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"
	"time"
)

// StepMetadata captures per-analysis-step metadata (mirrors StepMetadata).
type StepMetadata struct {
	StepName     string    `json:"step_name"`
	Status       string    `json:"status"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	DurationMs   int64     `json:"duration_ms"`
	Model        string    `json:"model,omitempty"`
	InputTokens  int       `json:"input_tokens,omitempty"`
	OutputTokens int       `json:"output_tokens,omitempty"`
	StopReason   string    `json:"stop_reason,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// SessionSummary holds summary info for listing sessions.
type SessionSummary struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Timestamp string `json:"timestamp,omitempty"`
	FileType  string `json:"file_type,omitempty"`
	Input     string `json:"input,omitempty"`
	Steps     int    `json:"steps"`
	Errors    int    `json:"errors"`
	Duration  int64  `json:"duration_ms"`
}

// SessionDetail holds full details of a debug session.
type SessionDetail struct {
	Name    string         `json:"name"`
	Path    string         `json:"path"`
	Session map[string]any `json:"session,omitempty"`
	Steps   []StepMetadata `json:"steps"`
	Files   []string       `json:"files"`
}

// PrintDebugList prints a table of debug sessions.
func PrintDebugList(sessions []SessionSummary) {
	fmt.Println("┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│  Debug Sessions                                                  │")
	fmt.Println("├──────────────────────────────────────────────────────────────────┤")

	for i, s := range sessions {
		label := s.Name
		if i == 0 {
			label += " (latest)"
		}

		fmt.Printf("│  %-64s│\n", Truncate(label, 64))

		details := []string{}
		if s.FileType != "" {
			details = append(details, fmt.Sprintf("type=%s", s.FileType))
		}
		if s.Steps > 0 {
			details = append(details, fmt.Sprintf("steps=%d", s.Steps))
		}
		if s.Errors > 0 {
			details = append(details, fmt.Sprintf("errors=%d", s.Errors))
		}
		if s.Duration > 0 {
			details = append(details, fmt.Sprintf("duration=%dms", s.Duration))
		}

		if len(details) > 0 {
			line := "    " + strings.Join(details, "  ")
			fmt.Printf("│  %-64s│\n", Truncate(line, 64))
		}

		if s.Input != "" {
			fmt.Printf("│  %-64s│\n", Truncate("    input="+s.Input, 64))
		}

		if i < len(sessions)-1 {
			fmt.Println("│                                                                  │")
		}
	}

	fmt.Println("└──────────────────────────────────────────────────────────────────┘")
	fmt.Printf("\n  %d session(s) found. Use 'debug show <name>' for details.\n", len(sessions))
}

// PrintDebugShow prints detailed session information.
func PrintDebugShow(detail *SessionDetail) {
	fmt.Println("┌──────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│  Session: %-56s│\n", Truncate(detail.Name, 56))
	fmt.Println("├──────────────────────────────────────────────────────────────────┤")

	// Session metadata
	if detail.Session != nil {
		if ts, ok := detail.Session["timestamp"].(string); ok {
			fmt.Printf("│  Timestamp:  %-53s│\n", Truncate(ts, 53))
		}
		if inp, ok := detail.Session["input"].(string); ok {
			fmt.Printf("│  Input:      %-53s│\n", Truncate(inp, 53))
		}
		if ft, ok := detail.Session["file_type"].(string); ok {
			fmt.Printf("│  File Type:  %-53s│\n", ft)
		}
		if cat, ok := detail.Session["category"].(string); ok {
			fmt.Printf("│  Category:   %-53s│\n", cat)
		}
		if dur, ok := detail.Session["duration_ms"].(float64); ok {
			fmt.Printf("│  Duration:   %-53s│\n", fmt.Sprintf("%dms", int64(dur)))
		}
		if cnt, ok := detail.Session["errors_count"].(float64); ok && cnt > 0 {
			fmt.Printf("│  Errors:     %-53s│\n", fmt.Sprintf("%d", int(cnt)))
		}
	}

	// Files at session level
	if len(detail.Files) > 0 {
		fmt.Println("├──────────────────────────────────────────────────────────────────┤")
		fmt.Println("│  Session Files                                                   │")
		fmt.Println("│                                                                  │")
		for _, f := range detail.Files {
			fmt.Printf("│    %-62s│\n", Truncate(f, 62))
		}
	}

	// Steps
	if len(detail.Steps) > 0 {
		fmt.Println("├──────────────────────────────────────────────────────────────────┤")
		fmt.Println("│  Analysis Steps                                                  │")
		fmt.Println("│                                                                  │")

		for i, step := range detail.Steps {
			status := step.Status
			if status == "" {
				status = "unknown"
			}

			statusIcon := " "
			switch status {
			case "ok":
				statusIcon = "+"
			case "error":
				statusIcon = "!"
			case "skipped":
				statusIcon = "-"
			}

			name := Truncate(step.StepName, 45)
			fmt.Printf("│  [%s] %-45s %8dms  │\n", statusIcon, name, step.DurationMs)

			if step.Error != "" {
				errLine := "      Error: " + Truncate(step.Error, 50)
				fmt.Printf("│  %-64s│\n", errLine)
			}

			if step.Model != "" {
				info := fmt.Sprintf("      Model: %s  tokens: %d/%d",
					step.Model, step.InputTokens, step.OutputTokens)
				fmt.Printf("│  %-64s│\n", Truncate(info, 64))
			}

			if i < len(detail.Steps)-1 {
				fmt.Println("│                                                                  │")
			}
		}
	}

	fmt.Println("└──────────────────────────────────────────────────────────────────┘")
	fmt.Printf("\n  Path: %s\n", detail.Path)
}

// PrintDebugDiff prints a comparison of two debug sessions.
func PrintDebugDiff(s1, s2 *SessionDetail) {
	fmt.Println("┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│  Session Comparison                                              │")
	fmt.Println("├──────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│  A: %-62s│\n", Truncate(s1.Name, 62))
	fmt.Printf("│  B: %-62s│\n", Truncate(s2.Name, 62))
	fmt.Println("├──────────────────────────────────────────────────────────────────┤")

	// Compare metadata
	ft1 := sessionField(s1, "file_type")
	ft2 := sessionField(s2, "file_type")
	if ft1 != ft2 {
		fmt.Printf("│  File Type:  A=%-20s B=%-23s│\n", ft1, ft2)
	} else {
		fmt.Printf("│  File Type:  %-53s│\n", ft1)
	}

	dur1 := sessionDuration(s1)
	dur2 := sessionDuration(s2)
	diff := dur2 - dur1
	sign := "+"
	if diff < 0 {
		sign = ""
	}
	fmt.Printf("│  Duration:   A=%-12s B=%-12s (%s%dms)       │\n",
		fmt.Sprintf("%dms", dur1), fmt.Sprintf("%dms", dur2), sign, diff)

	// Compare steps
	fmt.Println("├──────────────────────────────────────────────────────────────────┤")
	fmt.Println("│  Steps                                                           │")
	fmt.Println("│                                                                  │")

	steps1 := mapSteps(s1.Steps)
	steps2 := mapSteps(s2.Steps)

	allSteps := mergeKeys(steps1, steps2)
	for _, name := range allSteps {
		st1, ok1 := steps1[name]
		st2, ok2 := steps2[name]

		shortName := Truncate(name, 30)
		switch {
		case ok1 && ok2:
			d := st2.DurationMs - st1.DurationMs
			dsign := "+"
			if d < 0 {
				dsign = ""
			}
			fmt.Printf("│  %-30s  A=%-8s B=%-8s (%s%dms)  │\n",
				shortName,
				fmt.Sprintf("%dms", st1.DurationMs),
				fmt.Sprintf("%dms", st2.DurationMs),
				dsign, d)
		case ok1:
			fmt.Printf("│  %-30s  A=%-8s B=%-18s│\n",
				shortName, fmt.Sprintf("%dms", st1.DurationMs), "(missing)")
		case ok2:
			fmt.Printf("│  %-30s  A=%-14s B=%-8s      │\n",
				shortName, "(missing)", fmt.Sprintf("%dms", st2.DurationMs))
		}
	}

	fmt.Println("└──────────────────────────────────────────────────────────────────┘")
}

func sessionField(d *SessionDetail, key string) string {
	if d.Session == nil {
		return ""
	}
	if v, ok := d.Session[key].(string); ok {
		return v
	}
	return ""
}

func sessionDuration(d *SessionDetail) int64 {
	if d.Session == nil {
		return 0
	}
	if v, ok := d.Session["duration_ms"].(float64); ok {
		return int64(v)
	}
	return 0
}

func mapSteps(steps []StepMetadata) map[string]StepMetadata {
	m := make(map[string]StepMetadata, len(steps))
	for _, s := range steps {
		m[s.StepName] = s
	}
	return m
}

func mergeKeys(a, b map[string]StepMetadata) []string {
	seen := make(map[string]bool)
	var keys []string
	for k := range a {
		if !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	for k := range b {
		if !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	return keys
}
