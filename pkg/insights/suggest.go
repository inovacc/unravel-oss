/*
Copyright (c) 2026 Security Research
*/

package insights

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Confidence string

const (
	ConfLow  Confidence = "LOW"
	ConfMed  Confidence = "MED"
	ConfHigh Confidence = "HIGH"
)

// Suggestion is one heuristic-generated improvement candidate.
type Suggestion struct {
	ID             string     `json:"id"`
	Rule           string     `json:"rule"`
	What           string     `json:"what"`
	Why            string     `json:"why"`
	ProposedAction string     `json:"proposed_action"`
	Confidence     Confidence `json:"confidence"`
	GeneratedAt    time.Time  `json:"generated_at"`
}

// Suggest applies all heuristic rules to the supplied rollup and
// emits candidates. Writes one markdown file per date if writeDigest
// is true.
func Suggest(r Rollup, writeDigest bool) ([]Suggestion, error) {
	if IsDisabled() {
		return nil, nil
	}
	var out []Suggestion
	out = append(out, ruleHighRetryRate(r)...)
	out = append(out, ruleHighFailureRate(r)...)
	out = append(out, ruleHighFrictionGoals(r)...)
	out = append(out, ruleDeadCommand(r)...)
	out = append(out, ruleFrequentFailureMessage(r)...)
	out = append(out, ruleNoGoalsClosed(r)...)

	now := time.Now().UTC()
	for i := range out {
		out[i].GeneratedAt = now
		out[i].ID = fmt.Sprintf("%s-%03d", now.Format("20060102"), i+1)
	}
	sort.Slice(out, func(i, j int) bool {
		return confidenceRank(out[i].Confidence) > confidenceRank(out[j].Confidence)
	})
	if writeDigest && len(out) > 0 {
		if err := writeSuggestionsMarkdown(out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfHigh:
		return 3
	case ConfMed:
		return 2
	default:
		return 1
	}
}

func ruleHighRetryRate(r Rollup) []Suggestion {
	var out []Suggestion
	for _, c := range r.PerCommand {
		if c.Invocations < 5 || c.RetryRate < 0.20 {
			continue
		}
		conf := ConfMed
		if c.RetryRate > 0.40 {
			conf = ConfHigh
		}
		out = append(out, Suggestion{
			Rule:           "high_retry_rate",
			What:           fmt.Sprintf("command %q has retry_rate=%.0f%% over %d invocations", c.Cmd, c.RetryRate*100, c.Invocations),
			Why:            "retries indicate users hit a recoverable failure mode that the command's default behaviour does not handle on first attempt",
			ProposedAction: "tighten arg validation, widen body_cap default, or expand error-recovery path",
			Confidence:     conf,
		})
	}
	return out
}

func ruleHighFailureRate(r Rollup) []Suggestion {
	var out []Suggestion
	for _, c := range r.PerCommand {
		if c.Invocations < 5 || c.FailureRate < 0.10 {
			continue
		}
		conf := ConfMed
		if c.FailureRate > 0.30 {
			conf = ConfHigh
		}
		out = append(out, Suggestion{
			Rule:           "high_failure_rate",
			What:           fmt.Sprintf("command %q has failure_rate=%.0f%% over %d invocations", c.Cmd, c.FailureRate*100, c.Invocations),
			Why:            "high outright failure rate suggests broken contract or missing prerequisite",
			ProposedAction: "audit error path, add explicit prerequisite check, surface a clearer error message",
			Confidence:     conf,
		})
	}
	return out
}

func ruleHighFrictionGoals(r Rollup) []Suggestion {
	for goalID, g := range r.GoalsByID {
		if g.Friction <= 5 {
			continue
		}
		return []Suggestion{{
			Rule:           "high_friction_goal",
			What:           fmt.Sprintf("goal %q required %d jumps (friction=%d)", goalID, g.Jumps, g.Friction),
			Why:            "high jump count means the user needed many context switches; a single higher-level command could compress the workflow",
			ProposedAction: "propose a new slash command or orchestrator agent that fuses the observed jump sequence",
			Confidence:     ConfMed,
		}}
	}
	return nil
}

func ruleDeadCommand(r Rollup) []Suggestion {
	if r.WindowDays < 14 {
		return nil
	}
	// Surface any command not registered in this rollup but present in
	// PerCommand history would require external state; for now suggest
	// based on zero-invocation rows ONLY if explicitly listed (caller
	// can pre-seed). Placeholder honest no-op.
	return nil
}

func ruleFrequentFailureMessage(r Rollup) []Suggestion {
	var out []Suggestion
	for _, line := range r.FailureTop {
		if strings.HasPrefix(line, "[") {
			closer := strings.Index(line, "]")
			if closer < 0 {
				continue
			}
			countStr := line[1:closer]
			n := 0
			fmt.Sscanf(countStr, "%d", &n)
			if n >= 5 {
				out = append(out, Suggestion{
					Rule:           "frequent_failure_message",
					What:           fmt.Sprintf("failure message seen %d times: %s", n, strings.TrimSpace(line[closer+1:])),
					Why:            "repeated identical failure suggests a single root cause worth fixing",
					ProposedAction: "diagnose root cause; add validation or auto-recovery; consider surfacing as a doctor check",
					Confidence:     ConfMed,
				})
			}
		}
	}
	return out
}

func ruleNoGoalsClosed(r Rollup) []Suggestion {
	if r.GoalsSeen >= 3 && r.GoalsClosed == 0 {
		return []Suggestion{{
			Rule:           "no_goals_closed",
			What:           fmt.Sprintf("%d goals opened, 0 closed in the last %d days", r.GoalsSeen, r.WindowDays),
			Why:            "users open goals but never mark them complete — either the close path is undiscovered or workflows abandon mid-flight",
			ProposedAction: "auto-close goals on success-marker events; add doctor reminder; ensure /unravel:resume hints completion",
			Confidence:     ConfLow,
		}}
	}
	return nil
}

func writeSuggestionsMarkdown(suggestions []Suggestion) error {
	dir, err := SubPath(SubdirSuggestions)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	path := filepath.Join(dir, now.Format("2006-01-02")+".md")

	var b strings.Builder
	fmt.Fprintf(&b, "# Insights suggestions — %s\n\n", now.Format(time.RFC3339))
	fmt.Fprintf(&b, "<!-- created:%s -->\n\n", now.Format("2006-01-02"))
	fmt.Fprintf(&b, "%d candidate(s) ranked by confidence.\n\n", len(suggestions))
	for _, s := range suggestions {
		fmt.Fprintf(&b, "## [%s] %s — %s\n\n", s.Confidence, s.ID, s.Rule)
		fmt.Fprintf(&b, "**What:** %s\n\n", s.What)
		fmt.Fprintf(&b, "**Why:** %s\n\n", s.Why)
		fmt.Fprintf(&b, "**Proposed:** %s\n\n", s.ProposedAction)
		b.WriteString("---\n\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
