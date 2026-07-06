/*
Copyright (c) 2026 Security Research
*/

package insights

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CmdStats is per-command aggregate computed by Rollup.
type CmdStats struct {
	Cmd         string  `json:"cmd"`
	Invocations int     `json:"invocations"`
	Failures    int     `json:"failures"`
	Retries     int     `json:"retries"`
	FailureRate float64 `json:"failure_rate"`
	RetryRate   float64 `json:"retry_rate"`
}

// Rollup is the structured output of one rollup pass.
type Rollup struct {
	WindowDays  int                 `json:"window_days"`
	GeneratedAt time.Time           `json:"generated_at"`
	TotalEvents int                 `json:"total_events"`
	GoalsSeen   int                 `json:"goals_seen"`
	GoalsClosed int                 `json:"goals_closed"`
	GoalsOpen   int                 `json:"goals_open"`
	MedianJumps float64             `json:"median_jumps"`
	P95Jumps    float64             `json:"p95_jumps"`
	MaxJumps    int                 `json:"max_jumps"`
	PerCommand  []CmdStats          `json:"per_command"`
	FailureTop  []string            `json:"failure_top"`
	GoalsByID   map[string]GoalRoll `json:"goals_by_id"`
}

// GoalRoll is the per-goal aggregate.
type GoalRoll struct {
	GoalID    string    `json:"goal_id"`
	Jumps     int       `json:"jumps"`
	Friction  int       `json:"friction"`
	Outcome   Outcome   `json:"outcome,omitempty"`
	StartedAt time.Time `json:"started_at"`
	ClosedAt  time.Time `json:"closed_at"`
}

// DoRollup reads the last windowDays of events/*.jsonl, computes
// aggregate stats, updates per-goal envelopes with jump counts, and
// returns the rollup. Writes per-month digest if writeDigest is true.
func DoRollup(windowDays int, writeDigest bool) (Rollup, error) {
	if IsDisabled() {
		return Rollup{}, nil
	}
	eventsDir, err := SubPath(SubdirEvents)
	if err != nil {
		return Rollup{}, err
	}
	goalsDir, err := SubPath(SubdirGoals)
	if err != nil {
		return Rollup{}, err
	}

	roll := Rollup{
		WindowDays:  windowDays,
		GeneratedAt: time.Now().UTC(),
		GoalsByID:   map[string]GoalRoll{},
	}
	perCmd := map[string]*CmdStats{}
	failureCounts := map[string]int{}

	cutoff := time.Now().UTC().Add(-time.Duration(windowDays) * 24 * time.Hour)

	entries, _ := os.ReadDir(eventsDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(eventsDir, e.Name())
		if err := scanFile(path, cutoff, &roll, perCmd, failureCounts); err != nil {
			return roll, err
		}
	}

	// Finalise per-command stats
	for _, cs := range perCmd {
		if cs.Invocations > 0 {
			cs.FailureRate = float64(cs.Failures) / float64(cs.Invocations)
			cs.RetryRate = float64(cs.Retries) / float64(cs.Invocations)
		}
		roll.PerCommand = append(roll.PerCommand, *cs)
	}
	sort.Slice(roll.PerCommand, func(i, j int) bool {
		return roll.PerCommand[i].Invocations > roll.PerCommand[j].Invocations
	})

	// Top failure messages
	type fc struct {
		Msg string
		N   int
	}
	var fcs []fc
	for k, v := range failureCounts {
		fcs = append(fcs, fc{Msg: k, N: v})
	}
	sort.Slice(fcs, func(i, j int) bool { return fcs[i].N > fcs[j].N })
	for i := 0; i < len(fcs) && i < 10; i++ {
		roll.FailureTop = append(roll.FailureTop, fmt.Sprintf("[%d] %s", fcs[i].N, fcs[i].Msg))
	}

	// Update per-goal envelopes + jump histogram
	var jumpVals []int
	for goalID, gr := range roll.GoalsByID {
		goalPath := filepath.Join(goalsDir, goalID+".json")
		if g, err := readGoal(goalPath); err == nil {
			g.Jumps = gr.Jumps
			g.Friction = gr.Friction
			_ = writeGoal(goalPath, g)
			gr.Outcome = g.Outcome
			gr.StartedAt = g.StartedAt
			if g.CompletedAt != nil {
				gr.ClosedAt = *g.CompletedAt
				roll.GoalsClosed++
			} else {
				roll.GoalsOpen++
			}
			roll.GoalsByID[goalID] = gr
		}
		jumpVals = append(jumpVals, gr.Jumps)
	}
	roll.GoalsSeen = len(roll.GoalsByID)
	if len(jumpVals) > 0 {
		sort.Ints(jumpVals)
		roll.MedianJumps = float64(jumpVals[len(jumpVals)/2])
		roll.P95Jumps = float64(jumpVals[int(float64(len(jumpVals))*0.95)])
		if jumpVals[len(jumpVals)-1] > roll.MaxJumps {
			roll.MaxJumps = jumpVals[len(jumpVals)-1]
		}
	}

	if writeDigest {
		if err := writeMarkdownDigest(roll); err != nil {
			return roll, err
		}
	}
	return roll, nil
}

func scanFile(path string, cutoff time.Time, roll *Rollup, perCmd map[string]*CmdStats, failureCounts map[string]int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		if ev.TS.Before(cutoff) {
			continue
		}
		roll.TotalEvents++
		if ev.GoalID != "" {
			gr := roll.GoalsByID[ev.GoalID]
			gr.GoalID = ev.GoalID
			if ev.Type == EventCommandInvoked || ev.Type == EventRetry {
				gr.Jumps++
			}
			roll.GoalsByID[ev.GoalID] = gr
		}
		switch ev.Type {
		case EventCommandInvoked:
			cmd, _ := ev.Payload["cmd"].(string)
			if cmd == "" {
				continue
			}
			if _, ok := perCmd[cmd]; !ok {
				perCmd[cmd] = &CmdStats{Cmd: cmd}
			}
			perCmd[cmd].Invocations++
		case EventFailure:
			cmd, _ := ev.Payload["cmd"].(string)
			if cmd != "" {
				if _, ok := perCmd[cmd]; !ok {
					perCmd[cmd] = &CmdStats{Cmd: cmd}
				}
				perCmd[cmd].Failures++
			}
			if msg, ok := ev.Payload["error"].(string); ok && msg != "" {
				failureCounts[truncate(msg, 80)]++
			}
		case EventRetry:
			cmd, _ := ev.Payload["cmd"].(string)
			if cmd != "" {
				if _, ok := perCmd[cmd]; !ok {
					perCmd[cmd] = &CmdStats{Cmd: cmd}
				}
				perCmd[cmd].Retries++
			}
		}
	}
	return sc.Err()
}

func writeMarkdownDigest(r Rollup) error {
	dir, err := SubPath(SubdirRollups)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, r.GeneratedAt.Format("2006-01")+".md")

	var b strings.Builder
	fmt.Fprintf(&b, "# Insights rollup — %s\n\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "<!-- created:%s -->\n\n", r.GeneratedAt.Format("2006-01-02"))
	fmt.Fprintf(&b, "## Summary (last %d days)\n\n", r.WindowDays)
	fmt.Fprintf(&b, "- total_events: %d\n", r.TotalEvents)
	fmt.Fprintf(&b, "- goals_seen: %d (closed=%d, open=%d)\n", r.GoalsSeen, r.GoalsClosed, r.GoalsOpen)
	fmt.Fprintf(&b, "- jumps: median=%.1f p95=%.1f max=%d\n\n", r.MedianJumps, r.P95Jumps, r.MaxJumps)

	if len(r.PerCommand) > 0 {
		b.WriteString("## Per command\n\n")
		b.WriteString("| cmd | inv | fail | retry | fail_rate | retry_rate |\n")
		b.WriteString("|-----|-----|------|-------|-----------|------------|\n")
		for _, c := range r.PerCommand {
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %.1f%% | %.1f%% |\n", c.Cmd, c.Invocations, c.Failures, c.Retries, c.FailureRate*100, c.RetryRate*100)
		}
		b.WriteString("\n")
	}
	if len(r.FailureTop) > 0 {
		b.WriteString("## Top failure messages\n\n")
		for _, m := range r.FailureTop {
			fmt.Fprintf(&b, "- %s\n", m)
		}
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
