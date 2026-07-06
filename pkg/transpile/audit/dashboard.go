package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DashboardEntry aggregates metrics from a single pipeline run.
type DashboardEntry struct {
	ID           string        `json:"id"`
	ScenarioName string        `json:"scenario_name"`
	APICalls     int           `json:"api_calls"`
	InputTokens  int           `json:"input_tokens"`
	OutputTokens int           `json:"output_tokens"`
	TotalTokens  int           `json:"total_tokens"`
	Truncated    int           `json:"truncated"`
	Duration     time.Duration `json:"duration_ms"`
}

// Dashboard holds aggregated metrics across audit runs.
type Dashboard struct {
	Entries []DashboardEntry `json:"entries"`
}

// LoadDashboard scans auditDir for */pipeline.json files and aggregates metrics.
func LoadDashboard(auditDir string) (*Dashboard, error) {
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		return nil, fmt.Errorf("read audit dir: %w", err)
	}

	var d Dashboard

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pipelinePath := filepath.Join(auditDir, entry.Name(), "pipeline.json")

		data, err := os.ReadFile(pipelinePath)
		if err != nil {
			continue // skip dirs without pipeline.json
		}

		var report PipelineReport
		if err := json.Unmarshal(data, &report); err != nil {
			continue
		}

		truncated := 0

		for _, call := range report.Tokens.Calls {
			if call.StopReason == "max_tokens" {
				truncated++
			}
		}

		d.Entries = append(d.Entries, DashboardEntry{
			ID:           report.ID,
			ScenarioName: report.ScenarioName,
			APICalls:     report.Tokens.APICalls,
			InputTokens:  report.Tokens.TotalInputTokens,
			OutputTokens: report.Tokens.TotalOutputTokens,
			TotalTokens:  report.Tokens.TotalTokens,
			Truncated:    truncated,
			Duration:     time.Duration(report.TotalDurationMS) * time.Millisecond,
		})
	}

	sort.Slice(d.Entries, func(i, j int) bool {
		return d.Entries[i].ID < d.Entries[j].ID
	})

	return &d, nil
}

// PrintTable writes a formatted table to w.
func (d *Dashboard) PrintTable(w io.Writer) {
	if len(d.Entries) == 0 {
		_, _ = fmt.Fprintln(w, "No audit runs found.")
		return
	}

	// Calculate column widths
	maxName := len("Scenario")

	for _, e := range d.Entries {
		name := e.ScenarioName
		if name == "" {
			name = e.ID[:8]
		}

		if len(name) > maxName {
			maxName = len(name)
		}
	}

	if maxName > 30 {
		maxName = 30
	}

	_, _ = fmt.Fprintln(w, "Token Usage Dashboard")
	_, _ = fmt.Fprintln(w, strings.Repeat("=", 80))

	headerFmt := fmt.Sprintf("%%-%ds | %%9s | %%9s | %%9s | %%9s | %%9s\n", maxName)
	rowFmt := fmt.Sprintf("%%-%ds | %%9s | %%9s | %%9s | %%9s | %%9d\n", maxName)
	sepFmt := fmt.Sprintf("%%-%ds-+-%%9s-+-%%9s-+-%%9s-+-%%9s-+-%%9s\n", maxName)

	_, _ = fmt.Fprintf(w, headerFmt, "Scenario", "API Calls", "Input", "Output", "Total", "Truncated")
	_, _ = fmt.Fprintf(w, sepFmt,
		strings.Repeat("-", maxName),
		strings.Repeat("-", 9),
		strings.Repeat("-", 9),
		strings.Repeat("-", 9),
		strings.Repeat("-", 9),
		strings.Repeat("-", 9),
	)

	var totalAPICalls, totalInput, totalOutput, totalTokens, totalTruncated int

	for _, e := range d.Entries {
		name := e.ScenarioName
		if name == "" {
			name = e.ID[:8]
		}

		if len(name) > maxName {
			name = name[:maxName]
		}

		_, _ = fmt.Fprintf(w, rowFmt,
			name,
			fmtInt(e.APICalls),
			fmtInt(e.InputTokens),
			fmtInt(e.OutputTokens),
			fmtInt(e.TotalTokens),
			e.Truncated,
		)

		totalAPICalls += e.APICalls
		totalInput += e.InputTokens
		totalOutput += e.OutputTokens
		totalTokens += e.TotalTokens
		totalTruncated += e.Truncated
	}

	_, _ = fmt.Fprintf(w, sepFmt,
		strings.Repeat("-", maxName),
		strings.Repeat("-", 9),
		strings.Repeat("-", 9),
		strings.Repeat("-", 9),
		strings.Repeat("-", 9),
		strings.Repeat("-", 9),
	)

	_, _ = fmt.Fprintf(w, rowFmt,
		"TOTAL",
		fmtInt(totalAPICalls),
		fmtInt(totalInput),
		fmtInt(totalOutput),
		fmtInt(totalTokens),
		totalTruncated,
	)

	// Cost estimate (claude-opus-4-6 pricing)
	inputCost := float64(totalInput) * 15.0 / 1_000_000
	outputCost := float64(totalOutput) * 75.0 / 1_000_000

	_, _ = fmt.Fprintf(w, "\nEstimated cost (claude-opus-4-6):\n")
	_, _ = fmt.Fprintf(w, "  Input:  $%.2f (%s tokens x $15.00/MTok)\n", inputCost, fmtInt(totalInput))
	_, _ = fmt.Fprintf(w, "  Output: $%.2f (%s tokens x $75.00/MTok)\n", outputCost, fmtInt(totalOutput))
	_, _ = fmt.Fprintf(w, "  Total:  $%.2f\n", inputCost+outputCost)
}

// PrintJSON writes the dashboard as JSON to w.
func (d *Dashboard) PrintJSON(w io.Writer) error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dashboard: %w", err)
	}

	_, err = w.Write(data)

	return err
}

// fmtInt formats an integer with comma separators.
func fmtInt(n int) string {
	if n < 0 {
		return "-" + fmtInt(-n)
	}

	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}

	var result []byte

	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}

		result = append(result, byte(c))
	}

	return string(result)
}
