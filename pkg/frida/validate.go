/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Validation severity badges (text-only, no emojis per D-23).
const (
	SeverityBlock = "BLOCK"
	SeverityFlag  = "FLAG"
	SeverityPass  = "PASS"
)

// frida-event-v1 line prefix produced by enriched Frida scripts on stdout.
const eventLinePrefix = "[FRIDA-EVENT] "

// maxJSONBytes is the strict 1 MiB cap (T-09-04) on input documents:
// criteria.json and the capture/RunResult JSON file.
const maxJSONBytes = 1 << 20

// errPathTraversal is returned when a user-supplied path contains "..".
var errPathTraversal = errors.New("frida: path traversal rejected")

// Criterion, HookCriteria, CriteriaFile, EventRecord are defined in types.go (09-01 canonical).
// validate.go reads them; the local duplicates were removed during Wave-1 reconciliation.

// Finding is one criterion's result.
type Finding struct {
	HookID   string `json:"hook_id"`
	Severity string `json:"severity"`
	Operator string `json:"operator"`
	Expected any    `json:"expected,omitempty"`
	Observed any    `json:"observed,omitempty"`
	Message  string `json:"message,omitempty"`
}

// ValidationSummary is the run aggregate.
type ValidationSummary struct {
	Total int `json:"total"`
	Block int `json:"block"`
	Flag  int `json:"flag"`
	Pass  int `json:"pass"`
}

// ValidationReport is the post-capture validator output.
type ValidationReport struct {
	CriteriaPath string            `json:"criteria_path"`
	CapturePath  string            `json:"capture_path"`
	PackageName  string            `json:"package_name,omitempty"`
	Findings     []Finding         `json:"findings"`
	Summary      ValidationSummary `json:"summary"`
}

// captureWrapper auto-detects RunResult vs SessionResult.
type captureWrapper struct {
	// SessionResult fields
	PackageName string      `json:"package_name,omitempty"`
	Scripts     []RunResult `json:"scripts,omitempty"`
	// RunResult fields (also captured if top-level)
	ScriptName string   `json:"script_name,omitempty"`
	Output     []string `json:"output,omitempty"`
}

// Validate runs the post-capture validator. It loads `criteriaPath` and
// `capturePath`, applies each criterion against parsed [FRIDA-EVENT] records,
// and returns a severity-tagged ValidationReport.
func Validate(criteriaPath, capturePath string) (*ValidationReport, error) {
	criteria, err := loadCriteria(criteriaPath)
	if err != nil {
		return nil, fmt.Errorf("load criteria: %w", err)
	}
	events, packageName, err := loadCapture(capturePath)
	if err != nil {
		return nil, fmt.Errorf("load capture: %w", err)
	}

	report := &ValidationReport{
		CriteriaPath: criteriaPath,
		CapturePath:  capturePath,
		PackageName:  packageName,
		Findings:     []Finding{},
	}

	// Stable iteration order: types.go declares Hooks as []HookCriteria
	// (slice). Sort by hook ID for deterministic reports.
	hookOrder := make([]int, 0, len(criteria.Hooks))
	for i := range criteria.Hooks {
		hookOrder = append(hookOrder, i)
	}
	sort.SliceStable(hookOrder, func(a, b int) bool {
		return criteria.Hooks[hookOrder[a]].ID < criteria.Hooks[hookOrder[b]].ID
	})

	for _, idx := range hookOrder {
		hc := criteria.Hooks[idx]
		hookID := hc.ID
		for _, crit := range hc.Criteria {
			f := evaluateCriterion(hookID, crit, events)
			report.Findings = append(report.Findings, f)
			report.Summary.Total++
			switch f.Severity {
			case SeverityBlock:
				report.Summary.Block++
			case SeverityFlag:
				report.Summary.Flag++
			case SeverityPass:
				report.Summary.Pass++
			}
		}
	}

	return report, nil
}

// sanitizePath enforces T-09-02: reject ".." segments + Clean + Abs.
func sanitizePath(p string) (string, error) {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return "", errPathTraversal
		}
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("resolve abs: %w", err)
	}
	return abs, nil
}

// readCappedJSON reads at most maxJSONBytes from path and strict-decodes into v.
// T-09-04: rejects unknown fields and oversize input.
func readCappedJSON(path string, v any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decoder panic: %v", r)
		}
	}()
	abs, perr := sanitizePath(path)
	if perr != nil {
		return perr
	}
	f, oerr := os.Open(abs)
	if oerr != nil {
		return fmt.Errorf("open: %w", oerr)
	}
	defer func() { _ = f.Close() }()

	limited := io.LimitReader(f, maxJSONBytes+1)
	data, rerr := io.ReadAll(limited)
	if rerr != nil {
		return fmt.Errorf("read: %w", rerr)
	}
	if len(data) > maxJSONBytes {
		return fmt.Errorf("input exceeds %d bytes", maxJSONBytes)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(v); derr != nil {
		return fmt.Errorf("decode: %w", derr)
	}
	return nil
}

func loadCriteria(path string) (*CriteriaFile, error) {
	abs, perr := sanitizePath(path)
	if perr != nil {
		return nil, perr
	}
	f, oerr := os.Open(abs)
	if oerr != nil {
		return nil, fmt.Errorf("open: %w", oerr)
	}
	defer func() { _ = f.Close() }()
	limited := io.LimitReader(f, maxJSONBytes+1)
	data, rerr := io.ReadAll(limited)
	if rerr != nil {
		return nil, fmt.Errorf("read: %w", rerr)
	}
	if len(data) > maxJSONBytes {
		return nil, fmt.Errorf("criteria exceeds %d bytes", maxJSONBytes)
	}
	// Strict decode into the canonical CriteriaFile shape (types.go).
	// Min/Max are *float64 — nil already encodes "not set", so no separate
	// HasMin/HasMax peek is needed.
	var typed CriteriaFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&typed); derr != nil {
		return nil, fmt.Errorf("decode criteria: %w", derr)
	}
	return &typed, nil
}

func loadCapture(path string) (events []EventRecord, packageName string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("capture decoder panic: %v", r)
		}
	}()
	abs, perr := sanitizePath(path)
	if perr != nil {
		return nil, "", perr
	}
	f, oerr := os.Open(abs)
	if oerr != nil {
		return nil, "", fmt.Errorf("open: %w", oerr)
	}
	defer func() { _ = f.Close() }()
	limited := io.LimitReader(f, maxJSONBytes+1)
	data, rerr := io.ReadAll(limited)
	if rerr != nil {
		return nil, "", fmt.Errorf("read: %w", rerr)
	}
	if len(data) > maxJSONBytes {
		return nil, "", fmt.Errorf("capture exceeds %d bytes", maxJSONBytes)
	}
	var w captureWrapper
	// Permissive decode — capture format is RunResult/SessionResult which has
	// many fields (duration, started, etc.) we do not need; strict-mode would
	// reject those. Strictness is enforced on criteria.json (T-09-04 surface).
	if jerr := json.Unmarshal(data, &w); jerr != nil {
		return nil, "", fmt.Errorf("decode capture: %w", jerr)
	}
	packageName = w.PackageName
	var lines []string
	if len(w.Scripts) > 0 {
		for _, s := range w.Scripts {
			lines = append(lines, s.Output...)
		}
	} else {
		lines = w.Output
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, eventLinePrefix) {
			continue
		}
		payload := strings.TrimPrefix(line, eventLinePrefix)
		var ev EventRecord
		if jerr := json.Unmarshal([]byte(payload), &ev); jerr != nil {
			// Skip malformed event lines, do not panic (T-09-05).
			continue
		}
		events = append(events, ev)
	}
	return events, packageName, nil
}

// evaluateCriterion dispatches to the operator implementation and tags severity.
func evaluateCriterion(hookID string, c Criterion, events []EventRecord) Finding {
	f := Finding{HookID: hookID, Operator: c.Op}

	switch c.Op {
	case "frequency-count":
		return evalFrequencyCount(hookID, c, events)
	case "equals":
		return evalEquals(hookID, c, events)
	case "present":
		return evalPresent(hookID, c, events)
	case "in-range":
		return evalInRange(hookID, c, events)
	case "regex":
		return evalRegex(hookID, c, events)
	default:
		f.Severity = SeverityFlag
		f.Message = fmt.Sprintf("unknown operator %q", c.Op)
		return f
	}
}

// matchPhase returns true if the event matches the criterion phase filter.
// Default phase is "enter" when criterion specifies none.
func matchPhase(c Criterion, ev EventRecord) bool {
	want := c.Phase
	if want == "" {
		want = "enter"
	}
	if ev.Phase == "" {
		return want == "enter"
	}
	return ev.Phase == want
}

// resolveTarget extracts a target value from an event.
func resolveTarget(target string, ev EventRecord) (any, bool) {
	switch {
	case target == "ret" || target == "return":
		return ev.Ret, ev.Ret != nil
	case target == "frame":
		return ev.Frame, ev.Frame != ""
	case strings.HasPrefix(target, "args["):
		// args[N]
		end := strings.Index(target, "]")
		if end < 0 {
			return nil, false
		}
		idx, err := strconv.Atoi(target[len("args["):end])
		if err != nil || idx < 0 || idx >= len(ev.Args) {
			return nil, false
		}
		return ev.Args[idx], true
	}
	return nil, false
}

func eventsForHook(hookID string, events []EventRecord) []EventRecord {
	var out []EventRecord
	for _, ev := range events {
		if ev.HookID == hookID {
			out = append(out, ev)
		}
	}
	return out
}

func evalFrequencyCount(hookID string, c Criterion, events []EventRecord) Finding {
	// types.go: Target carries the hook-id for frequency-count
	// (D-09: {op: "frequency-count", target: "<hook-id>"}).
	target := hookID
	if c.Target != "" {
		target = c.Target
	}
	count := 0
	for _, ev := range events {
		if ev.HookID == target {
			count++
		}
	}
	f := Finding{
		HookID:   hookID,
		Operator: "frequency-count",
		Expected: fmt.Sprintf("count in [%v,%v]", c.Min, c.Max),
		Observed: count,
	}
	min := 0
	max := 1<<31 - 1
	if c.HasMin() {
		min = int(*c.Min)
	}
	if c.HasMax() {
		max = int(*c.Max)
	}
	if count >= min && count <= max {
		f.Severity = SeverityPass
		f.Message = "frequency in range"
		return f
	}
	// BLOCK if expected to fire (min > 0) but never fired.
	if min > 0 && count == 0 {
		f.Severity = applyHint(c, SeverityBlock)
		f.Message = "expected hook never fired"
		return f
	}
	f.Severity = applyHint(c, SeverityFlag)
	f.Message = "frequency outside expected range"
	return f
}

func evalEquals(hookID string, c Criterion, events []EventRecord) Finding {
	f := Finding{
		HookID:   hookID,
		Operator: "equals",
		Expected: c.Value,
	}
	matched := false
	hookEvents := eventsForHook(hookID, events)
	if len(hookEvents) == 0 {
		f.Severity = applyHint(c, SeverityBlock)
		f.Message = "expected hook never fired"
		return f
	}
	var observed any
	for _, ev := range hookEvents {
		if !matchPhase(c, ev) {
			continue
		}
		v, ok := resolveTarget(c.Target, ev)
		if !ok {
			continue
		}
		observed = v
		if stringifyValue(v) == c.Value {
			matched = true
			break
		}
	}
	f.Observed = observed
	if matched {
		f.Severity = SeverityPass
		f.Message = "value matched"
		return f
	}
	f.Severity = applyHint(c, SeverityFlag)
	f.Message = "value mismatch"
	return f
}

func evalPresent(hookID string, c Criterion, events []EventRecord) Finding {
	f := Finding{HookID: hookID, Operator: "present", Expected: fmt.Sprintf("%s present", c.Target)}
	hookEvents := eventsForHook(hookID, events)
	if len(hookEvents) == 0 {
		f.Severity = applyHint(c, SeverityBlock)
		f.Message = "expected hook never fired"
		return f
	}
	for _, ev := range hookEvents {
		if !matchPhase(c, ev) {
			continue
		}
		v, ok := resolveTarget(c.Target, ev)
		if !ok {
			continue
		}
		if s := stringifyValue(v); s != "" && s != "null" {
			f.Severity = SeverityPass
			f.Observed = v
			f.Message = "target present"
			return f
		}
	}
	f.Severity = applyHint(c, SeverityFlag)
	f.Message = "target absent"
	return f
}

func evalInRange(hookID string, c Criterion, events []EventRecord) Finding {
	f := Finding{
		HookID:   hookID,
		Operator: "in-range",
		Expected: fmt.Sprintf("[%v,%v]", c.Min, c.Max),
	}
	hookEvents := eventsForHook(hookID, events)
	if len(hookEvents) == 0 {
		f.Severity = applyHint(c, SeverityBlock)
		f.Message = "expected hook never fired"
		return f
	}
	for _, ev := range hookEvents {
		if !matchPhase(c, ev) {
			continue
		}
		v, ok := resolveTarget(c.Target, ev)
		if !ok {
			continue
		}
		num, ok := coerceNumber(v)
		if !ok {
			f.Observed = v
			f.Severity = applyHint(c, SeverityFlag)
			f.Message = "target not numeric"
			return f
		}
		f.Observed = num
		lo := -math.MaxFloat64
		hi := math.MaxFloat64
		if c.HasMin() {
			lo = *c.Min
		}
		if c.HasMax() {
			hi = *c.Max
		}
		if num >= lo && num <= hi {
			f.Severity = SeverityPass
			f.Message = "value in range"
			return f
		}
	}
	f.Severity = applyHint(c, SeverityFlag)
	f.Message = "value out of range"
	return f
}

func evalRegex(hookID string, c Criterion, events []EventRecord) Finding {
	f := Finding{HookID: hookID, Operator: "regex", Expected: c.Pattern}
	// Use regexp.Compile (NOT MustCompile) so a bad pattern surfaces as a
	// FLAG instead of panicking (Pitfall 4 / D-25).
	re, err := regexp.Compile(c.Pattern)
	if err != nil {
		f.Severity = applyHint(c, SeverityFlag)
		f.Message = fmt.Sprintf("invalid regex: %v", err)
		return f
	}
	hookEvents := eventsForHook(hookID, events)
	if len(hookEvents) == 0 {
		f.Severity = applyHint(c, SeverityBlock)
		f.Message = "expected hook never fired"
		return f
	}
	for _, ev := range hookEvents {
		if !matchPhase(c, ev) {
			continue
		}
		v, ok := resolveTarget(c.Target, ev)
		if !ok {
			continue
		}
		s := stringifyValue(v)
		if re.MatchString(s) {
			f.Severity = SeverityPass
			f.Observed = s
			f.Message = "regex matched"
			return f
		}
		f.Observed = s
	}
	f.Severity = applyHint(c, SeverityFlag)
	f.Message = "regex did not match"
	return f
}

// applyHint promotes/demotes severity if the criterion specifies a hint.
func applyHint(c Criterion, def string) string {
	switch strings.ToLower(c.Severity) {
	case "block":
		return SeverityBlock
	case "flag":
		return SeverityFlag
	case "pass":
		return SeverityPass
	}
	return def
}

func stringifyValue(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func coerceNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case string:
		n, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// sortStrings is a tiny in-place lex sort to avoid pulling in `sort` for one call.
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}
