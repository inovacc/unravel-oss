package decompiler

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// defaultNativeTimeout bounds a single native decompile. Some obfuscated
// classes drive the op03 structuring pass into a non-terminating state; without
// a ceiling a whole-JAR batch stalls forever on one bad class.
const defaultNativeTimeout = 20 * time.Second

// errNativeTimeout is returned when the native decompiler exceeds NativeTimeout.
var errNativeTimeout = errors.New("native decompiler timed out")

// SourceJudge picks the more faithful decompilation when the heuristic score
// is not decisive enough on its own.
type SourceJudge interface {
	Judge(ctx context.Context, prompt string) (string, error)
}

type judgeFunc func(ctx context.Context, prompt string) (string, error)

func (f judgeFunc) Judge(ctx context.Context, prompt string) (string, error) {
	return f(ctx, prompt)
}

// codexJudge shells out to the local codex CLI in non-interactive mode.
type codexJudge struct {
	Path    string
	Timeout time.Duration
}

func (j codexJudge) Judge(ctx context.Context, prompt string) (string, error) {
	if j.Path == "" {
		return "", fmt.Errorf("empty judge path")
	}

	if j.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, j.Timeout)
		defer cancel()
	}

	// Capture only the agent's final message so banner/token-usage noise never
	// reaches the NATIVE/FALLBACK decision parser.
	lastMsg, err := os.CreateTemp("", "unravel-codex-judge-*.txt")
	if err != nil {
		return "", fmt.Errorf("codex judge temp file: %w", err)
	}
	lastMsgPath := lastMsg.Name()
	_ = lastMsg.Close()
	defer func() { _ = os.Remove(lastMsgPath) }()

	cmd := exec.CommandContext(ctx, j.Path, "exec",
		"--skip-git-repo-check",
		"--ephemeral",
		"--color", "never",
		"--sandbox", "read-only",
		"-o", lastMsgPath,
		prompt,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codex failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	final, readErr := os.ReadFile(lastMsgPath)
	if readErr != nil || strings.TrimSpace(string(final)) == "" {
		final = out // fall back to combined output if the last-message file is empty
	}

	return normalizeJudgeDecision(string(final)), nil
}

// normalizeJudgeDecision reduces a judge's free-form reply to the exact NATIVE
// or FALLBACK token the selector expects, tolerating extra prose.
func normalizeJudgeDecision(raw string) string {
	up := strings.ToUpper(raw)
	native := strings.LastIndex(up, "NATIVE")
	fallback := strings.LastIndex(up, "FALLBACK")
	switch {
	case fallback > native:
		return "FALLBACK"
	case native > fallback:
		return "NATIVE"
	default:
		return strings.TrimSpace(raw)
	}
}

// HybridDecompiler tries the native Go decompiler first, falls back to
// external Java decompilers (CFR, Fernflower, Procyon) when available.
type HybridDecompiler struct {
	Native        *NativeDecompiler
	JavaCmd       string // path to java binary (empty = no fallback)
	CFRPath       string // path to cfr.jar
	Judge         SourceJudge
	JudgeTimeout  time.Duration
	FallbackOnly  bool          // skip native, always use external
	NativeTimeout time.Duration // per-class ceiling for the native decompiler (0 = unbounded)
}

// NewHybridDecompiler creates a hybrid decompiler that auto-discovers java and CFR.
func NewHybridDecompiler() *HybridDecompiler {
	h := &HybridDecompiler{
		Native:        &NativeDecompiler{},
		NativeTimeout: defaultNativeTimeout,
	}
	h.discoverTools()
	return h
}

// nativeDecompile runs the native decompiler under NativeTimeout. On timeout the
// running goroutine is abandoned (it cannot be preempted mid-loop) and the caller
// falls back to CFR when available, so one pathological class never stalls a batch.
func (h *HybridDecompiler) nativeDecompile(data []byte) (string, error) {
	if h.NativeTimeout <= 0 {
		return h.Native.DecompileBytes(data)
	}

	type nativeResult struct {
		source string
		err    error
	}
	done := make(chan nativeResult, 1)
	go func() {
		source, err := h.Native.DecompileBytes(data)
		done <- nativeResult{source, err}
	}()

	select {
	case r := <-done:
		return r.source, r.err
	case <-time.After(h.NativeTimeout):
		return "", errNativeTimeout
	}
}

// HasFallback returns true if an external Java decompiler is available.
func (h *HybridDecompiler) HasFallback() bool {
	return h.JavaCmd != "" && h.CFRPath != ""
}

// Decompile writes decompiled .java to outputDir.
func (h *HybridDecompiler) Decompile(classPath string, outputDir string) error {
	data, err := os.ReadFile(classPath)
	if err != nil {
		return fmt.Errorf("read class file: %w", err)
	}

	source, err := h.DecompileBytes(data)
	if err != nil {
		return fmt.Errorf("decompile %s: %w", filepath.Base(classPath), err)
	}

	baseName := strings.TrimSuffix(filepath.Base(classPath), ".class") + ".java"
	outPath := filepath.Join(outputDir, baseName)

	return os.WriteFile(outPath, []byte(source), 0o644)
}

// DecompileBytes decompiles raw .class bytes to Java source.
// Tries native first, falls back to CFR if the result has errors.
func (h *HybridDecompiler) DecompileBytes(data []byte) (string, error) {
	if h.FallbackOnly && h.HasFallback() {
		return h.decompileWithCFR(data)
	}

	// Try native decompiler (bounded so a hanging class can't stall a batch)
	source, nativeErr := h.nativeDecompile(data)

	if !h.HasFallback() {
		if nativeErr != nil {
			return "", nativeErr
		}
		return source, nil
	}

	cfrSource, cfrErr := h.decompileWithCFR(data)
	if nativeErr != nil && cfrErr != nil {
		return "", nativeErr
	}

	if nativeErr != nil {
		return cfrSource, nil
	}

	if cfrErr != nil {
		return source, nil
	}

	preferred, judgeErr := h.selectPreferredSource(source, cfrSource)
	if judgeErr == nil && preferred != "" {
		return preferred, nil
	}

	// Fall back to the native result when the heuristic/judge path cannot decide.
	return source, nil
}

// DecompileJAR decompiles all classes in a JAR to the output directory.
// Uses CFR's native JAR handling when available (much faster than per-class).
func (h *HybridDecompiler) DecompileJAR(jarPath string, outputDir string) error {
	if h.HasFallback() {
		return h.decompileJARWithCFR(jarPath, outputDir)
	}
	// Fall back to extract + per-class decompilation
	return fmt.Errorf("JAR decompilation requires CFR fallback or archive extraction")
}

// decompileWithCFR runs CFR on a single .class file.
func (h *HybridDecompiler) decompileWithCFR(data []byte) (string, error) {
	// Write class data to temp file
	tmpFile, err := os.CreateTemp("", "unravel-class-*.class")
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("write temp: %w", err)
	}
	_ = tmpFile.Close()

	// Absolutize the temp class path so it can never be parsed as a flag by
	// CFR (argument injection, CWE-88).
	tmpPath := tmpFile.Name()
	if abs, absErr := filepath.Abs(tmpPath); absErr == nil {
		tmpPath = abs
	}

	// Run CFR
	cmd := exec.Command(h.JavaCmd, "-jar", h.CFRPath, tmpPath)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cfr failed: %w", err)
	}

	return string(out), nil
}

// decompileJARWithCFR runs CFR on an entire JAR at once.
func (h *HybridDecompiler) decompileJARWithCFR(jarPath string, outputDir string) error {
	_ = os.MkdirAll(outputDir, 0o755)

	// Absolutize the (untrusted) JAR path so it can never be parsed as a flag
	// by CFR (argument injection, CWE-88).
	if abs, absErr := filepath.Abs(jarPath); absErr == nil {
		jarPath = abs
	}

	cmd := exec.Command(h.JavaCmd, "-jar", h.CFRPath, jarPath, "--outputdir", outputDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cfr failed: %s: %w", string(out), err)
	}

	return nil
}

// hasDecompilationErrors checks if decompiled source contains error markers.
func hasDecompilationErrors(source string) bool {
	markers := []string{
		"/* decompilation error:",
		"/* error:",
		"// ERROR:",
	}

	for _, m := range markers {
		if strings.Contains(source, m) {
			return true
		}
	}

	return false
}

// discoverTools finds java and decompiler JARs on the system.
func (h *HybridDecompiler) discoverTools() {
	// Find java binary
	for _, name := range []string{"java", "java.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			h.JavaCmd = p
			break
		}
	}

	// Also check common Windows locations
	if h.JavaCmd == "" {
		winPaths := []string{
			`C:\Program Files\Java`,
			`C:\Program Files\Eclipse Adoptium`,
			`C:\Program Files\Microsoft\jdk`,
		}

		for _, base := range winPaths {
			entries, err := os.ReadDir(base)
			if err != nil {
				continue
			}

			for _, e := range entries {
				if !e.IsDir() {
					continue
				}

				p := filepath.Join(base, e.Name(), "bin", "java.exe")
				if _, err := os.Stat(p); err == nil {
					h.JavaCmd = p
					break
				}
			}

			if h.JavaCmd != "" {
				break
			}
		}
	}

	// Find CFR jar
	searchPaths := []string{
		"tools/cfr.jar",
	}

	// Check XDG cache
	if cache, err := os.UserCacheDir(); err == nil {
		searchPaths = append(searchPaths,
			filepath.Join(cache, "unravel", "tools", "cfr.jar"),
		)
	}

	// Check home directory
	if home, err := os.UserHomeDir(); err == nil {
		searchPaths = append(searchPaths,
			filepath.Join(home, "unravel", "tools", "cfr.jar"),
		)
	}

	for _, p := range searchPaths {
		if abs, err := filepath.Abs(p); err == nil {
			if _, err := os.Stat(abs); err == nil {
				h.CFRPath = abs
				break
			}
		}
	}

	if p, err := exec.LookPath("codex"); err == nil {
		h.Judge = codexJudge{Path: p, Timeout: 45 * time.Second}
	}
}

type sourceMetrics struct {
	HasPackage   bool
	ClassCount   int
	MethodCount  int
	ImportCount  int
	SyntaxErrors int
	CompileReady bool
	Completeness float64
	Score        float64
}

func (m sourceMetrics) closeTo(other sourceMetrics) bool {
	scoreGap := math.Abs(m.Score - other.Score)
	if m.CompileReady != other.CompileReady {
		return false
	}
	if m.SyntaxErrors != other.SyntaxErrors {
		return false
	}
	return scoreGap <= 8
}

func scoreSource(source string) sourceMetrics {
	lines := strings.Split(source, "\n")
	m := sourceMetrics{}
	braceBalance := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") {
			m.ImportCount++
		}
		if strings.HasPrefix(trimmed, "package ") {
			m.HasPackage = true
		}
		if strings.Contains(trimmed, "class ") || strings.Contains(trimmed, "interface ") || strings.Contains(trimmed, "enum ") {
			m.ClassCount++
		}
		if (strings.Contains(trimmed, "(") && strings.Contains(trimmed, ")")) &&
			(strings.HasSuffix(trimmed, "{") || strings.HasSuffix(trimmed, ";")) &&
			!strings.HasPrefix(trimmed, "//") &&
			!strings.HasPrefix(trimmed, "if") &&
			!strings.HasPrefix(trimmed, "for") &&
			!strings.HasPrefix(trimmed, "while") {
			m.MethodCount++
		}
		braceBalance += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
	}

	m.SyntaxErrors = int(math.Abs(float64(braceBalance)))
	m.CompileReady = m.ClassCount > 0 && m.SyntaxErrors == 0

	score := 0.0
	if m.HasPackage {
		score += 0.1
	}
	if m.ClassCount > 0 {
		score += 0.3
	}
	if m.MethodCount > 0 {
		score += 0.3
	}
	if m.SyntaxErrors == 0 {
		score += 0.2
	}
	if m.ImportCount > 0 {
		score += 0.1
	}

	if m.CompileReady {
		score += 0.15
	}

	score -= float64(m.SyntaxErrors) * 0.05
	m.Completeness = score
	m.Score = score*100 + float64(m.MethodCount)*2 + float64(m.ImportCount) - float64(m.SyntaxErrors)*10

	return m
}

func (h *HybridDecompiler) selectPreferredSource(nativeSource, fallbackSource string) (string, error) {
	nativeMetrics := scoreSource(nativeSource)
	fallbackMetrics := scoreSource(fallbackSource)

	if nativeMetrics.CompileReady != fallbackMetrics.CompileReady {
		if nativeMetrics.CompileReady {
			return nativeSource, nil
		}

		return fallbackSource, nil
	}

	if nativeMetrics.SyntaxErrors != fallbackMetrics.SyntaxErrors {
		if nativeMetrics.SyntaxErrors < fallbackMetrics.SyntaxErrors {
			return nativeSource, nil
		}

		return fallbackSource, nil
	}

	if strings.TrimSpace(nativeSource) == strings.TrimSpace(fallbackSource) {
		return nativeSource, nil
	}

	if h.Judge == nil {
		if nativeMetrics.Score >= fallbackMetrics.Score {
			return nativeSource, nil
		}

		return fallbackSource, nil
	}

	decision, err := h.askJudge(nativeSource, fallbackSource, nativeMetrics, fallbackMetrics)
	if err != nil {
		if nativeMetrics.Score >= fallbackMetrics.Score {
			return nativeSource, err
		}

		return fallbackSource, err
	}

	switch strings.ToUpper(strings.TrimSpace(decision)) {
	case "NATIVE":
		return nativeSource, nil
	case "FALLBACK":
		return fallbackSource, nil
	}

	if nativeMetrics.Score >= fallbackMetrics.Score {
		return nativeSource, nil
	}

	return fallbackSource, nil
}

func (h *HybridDecompiler) askJudge(nativeSource, fallbackSource string, nativeMetrics, fallbackMetrics sourceMetrics) (string, error) {
	const excerptCap = 6000

	nativeExcerpt := nativeSource
	if len(nativeExcerpt) > excerptCap {
		nativeExcerpt = nativeExcerpt[:excerptCap]
	}

	fallbackExcerpt := fallbackSource
	if len(fallbackExcerpt) > excerptCap {
		fallbackExcerpt = fallbackExcerpt[:excerptCap]
	}

	prompt := fmt.Sprintf(
		"You are judging two Java decompilations of the same class.\n"+
			"Choose the source that is more faithful to the bytecode, preserves structure and types, and is more likely to compile.\n"+
			"Reply with exactly one word: NATIVE or FALLBACK.\n\n"+
			"Native metrics: package=%t class=%d methods=%d imports=%d syntax_errors=%d score=%.2f\n"+
			"Fallback metrics: package=%t class=%d methods=%d imports=%d syntax_errors=%d score=%.2f\n\n"+
			"<<<NATIVE\n%s\nNATIVE>>>\n\n"+
			"<<<FALLBACK\n%s\nFALLBACK>>>",
		nativeMetrics.HasPackage, nativeMetrics.ClassCount, nativeMetrics.MethodCount, nativeMetrics.ImportCount, nativeMetrics.SyntaxErrors, nativeMetrics.Score,
		fallbackMetrics.HasPackage, fallbackMetrics.ClassCount, fallbackMetrics.MethodCount, fallbackMetrics.ImportCount, fallbackMetrics.SyntaxErrors, fallbackMetrics.Score,
		nativeExcerpt, fallbackExcerpt,
	)

	ctx := context.Background()
	if h.JudgeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.JudgeTimeout)
		defer cancel()
	}

	return h.Judge.Judge(ctx, prompt)
}
