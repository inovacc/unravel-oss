// Package android implements Android app behavior capture via ADB shell commands.
// It monitors intents, broadcasts, logcat output, shared preferences, and network
// traffic for a specified package, emitting events in the unified capture format.
package android

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// Config holds parameters for an Android capture session.
type Config struct {
	// Package is the Android package name to monitor (e.g., "com.example.app").
	Package string

	// Serial is the ADB device serial (optional, empty for default device).
	Serial string

	// PollInterval is how often to poll for broadcast/intent/prefs changes.
	PollInterval time.Duration

	// EnableTcpdump enables network capture via tcpdump (requires root).
	EnableTcpdump bool
}

// Session manages a live Android capture via ADB.
type Session struct {
	config Config
	events chan capture.Event
	seq    int64
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// CheckADB verifies that ADB is available on the system PATH.
func CheckADB() error {
	_, err := exec.LookPath("adb")
	if err != nil {
		return fmt.Errorf("adb not found in PATH: install Android SDK platform-tools")
	}
	return nil
}

// ListDevices returns the list of connected ADB device serials.
func ListDevices(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "adb", "devices").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("adb devices: %w", err)
	}
	var devices []string
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of") || strings.HasPrefix(line, "*") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == "device" {
			devices = append(devices, parts[0])
		}
	}
	return devices, nil
}

// Start begins an Android capture session. The caller must call Stop to finalize.
func Start(ctx context.Context, cfg Config, events chan capture.Event, seqFn func() int) (*Session, error) {
	if err := CheckADB(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	s := &Session{
		config: cfg,
		events: events,
		cancel: cancel,
	}

	// Use the provided seqFn or create a local one
	nextSeq := seqFn
	if nextSeq == nil {
		nextSeq = func() int { return int(atomic.AddInt64(&s.seq, 1)) }
	}

	// Start logcat monitoring (filtered by package)
	s.wg.Go(func() {
		s.monitorLogcat(ctx, nextSeq)
	})

	// Start periodic broadcast/intent polling
	s.wg.Go(func() {
		s.pollBroadcasts(ctx, nextSeq)
	})

	// Start periodic shared preferences snapshots
	s.wg.Go(func() {
		s.pollSharedPrefs(ctx, nextSeq)
	})

	// Start tcpdump if enabled
	if cfg.EnableTcpdump {
		s.wg.Go(func() {
			s.monitorNetwork(ctx, nextSeq)
		})
	}

	return s, nil
}

// Stop ends the Android capture session.
func (s *Session) Stop() {
	s.cancel()
	s.wg.Wait()
}

// adbArgs builds command arguments, inserting -s <serial> if configured.
func (s *Session) adbArgs(args ...string) []string {
	if s.config.Serial != "" {
		return append([]string{"-s", s.config.Serial}, args...)
	}
	return args
}

// runADB executes an ADB command and returns its combined output.
func (s *Session) runADB(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "adb", s.adbArgs(args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("adb %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// monitorLogcat streams logcat output filtered by the target package.
func (s *Session) monitorLogcat(ctx context.Context, nextSeq func() int) {
	// Clear logcat buffer first
	_, _ = s.runADB(ctx, "logcat", "-c")

	args := s.adbArgs("logcat", "-v", "brief")
	if s.config.Package != "" {
		// Filter by package: use --pid if we can discover it, otherwise grep in code
		args = s.adbArgs("logcat", "-v", "brief", "-s", s.config.Package+":V", "*:S")
	}

	cmd := exec.CommandContext(ctx, "adb", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		priority, tag, message := parseLogcatLine(line)
		if priority == "" {
			continue
		}

		// Filter by package name in the tag or message if no logcat filter worked
		if s.config.Package != "" && !strings.Contains(line, s.config.Package) &&
			!strings.Contains(tag, s.config.Package) {
			// Allow through if it's a general system message about our package
			continue
		}

		data := capture.AndroidLogcatData{
			Priority: priority,
			Tag:      tag,
			Message:  message,
		}

		evt, err := capture.NewEvent(nextSeq(), time.Now(), capture.EventAndroidLogcat, capture.SourceADB, data)
		if err != nil {
			continue
		}
		select {
		case s.events <- evt:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return
		}
	}

	_ = cmd.Wait()
}

// pollBroadcasts periodically captures broadcast and intent activity.
func (s *Session) pollBroadcasts(ctx context.Context, nextSeq func() int) {
	interval := s.config.PollInterval
	if interval == 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastBroadcasts string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Capture broadcast history
		out, err := s.runADB(ctx, "shell", "dumpsys", "activity", "broadcasts")
		if err != nil {
			continue
		}

		if out == lastBroadcasts {
			continue
		}
		lastBroadcasts = out

		broadcasts := parseBroadcastDump(out, s.config.Package)
		for _, b := range broadcasts {
			evt, err := capture.NewEvent(nextSeq(), time.Now(), capture.EventAndroidBroadcast, capture.SourceADB, b)
			if err != nil {
				continue
			}
			select {
			case s.events <- evt:
			case <-ctx.Done():
				return
			}
		}

		// Capture recent intents from activity history
		intentOut, err := s.runADB(ctx, "shell", "dumpsys", "activity", "activities")
		if err != nil {
			continue
		}

		intents := parseIntentDump(intentOut, s.config.Package)
		for _, intent := range intents {
			evt, err := capture.NewEvent(nextSeq(), time.Now(), capture.EventAndroidIntent, capture.SourceADB, intent)
			if err != nil {
				continue
			}
			select {
			case s.events <- evt:
			case <-ctx.Done():
				return
			}
		}
	}
}

// pollSharedPrefs periodically snapshots shared preferences files.
func (s *Session) pollSharedPrefs(ctx context.Context, nextSeq func() int) {
	if s.config.Package == "" {
		return
	}

	interval := s.config.PollInterval
	if interval == 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	lastPrefs := make(map[string]string) // file -> content hash

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// List shared_prefs files
		listOut, err := s.runADB(ctx, "shell", "run-as", s.config.Package, "ls", "shared_prefs/")
		if err != nil {
			// App might not have run-as permission; try su fallback
			listOut, err = s.runADB(ctx, "shell", "su", "-c",
				fmt.Sprintf("ls /data/data/%s/shared_prefs/", s.config.Package))
			if err != nil {
				continue
			}
		}

		for fileName := range strings.SplitSeq(strings.TrimSpace(listOut), "\n") {
			fileName = strings.TrimSpace(fileName)
			if fileName == "" || !strings.HasSuffix(fileName, ".xml") {
				continue
			}

			content, err := s.runADB(ctx, "shell", "run-as", s.config.Package,
				"cat", "shared_prefs/"+fileName)
			if err != nil {
				content, err = s.runADB(ctx, "shell", "su", "-c",
					fmt.Sprintf("cat /data/data/%s/shared_prefs/%s", s.config.Package, fileName))
				if err != nil {
					continue
				}
			}

			if old, ok := lastPrefs[fileName]; ok && old == content {
				continue
			}
			lastPrefs[fileName] = content

			entries := parseSharedPrefsXML(content)
			data := capture.AndroidPrefsData{
				File:    fileName,
				Entries: entries,
			}

			evt, err := capture.NewEvent(nextSeq(), time.Now(), capture.EventAndroidPrefs, capture.SourceADB, data)
			if err != nil {
				continue
			}
			select {
			case s.events <- evt:
			case <-ctx.Done():
				return
			}
		}
	}
}

// monitorNetwork captures network traffic via tcpdump on the device.
func (s *Session) monitorNetwork(ctx context.Context, nextSeq func() int) {
	args := s.adbArgs("shell", "su", "-c", "tcpdump -l -n -q")
	cmd := exec.CommandContext(ctx, "adb", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return
		default:
		}

		line := scanner.Text()
		data := parseTcpdumpLine(line)
		if data == nil {
			continue
		}

		evt, err := capture.NewEvent(nextSeq(), time.Now(), capture.EventAndroidNetwork, capture.SourceADB, data)
		if err != nil {
			continue
		}
		select {
		case s.events <- evt:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return
		}
	}

	_ = cmd.Wait()
}

// parseLogcatLine parses a brief-format logcat line: "D/Tag(  PID): message"
func parseLogcatLine(line string) (priority, tag, message string) {
	if len(line) < 3 || line[1] != '/' {
		return "", "", ""
	}

	priority = string(line[0])
	rest := line[2:]

	before, _, ok := strings.Cut(rest, "(")
	if !ok {
		return "", "", ""
	}
	tag = strings.TrimSpace(before)

	_, after, ok := strings.Cut(rest, "): ")
	if !ok {
		return priority, tag, ""
	}
	message = strings.TrimSpace(after)
	return priority, tag, message
}

// parseBroadcastDump extracts broadcast actions from dumpsys output, filtered by package.
func parseBroadcastDump(dump string, pkg string) []capture.AndroidBroadcastData {
	var results []capture.AndroidBroadcastData
	seen := make(map[string]bool)

	for line := range strings.SplitSeq(dump, "\n") {
		line = strings.TrimSpace(line)

		if !strings.Contains(line, "act=") {
			continue
		}
		if pkg != "" && !strings.Contains(line, pkg) {
			continue
		}

		action := extractField(line, "act=")
		if action == "" || seen[action] {
			continue
		}
		seen[action] = true

		component := extractField(line, "cmp=")
		results = append(results, capture.AndroidBroadcastData{
			Action:    action,
			Component: component,
		})
	}
	return results
}

// parseIntentDump extracts intent actions from activity dumpsys output.
func parseIntentDump(dump string, pkg string) []capture.AndroidIntentData {
	var results []capture.AndroidIntentData
	seen := make(map[string]bool)

	for line := range strings.SplitSeq(dump, "\n") {
		line = strings.TrimSpace(line)

		if !strings.Contains(line, "act=") && !strings.Contains(line, "Intent") {
			continue
		}
		if pkg != "" && !strings.Contains(line, pkg) {
			continue
		}

		action := extractField(line, "act=")
		if action == "" || seen[action] {
			continue
		}
		seen[action] = true

		component := extractField(line, "cmp=")
		data := extractField(line, "dat=")
		flags := extractField(line, "flg=")

		results = append(results, capture.AndroidIntentData{
			Action:    action,
			Component: component,
			Data:      data,
			Flags:     flags,
		})
	}
	return results
}

// extractField pulls a value from a dumpsys line like "act=android.intent.action.MAIN"
func extractField(line, prefix string) string {
	_, after, ok := strings.Cut(line, prefix)
	if !ok {
		return ""
	}
	rest := after
	end := strings.IndexAny(rest, " }")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// parseSharedPrefsXML does a simple key-value extraction from Android shared prefs XML.
func parseSharedPrefsXML(content string) map[string]string {
	entries := make(map[string]string)

	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)

		// Handle <string name="key">value</string>
		if strings.HasPrefix(line, "<string ") {
			name := extractXMLAttr(line, "name")
			if name == "" {
				continue
			}
			start := strings.Index(line, ">")
			end := strings.Index(line, "</string>")
			if start >= 0 && end > start {
				entries[name] = line[start+1 : end]
			}
		}

		// Handle <boolean name="key" value="true" />
		if strings.HasPrefix(line, "<boolean ") || strings.HasPrefix(line, "<int ") ||
			strings.HasPrefix(line, "<long ") || strings.HasPrefix(line, "<float ") {
			name := extractXMLAttr(line, "name")
			value := extractXMLAttr(line, "value")
			if name != "" {
				entries[name] = value
			}
		}

		// Handle <set name="key">
		if strings.HasPrefix(line, "<set ") {
			name := extractXMLAttr(line, "name")
			if name != "" {
				entries[name] = "(set)"
			}
		}
	}

	return entries
}

// extractXMLAttr extracts a named attribute value from an XML-like line.
func extractXMLAttr(line, attr string) string {
	search := attr + `="`
	_, after, ok := strings.Cut(line, search)
	if !ok {
		return ""
	}
	rest := after
	before, _, ok := strings.Cut(rest, `"`)
	if !ok {
		return ""
	}
	return before
}

// parseTcpdumpLine parses a tcpdump -q output line.
// Example: "12:34:56.789 IP 192.168.1.1.443 > 10.0.0.1.12345: tcp 128"
func parseTcpdumpLine(line string) *capture.AndroidNetworkData {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}

	// Look for "IP" protocol marker
	protoIdx := -1
	for i, f := range fields {
		if f == "IP" || f == "IP6" {
			protoIdx = i
			break
		}
	}
	if protoIdx < 0 || protoIdx+3 >= len(fields) {
		return nil
	}

	proto := fields[protoIdx]
	src := strings.TrimSuffix(fields[protoIdx+1], ":")
	dst := strings.TrimSuffix(fields[protoIdx+3], ":")

	// The > is at protoIdx+2
	info := ""
	if protoIdx+4 < len(fields) {
		info = strings.Join(fields[protoIdx+4:], " ")
	}

	return &capture.AndroidNetworkData{
		Protocol: proto,
		Source:   src,
		Dest:     dst,
		Info:     info,
	}
}
