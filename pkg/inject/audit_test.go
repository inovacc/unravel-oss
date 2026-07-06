/*
Copyright (c) 2026 Security Research
*/
package inject

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func setLogPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "inject-log.jsonl")
	t.Setenv("UNRAVEL_INJECT_LOG", p)
	return p
}

func TestAppend_RoundTrip(t *testing.T) {
	p := setLogPath(t)

	recs := []AuditRecord{
		{TargetPath: "/a", Method: "cdp", ScriptName: "s1", ScriptSHA256: "h1"},
		{TargetPath: "/b", Method: "asar", ScriptName: "s2", ScriptSHA256: "h2", Persistent: true, OutputPath: "/b.out"},
		{TargetPath: "/c", Method: "cdp", ScriptName: "s3", ScriptSHA256: "h3", Persistent: true},
	}
	for _, r := range recs {
		if err := Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	fh, err := os.Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = fh.Close() }()

	var got []AuditRecord
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var r AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("unmarshal %q: %v", sc.Text(), err)
		}
		got = append(got, r)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 records, got %d", len(got))
	}
	for i, r := range got {
		if r.SchemaVersion != 1 {
			t.Errorf("rec %d schema_version = %d, want 1", i, r.SchemaVersion)
		}
		if r.Timestamp.IsZero() {
			t.Errorf("rec %d timestamp zero", i)
		}
		if r.HostUser == "" {
			t.Errorf("rec %d host_user empty", i)
		}
		if r.TargetPath != recs[i].TargetPath {
			t.Errorf("rec %d target = %q, want %q", i, r.TargetPath, recs[i].TargetPath)
		}
		if r.ScriptSHA256 != recs[i].ScriptSHA256 {
			t.Errorf("rec %d hash = %q, want %q", i, r.ScriptSHA256, recs[i].ScriptSHA256)
		}
	}
}

func TestAppend_AppendOnly(t *testing.T) {
	p := setLogPath(t)
	if err := Append(AuditRecord{TargetPath: "/x", Method: "cdp", ScriptSHA256: "h"}); err != nil {
		t.Fatalf("append1: %v", err)
	}
	if err := Append(AuditRecord{TargetPath: "/y", Method: "cdp", ScriptSHA256: "h"}); err != nil {
		t.Fatalf("append2: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() == 0 {
		t.Fatal("file empty after appends")
	}
	// re-append; size must grow strictly.
	prev := st.Size()
	if err := Append(AuditRecord{TargetPath: "/z", Method: "cdp", ScriptSHA256: "h"}); err != nil {
		t.Fatalf("append3: %v", err)
	}
	st2, _ := os.Stat(p)
	if st2.Size() <= prev {
		t.Fatalf("file did not grow: %d -> %d", prev, st2.Size())
	}
}

func TestAppend_Concurrent(t *testing.T) {
	p := setLogPath(t)

	const G = 10
	const N = 10

	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < N; i++ {
				err := Append(AuditRecord{
					Timestamp:    time.Now().UTC(),
					TargetPath:   "/concurrent",
					Method:       "cdp",
					ScriptName:   "concurrent",
					ScriptSHA256: "h",
				})
				if err != nil {
					t.Errorf("g=%d i=%d: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	fh, err := os.Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = fh.Close() }()

	count := 0
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var r AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("malformed line %d: %v\n%s", count, err, sc.Text())
		}
		if r.SchemaVersion != 1 {
			t.Fatalf("line %d schema=%d", count, r.SchemaVersion)
		}
		count++
	}
	if count != G*N {
		t.Fatalf("expected %d lines, got %d", G*N, count)
	}
}

func TestLogPath_EnvOverride(t *testing.T) {
	t.Setenv("UNRAVEL_INJECT_LOG", "/tmp/custom.jsonl")
	if got := LogPath(); got != "/tmp/custom.jsonl" {
		t.Fatalf("LogPath = %q, want /tmp/custom.jsonl", got)
	}
}
