package fswatch

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

func TestCategory(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/data/leveldb/000003.log", "leveldb"},
		{"/data/leveldb/000003.ldb", "leveldb"},
		{"/data/Cookies", "cookies"},
		{"/data/Cookies-journal", "cookies"},
		{"/data/Local Storage/leveldb/LOG", "localstorage"},
		{"/data/Preferences", "preferences"},
		{"/data/Secure Preferences", "preferences"},
		{"/data/history.sqlite", "sqlite"},
		{"/data/cache.db", "sqlite"},
		{"/data/random.txt", "unknown"},
		// .ldb and .log files NOT in a leveldb dir => unknown
		{"/data/somedir/000003.ldb", "unknown"},
		{"/data/somedir/000003.log", "unknown"},
		// Local Storage takes priority over leveldb suffix
		{"/data/Local Storage/leveldb/000001.ldb", "localstorage"},
		// Deeply nested leveldb
		{"/app/data/leveldb/MANIFEST-000001", "leveldb"},
		// Edge cases
		{"/data/db/test.db", "sqlite"},
		{"/data/prefs/Preferences", "preferences"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := Category(tt.path); got != tt.want {
				t.Errorf("Category(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestWatcherIntegration(t *testing.T) {
	dir := t.TempDir()
	ldbDir := filepath.Join(dir, "leveldb")
	if err := os.MkdirAll(ldbDir, 0755); err != nil {
		t.Fatal(err)
	}

	events := make(chan capture.Event, 10)
	var counter int64
	seqFn := func() int { return int(atomic.AddInt64(&counter, 1)) }

	w := New(dir, events, seqFn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() { _ = w.Watch(ctx) }()

	time.Sleep(200 * time.Millisecond)

	testFile := filepath.Join(ldbDir, "000001.ldb")
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case evt := <-events:
		if evt.Type != capture.EventStorageWrite {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventStorageWrite)
		}
		var data capture.StorageEventData
		if err := capture.DecodeEventData(evt, &data); err != nil {
			t.Fatal(err)
		}
		if data.Category != "leveldb" {
			t.Errorf("category = %q, want %q", data.Category, "leveldb")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestWatcherDelete(t *testing.T) {
	dir := t.TempDir()
	ldbDir := filepath.Join(dir, "leveldb")
	if err := os.MkdirAll(ldbDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Pre-create file before watcher starts
	testFile := filepath.Join(ldbDir, "000002.ldb")
	if err := os.WriteFile(testFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	events := make(chan capture.Event, 10)
	var counter int64
	seqFn := func() int { return int(atomic.AddInt64(&counter, 1)) }

	w := New(dir, events, seqFn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() { _ = w.Watch(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Delete the file
	if err := os.Remove(testFile); err != nil {
		t.Fatal(err)
	}

	select {
	case evt := <-events:
		if evt.Type != capture.EventStorageDelete {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventStorageDelete)
		}
		var data capture.StorageEventData
		if err := capture.DecodeEventData(evt, &data); err != nil {
			t.Fatal(err)
		}
		if data.Operation != "delete" {
			t.Errorf("operation = %q, want %q", data.Operation, "delete")
		}
		if data.SizeDelta != 0 {
			t.Errorf("sizeDelta = %d, want 0 for delete", data.SizeDelta)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delete event")
	}
}

func TestWatcherIgnoresUnknownCategory(t *testing.T) {
	dir := t.TempDir()

	events := make(chan capture.Event, 10)
	var counter int64
	seqFn := func() int { return int(atomic.AddInt64(&counter, 1)) }

	w := New(dir, events, seqFn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() { _ = w.Watch(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Create a file with unknown category
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case evt := <-events:
		t.Errorf("expected no event for unknown category, got %+v", evt)
	case <-time.After(500 * time.Millisecond):
		// good, no event
	}
}

func TestWatcherCancelledContext(t *testing.T) {
	dir := t.TempDir()

	events := make(chan capture.Event, 10)
	var counter int64
	seqFn := func() int { return int(atomic.AddInt64(&counter, 1)) }

	w := New(dir, events, seqFn)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- w.Watch(ctx) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Watch() = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Watch to return")
	}
}

func TestWatcherModifyEvent(t *testing.T) {
	dir := t.TempDir()
	ldbDir := filepath.Join(dir, "leveldb")
	if err := os.MkdirAll(ldbDir, 0755); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(ldbDir, "000003.ldb")
	if err := os.WriteFile(testFile, []byte("initial"), 0644); err != nil {
		t.Fatal(err)
	}

	events := make(chan capture.Event, 10)
	var counter int64
	seqFn := func() int { return int(atomic.AddInt64(&counter, 1)) }

	w := New(dir, events, seqFn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() { _ = w.Watch(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Modify the file
	if err := os.WriteFile(testFile, []byte("modified content longer"), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case evt := <-events:
		if evt.Type != capture.EventStorageWrite {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventStorageWrite)
		}
		var data capture.StorageEventData
		if err := capture.DecodeEventData(evt, &data); err != nil {
			t.Fatal(err)
		}
		if data.Operation != "modify" && data.Operation != "create" {
			t.Errorf("operation = %q, want modify or create", data.Operation)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for modify event")
	}
}

func TestNewWatcher(t *testing.T) {
	events := make(chan capture.Event, 1)
	seqFn := func() int { return 1 }

	w := New("/some/dir", events, seqFn)

	if w.RootDir != "/some/dir" {
		t.Errorf("RootDir = %q, want %q", w.RootDir, "/some/dir")
	}
	if w.Events == nil {
		t.Error("Events channel should not be nil")
	}
}

func TestWatcherSQLiteEvent(t *testing.T) {
	dir := t.TempDir()

	events := make(chan capture.Event, 10)
	var counter int64
	seqFn := func() int { return int(atomic.AddInt64(&counter, 1)) }

	w := New(dir, events, seqFn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() { _ = w.Watch(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Create a .db file (sqlite category)
	if err := os.WriteFile(filepath.Join(dir, "cache.db"), []byte("sqlite data"), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case evt := <-events:
		var data capture.StorageEventData
		if err := capture.DecodeEventData(evt, &data); err != nil {
			t.Fatal(err)
		}
		if data.Category != "sqlite" {
			t.Errorf("category = %q, want %q", data.Category, "sqlite")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sqlite event")
	}
}

func TestWatcherCookiesEvent(t *testing.T) {
	dir := t.TempDir()

	events := make(chan capture.Event, 10)
	var counter int64
	seqFn := func() int { return int(atomic.AddInt64(&counter, 1)) }

	w := New(dir, events, seqFn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() { _ = w.Watch(ctx) }()
	time.Sleep(200 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, "Cookies"), []byte("cookie data"), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case evt := <-events:
		var data capture.StorageEventData
		if err := capture.DecodeEventData(evt, &data); err != nil {
			t.Fatal(err)
		}
		if data.Category != "cookies" {
			t.Errorf("category = %q, want %q", data.Category, "cookies")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cookies event")
	}
}
