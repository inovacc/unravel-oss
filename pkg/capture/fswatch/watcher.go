package fswatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"

	"github.com/fsnotify/fsnotify"
)

// Watcher monitors a directory tree and emits capture events for file changes.
type Watcher struct {
	RootDir string
	Events  chan capture.Event
	seq     func() int
}

// New creates a watcher for the given directory.
func New(rootDir string, events chan capture.Event, seqFn func() int) *Watcher {
	return &Watcher{
		RootDir: rootDir,
		Events:  events,
		seq:     seqFn,
	}
}

// Watch starts monitoring and blocks until the context is cancelled.
func (w *Watcher) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	err = filepath.WalkDir(w.RootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk dir: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			w.handleEvent(event)
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			_ = err
		}
	}
}

func (w *Watcher) handleEvent(fsEvent fsnotify.Event) {
	var op string
	switch {
	case fsEvent.Has(fsnotify.Create):
		op = "create"
	case fsEvent.Has(fsnotify.Write):
		op = "modify"
	case fsEvent.Has(fsnotify.Remove):
		op = "delete"
	default:
		return
	}

	cat := Category(fsEvent.Name)
	if cat == "unknown" {
		return
	}

	relPath, err := filepath.Rel(w.RootDir, fsEvent.Name)
	if err != nil {
		relPath = fsEvent.Name
	}

	var sizeDelta int64
	if op != "delete" {
		if info, err := os.Stat(fsEvent.Name); err == nil {
			sizeDelta = info.Size()
		}
	}

	evtType := capture.EventStorageWrite
	if op == "delete" {
		evtType = capture.EventStorageDelete
	}

	evt, err := capture.NewEvent(w.seq(), time.Now(), evtType, capture.SourceFSWatch,
		capture.StorageEventData{
			Path:      relPath,
			Operation: op,
			Category:  cat,
			SizeDelta: sizeDelta,
		})
	if err != nil {
		return
	}

	select {
	case w.Events <- evt:
	default:
	}
}
