package boundedzip

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Sentinel errors returned wrapped via fmt.Errorf("…: %w", err).
var (
	ErrPerFileExceeded = errors.New("boundedzip: per-file size cap exceeded")
	ErrTotalExceeded   = errors.New("boundedzip: total extracted size cap exceeded")
	ErrSymlinkRejected = errors.New("boundedzip: symlink entry rejected")
	ErrZipSlip         = errors.New("boundedzip: entry path escapes destination")
)

// Default caps — parity with pkg/winui/xaml/{xbf,pri} bounds.
const (
	MaxPerFile int64 = 16 << 20
	MaxTotal   int64 = 64 << 20
)

// Options tunes the caps. Zero fields fall back to the defaults.
type Options struct {
	MaxPerFile int64
	MaxTotal   int64
}

// DefaultOptions returns the package-default caps.
func DefaultOptions() Options { return Options{MaxPerFile: MaxPerFile, MaxTotal: MaxTotal} }

func (o Options) normalize() Options {
	if o.MaxPerFile <= 0 {
		o.MaxPerFile = MaxPerFile
	}
	if o.MaxTotal <= 0 {
		o.MaxTotal = MaxTotal
	}
	return o
}

// Reader wraps *zip.Reader and tracks cumulative bytes copied.
type Reader struct {
	*zip.Reader
	rc        io.Closer
	opts      Options
	totalRead int64
}

// OpenReader opens a zip file from disk. Call Close when done.
func OpenReader(path string, opts Options) (*Reader, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	return &Reader{Reader: &zr.Reader, rc: zr, opts: opts.normalize()}, nil
}

// NewReader wraps an existing io.ReaderAt.
func NewReader(r io.ReaderAt, size int64, opts Options) (*Reader, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	return &Reader{Reader: zr, rc: nil, opts: opts.normalize()}, nil
}

// Close releases the underlying file if opened via OpenReader.
func (br *Reader) Close() error {
	if br.rc != nil {
		return br.rc.Close()
	}
	return nil
}

// TotalRead reports the cumulative number of bytes successfully copied so far.
func (br *Reader) TotalRead() int64 { return br.totalRead }

// CheckEntry validates symlink + zip-slip + per-file cap for f.
// If destDir is "", the zip-slip check is skipped (stream-only consumers).
// On success returns the cleaned relative path under destDir.
func (br *Reader) CheckEntry(f *zip.File, destDir string) (string, error) {
	if (f.Mode() & os.ModeSymlink) != 0 {
		return "", fmt.Errorf("boundedzip: entry %q is a symlink: %w", f.Name, ErrSymlinkRejected)
	}
	if int64(f.UncompressedSize64) > br.opts.MaxPerFile {
		return "", fmt.Errorf("boundedzip: entry %q uncompressed size %d exceeds per-file cap %d: %w",
			f.Name, f.UncompressedSize64, br.opts.MaxPerFile, ErrPerFileExceeded)
	}
	clean := filepath.Clean(f.Name)
	if destDir == "" {
		// Still reject absolute paths and parent traversal for stream-only callers,
		// so a malicious entry name never reaches the caller.
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") ||
			strings.Contains(clean, string(filepath.Separator)+".."+string(filepath.Separator)) {
			return "", fmt.Errorf("boundedzip: entry %q has unsafe path: %w", f.Name, ErrZipSlip)
		}
		return clean, nil
	}
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("boundedzip: entry %q is absolute: %w", f.Name, ErrZipSlip)
	}
	cleanDest := filepath.Clean(destDir)
	abs := filepath.Join(cleanDest, clean)
	sep := string(filepath.Separator)
	if abs != cleanDest && !strings.HasPrefix(abs+sep, cleanDest+sep) {
		return "", fmt.Errorf("boundedzip: entry %q escapes %q: %w", f.Name, destDir, ErrZipSlip)
	}
	return clean, nil
}

// CopyEntry opens f, enforces per-file and cumulative caps, and copies into w.
// It returns the number of bytes written.
func (br *Reader) CopyEntry(f *zip.File, w io.Writer) (int64, error) {
	if (f.Mode() & os.ModeSymlink) != 0 {
		return 0, fmt.Errorf("boundedzip: entry %q is a symlink: %w", f.Name, ErrSymlinkRejected)
	}
	if int64(f.UncompressedSize64) > br.opts.MaxPerFile {
		return 0, fmt.Errorf("boundedzip: entry %q uncompressed size %d exceeds per-file cap %d: %w",
			f.Name, f.UncompressedSize64, br.opts.MaxPerFile, ErrPerFileExceeded)
	}
	remainingTotal := max(br.opts.MaxTotal-br.totalRead, 0)
	rc, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("boundedzip: open %q: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()

	// Defensive: cap reads at per-file even if the header lies. We allow up to
	// MaxPerFile+1 bytes so we can detect overflow.
	perFileLimit := min(br.opts.MaxPerFile+1, remainingTotal+1)
	limited := io.LimitReader(rc, perFileLimit)
	n, err := io.Copy(w, limited)
	br.totalRead += n
	if err != nil {
		return n, fmt.Errorf("boundedzip: copy %q: %w", f.Name, err)
	}
	if n > br.opts.MaxPerFile {
		return n, fmt.Errorf("boundedzip: entry %q copied %d bytes exceeds per-file cap %d: %w",
			f.Name, n, br.opts.MaxPerFile, ErrPerFileExceeded)
	}
	if br.totalRead > br.opts.MaxTotal {
		return n, fmt.Errorf("boundedzip: cumulative copy %d bytes exceeds total cap %d: %w",
			br.totalRead, br.opts.MaxTotal, ErrTotalExceeded)
	}
	return n, nil
}

// ReadEntry returns the entry contents in memory, enforcing the same caps.
func (br *Reader) ReadEntry(f *zip.File) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := br.CopyEntry(f, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
