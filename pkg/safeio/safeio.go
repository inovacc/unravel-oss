// Package safeio provides bounded I/O helpers for processing UNTRUSTED,
// potentially malicious archives and binaries.
//
// Unravel dissects attacker-controlled inputs. A tiny archive can declare a
// huge length field, decompress to gigabytes, or claim millions of entries —
// any of which can OOM or DoS the analyst host. The helpers here cap reads,
// copies, allocations, and aggregate extraction so a hostile sample is rejected
// (or individual poisoned entries skipped) rather than exhausting resources.
//
// All caps are package-level vars (not hardcoded literals) so callers and tests
// can tune or inject them. The defaults are deliberately GENEROUS so legitimate
// large real-world apps (multi-GB game APKs, ~500 MiB Electron apps,
// multi-hundred-MiB MSIs) are never rejected; only egregious bombs trip them.
package safeio

import (
	"errors"
	"fmt"
	"io"
)

// Tunable default caps. These are vars, not consts, so callers/tests can
// override them. Defaults are intentionally generous; see package doc.
var (
	// DefaultMaxTotalBytes bounds the aggregate UNCOMPRESSED bytes an archive
	// may expand to across all entries. 8 GiB comfortably exceeds large real
	// packages (kernels, LibreOffice, big game APKs) while still stopping a
	// multi-terabyte bomb.
	DefaultMaxTotalBytes int64 = 8 << 30 // 8 GiB

	// DefaultMaxEntries bounds the number of entries an archive may declare,
	// defeating "millions of tiny headers" inode/syscall exhaustion. 1M is far
	// above any legitimate package's file count.
	DefaultMaxEntries int64 = 1_000_000

	// DefaultMaxEntryBytes bounds a single decompressed entry/stream. 2 GiB
	// suits even unusually large individual payloads.
	DefaultMaxEntryBytes int64 = 2 << 30 // 2 GiB

	// DefaultRatioFloorBytes is the absolute decompressed-size floor below
	// which the compression-ratio guard never trips. Ordinary small, highly
	// compressible files (e.g. a 1 KiB run of zeros) must always pass.
	DefaultRatioFloorBytes int64 = 64 << 20 // 64 MiB

	// DefaultMaxRatio is the decompressed:compressed ratio that, combined with
	// exceeding the floor, marks an EGREGIOUS bomb. DEFLATE's theoretical max
	// is ~1032:1; 1000:1 only trips on near-pathological streams, and only once
	// absolute size is already above the floor.
	DefaultMaxRatio int64 = 1000
)

// ErrLimitExceeded is returned when a bounded read/copy exceeds its cap.
var ErrLimitExceeded = errors.New("safeio: size limit exceeded")

// ErrBudgetExceeded is returned by Budget when an aggregate cap is exceeded.
var ErrBudgetExceeded = errors.New("safeio: extraction budget exceeded")

// ErrInvalidSize is returned by MakeBounded/CheckSize for a negative size or a
// size exceeding the allowed maximum.
var ErrInvalidSize = errors.New("safeio: invalid or oversized allocation size")

// ReadAllLimit reads from r until EOF or until max+1 bytes have been read.
// It returns ErrLimitExceeded if the stream is longer than max, so a hostile
// stream cannot be fully materialized in memory. A max <= 0 is treated as
// "no data allowed" and any non-empty stream errors.
func ReadAllLimit(r io.Reader, max int64) ([]byte, error) {
	if max < 0 {
		max = 0
	}
	// Read one extra byte so we can distinguish "exactly max" from "over max".
	lr := io.LimitReader(r, max+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return data, err
	}
	if int64(len(data)) > max {
		return data[:max], fmt.Errorf("%w: stream exceeds %d bytes", ErrLimitExceeded, max)
	}
	return data, nil
}

// CopyLimit copies from src to dst, stopping with ErrLimitExceeded if more than
// max bytes would be copied. It returns the number of bytes written. This is the
// per-stream decompression-bomb guard for a single decompressed entry/stream.
func CopyLimit(dst io.Writer, src io.Reader, max int64) (int64, error) {
	if max < 0 {
		max = 0
	}
	// Copy at most max+1 so we can detect overflow without unbounded buffering.
	n, err := io.Copy(dst, io.LimitReader(src, max+1))
	if err != nil {
		return n, err
	}
	if n > max {
		return max, fmt.Errorf("%w: copy exceeds %d bytes", ErrLimitExceeded, max)
	}
	return n, nil
}

// CheckSize validates an attacker-controlled length before it is used to size an
// allocation. It rejects negative sizes and sizes exceeding max. Pass max <= 0
// to use DefaultMaxEntryBytes.
func CheckSize(n int64, max int64) error {
	if max <= 0 {
		max = DefaultMaxEntryBytes
	}
	if n < 0 {
		return fmt.Errorf("%w: negative size %d", ErrInvalidSize, n)
	}
	if n > max {
		return fmt.Errorf("%w: size %d exceeds max %d", ErrInvalidSize, n, max)
	}
	return nil
}

// MakeBounded validates n against max (via CheckSize) and, if valid, allocates
// and returns a []byte of length n. It is the safe replacement for
// make([]byte, attackerLen) at sites where attackerLen comes from untrusted
// input. Pass max <= 0 to use DefaultMaxEntryBytes.
func MakeBounded(n int64, max int64) ([]byte, error) {
	if err := CheckSize(n, max); err != nil {
		return nil, err
	}
	return make([]byte, n), nil
}

// Budget tracks aggregate uncompressed bytes and entry count across a whole
// archive extraction, plus a per-entry size cap and an egregious-bomb
// compression-ratio guard. The zero value is not ready for use; call
// NewBudget. A Budget is not safe for concurrent use.
type Budget struct {
	// MaxTotalBytes caps cumulative uncompressed bytes across all entries.
	MaxTotalBytes int64
	// MaxEntries caps the number of entries (Add calls).
	MaxEntries int64
	// MaxEntryBytes caps a single entry's uncompressed size.
	MaxEntryBytes int64
	// RatioFloorBytes is the decompressed-size floor below which the ratio
	// guard never trips.
	RatioFloorBytes int64
	// MaxRatio is the decompressed:compressed ratio that trips the bomb guard
	// once RatioFloorBytes is exceeded. <= 0 disables the ratio guard.
	MaxRatio int64

	total   int64
	entries int64
}

// NewBudget returns a Budget initialized with the package default caps.
func NewBudget() *Budget {
	return &Budget{
		MaxTotalBytes:   DefaultMaxTotalBytes,
		MaxEntries:      DefaultMaxEntries,
		MaxEntryBytes:   DefaultMaxEntryBytes,
		RatioFloorBytes: DefaultRatioFloorBytes,
		MaxRatio:        DefaultMaxRatio,
	}
}

// Add accounts one entry of uncompressedSize bytes against the budget. It must
// be called once per extracted entry, before (or as) its bytes are written. It
// returns an error wrapping ErrBudgetExceeded if the per-entry cap, the entry
// count, or the aggregate total would be exceeded. A negative size is rejected
// via ErrInvalidSize.
func (b *Budget) Add(uncompressedSize int64) error {
	if uncompressedSize < 0 {
		return fmt.Errorf("%w: negative entry size %d", ErrInvalidSize, uncompressedSize)
	}
	if b.MaxEntryBytes > 0 && uncompressedSize > b.MaxEntryBytes {
		return fmt.Errorf("%w: entry size %d exceeds per-entry cap %d", ErrBudgetExceeded, uncompressedSize, b.MaxEntryBytes)
	}
	b.entries++
	if b.MaxEntries > 0 && b.entries > b.MaxEntries {
		return fmt.Errorf("%w: entry count exceeds %d", ErrBudgetExceeded, b.MaxEntries)
	}
	// Overflow-safe total check.
	if b.MaxTotalBytes > 0 && (b.total > b.MaxTotalBytes-uncompressedSize) {
		return fmt.Errorf("%w: aggregate size exceeds %d bytes", ErrBudgetExceeded, b.MaxTotalBytes)
	}
	b.total += uncompressedSize
	return nil
}

// CheckRatio reports an egregious-bomb error only when BOTH the decompressed
// size is above RatioFloorBytes AND the decompressed:compressed ratio exceeds
// MaxRatio. Ordinary well-compressed data (small absolute size, or modest
// ratio) always passes. compressedSize <= 0 means the compressed size is
// unknown and the check is skipped.
func (b *Budget) CheckRatio(decompressed, compressed int64) error {
	if b.MaxRatio <= 0 || compressed <= 0 {
		return nil
	}
	if decompressed <= b.RatioFloorBytes {
		return nil
	}
	if decompressed/compressed > b.MaxRatio {
		return fmt.Errorf("%w: compression ratio %d:1 above %d:1 at %d bytes", ErrBudgetExceeded, decompressed/compressed, b.MaxRatio, decompressed)
	}
	return nil
}

// Total returns the cumulative uncompressed bytes accounted so far.
func (b *Budget) Total() int64 { return b.total }

// Entries returns the number of entries accounted so far.
func (b *Budget) Entries() int64 { return b.entries }
