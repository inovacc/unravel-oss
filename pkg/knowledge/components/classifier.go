/*
Copyright (c) 2026 Security Research
*/
package components

import (
	"context"
	"log/slog"
	"os"
	"slices"
)

// Bucket is one of the nine component buckets a SourceFile can be classified
// into. Bucket strings are stable identifiers used in on-disk paths and JSON.
type Bucket string

const (
	BucketAuth        Bucket = "auth"
	BucketAPI         Bucket = "api"
	BucketIPC         Bucket = "ipc"
	BucketTelemetry   Bucket = "telemetry"
	BucketUI          Bucket = "ui"
	BucketPersistence Bucket = "persistence"
	BucketCrypto      Bucket = "crypto"
	BucketUpdate      Bucket = "update"
	BucketUnknown     Bucket = "unknown"
)

// ValidBuckets returns the canonical set of bucket values. Override loaders
// use this to reject unknown YAML values.
func ValidBuckets() []Bucket {
	return []Bucket{
		BucketAuth, BucketAPI, BucketIPC, BucketTelemetry,
		BucketUI, BucketPersistence, BucketCrypto, BucketUpdate, BucketUnknown,
	}
}

// IsValidBucket reports whether b is one of the canonical bucket values.
func IsValidBucket(b Bucket) bool {
	return slices.Contains(ValidBuckets(), b)
}

// SourceFile is the minimal projection of a knowledge source file the classifier
// consumes. Defined locally to avoid an import cycle with pkg/knowledge.
type SourceFile struct {
	Path    string
	Content []byte
}

// MCPClassifyFunc is the signature of the optional MCP-backed fallback
// classifier. The components package never imports MCP directly; the caller
// (07-02 wiring) supplies this function.
type MCPClassifyFunc func(ctx context.Context, f SourceFile) (Bucket, float64, error)

// Options controls classifier behavior.
type Options struct {
	// WithAI enables the MCP fallback path. Ignored if MCPClassify is nil.
	WithAI bool
	// Override maps source-relative path to a forced bucket. Takes precedence
	// over every pattern path and over the MCP fallback.
	Override map[string]Bucket
	// MCPClassify, if non-nil and WithAI is true, is consulted when no pattern
	// or content match is found.
	MCPClassify MCPClassifyFunc
	// Ctx is the context passed to MCPClassify. nil means context.Background().
	Ctx context.Context
}

// Classify maps a SourceFile into one of the nine buckets. It returns the
// bucket, a confidence in [0, 1], and the classifier-source label
// ("user-override" | "pattern" | "mcp").
//
// Decision order:
//  1. opts.Override (confidence 1.0, source "user-override")
//  2. matchPath
//  3. matchName
//  4. matchContent
//  5. opts.MCPClassify when WithAI && MCPClassify != nil
//  6. (BucketUnknown, 0, "pattern") fallthrough
func Classify(f SourceFile, opts Options) (Bucket, float64, string) {
	if b, ok := opts.Override[f.Path]; ok {
		if !IsValidBucket(b) {
			b = BucketUnknown
		}
		return b, 1.0, "user-override"
	}
	if b, c := matchPath(f.Path); b != BucketUnknown {
		return b, c, "pattern"
	}
	if b, c := matchName(f.Path); b != BucketUnknown {
		return b, c, "pattern"
	}
	if b, c := matchContent(f.Content); b != BucketUnknown {
		return b, c, "pattern"
	}
	if opts.WithAI && opts.MCPClassify != nil {
		ctx := opts.Ctx
		if ctx == nil {
			ctx = context.Background()
		}
		b, c, err := opts.MCPClassify(ctx, f)
		if err != nil {
			slog.New(slog.NewTextHandler(os.Stderr, nil)).Warn(
				"knowledge.components: MCP classify failed",
				"path", f.Path, "err", err)
			return BucketUnknown, 0, "pattern"
		}
		if !IsValidBucket(b) {
			return BucketUnknown, 0, "pattern"
		}
		return b, c, "mcp"
	}
	return BucketUnknown, 0, "pattern"
}
