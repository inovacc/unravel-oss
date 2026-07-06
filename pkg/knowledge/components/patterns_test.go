/*
Copyright (c) 2026 Security Research
*/
package components

import "testing"

func TestPatternTableCompiles(t *testing.T) {
	tables := map[string][]struct {
		re         interface{ MatchString(string) bool }
		bucket     Bucket
		confidence float64
	}{}
	_ = tables
	// Pattern arrays share the same slice; iterate pathPatterns to validate.
	for i, p := range pathPatterns {
		if p.re == nil {
			t.Fatalf("pathPatterns[%d]: nil regexp", i)
		}
		if !IsValidBucket(p.bucket) {
			t.Fatalf("pathPatterns[%d]: invalid bucket %q", i, p.bucket)
		}
		if p.confidence <= 0 || p.confidence > 1 {
			t.Fatalf("pathPatterns[%d]: confidence %v out of range", i, p.confidence)
		}
	}
}

func TestMatchPathBuckets(t *testing.T) {
	cases := []struct {
		path string
		want Bucket
	}{
		{"src/auth/login.js", BucketAuth},
		{"src/api/client.ts", BucketAPI},
		{"src/preload.js", BucketIPC},
		{"src/lib/sentry-init.ts", BucketTelemetry},
		{"src/crypto/aes.go", BucketCrypto},
		{"src/storage/leveldb.go", BucketPersistence},
		{"src/autoupdater.js", BucketUpdate},
		{"src/components/Button.tsx", BucketUI},
		{"src/zzz/no-keyword.go", BucketUnknown},
	}
	for _, tc := range cases {
		got, _ := matchPath(tc.path)
		if got != tc.want {
			t.Errorf("matchPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestMatchContentBoundedScan(t *testing.T) {
	// Place keyword past maxContentScan so the scan must NOT find it.
	prefix := make([]byte, maxContentScan)
	for i := range prefix {
		prefix[i] = ' '
	}
	body := append(prefix, []byte("sentry")...)
	if b, _ := matchContent(body); b != BucketUnknown {
		t.Fatalf("content scan should be bounded, got bucket %q", b)
	}
	// And again with the keyword inside the cap.
	if b, _ := matchContent([]byte("sentry init")); b != BucketTelemetry {
		t.Fatalf("inside-cap match failed, got bucket %q", b)
	}
}
