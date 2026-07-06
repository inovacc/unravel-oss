package cmd

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// updateKnowledgeHelpGolden, when set via `go test ./cmd/ -run TestKnowledgeHelpGolden -update`,
// regenerates the golden help-output files instead of asserting equality. It must NEVER fire
// during normal CI runs — golden regeneration is a deliberate, reviewed step.
var updateKnowledgeHelpGolden = flag.Bool("update", false, "regenerate help golden files under cmd/testdata/help/")

// TestKnowledgeHelpGolden locks the pre-refactor `--help` byte-shape for `unravel`,
// `unravel knowledge`, and `unravel kb`. Phase 66 (cmd/knowledge.go split) MUST keep this
// green; any drift in cobra registration order, Use/Short/Long text, or subcommand surface
// will fail this test.
//
// Isolation: each subtest spawns a fresh `go run . <args>` child process so that cobra's
// internal help cache and the package-level rootCmd singleton are never shared between
// subtests. This replaces the previous singleton-mutation approach (which caused ordering
// flakes when subtests ran after other tests had already executed rootCmd).
//
// If a future phase adds a `newRootCmd()` factory, prefer it over subprocess spawning.
func TestKnowledgeHelpGolden(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: spawns the go toolchain (build/run); run without -short to include")
	}
	// Intentionally NOT calling t.Parallel — subtests share the go build cache and
	// we want deterministic golden comparison without interleaved stdout.

	// Locate the project root (two directories up from this file: cmd/ -> repo root).
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	projectRoot := filepath.Dir(filepath.Dir(thisFile))

	cases := []struct {
		name       string
		args       []string
		goldenPath string
	}{
		{"root", []string{"--help"}, filepath.Join("testdata", "help", "unravel.help.golden.txt")},
		{"kb", []string{"kb", "--help"}, filepath.Join("testdata", "help", "unravel-kb.help.golden.txt")},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest spawns a fresh process — no singleton mutation.
			goArgs := append([]string{"run", "."}, tc.args...)
			cmd := exec.Command("go", goArgs...) //nolint:gosec
			cmd.Dir = projectRoot
			cmd.Env = append(os.Environ(), "NO_COLOR=1")

			got, err := cmd.Output()
			if err != nil {
				t.Fatalf("go run . %v: %v", tc.args, err)
			}
			if len(got) == 0 {
				t.Fatalf("captured help output for %q is empty", tc.name)
			}

			// goldenPath is relative to the cmd/ directory (same as before).
			goldenPath := filepath.Join(filepath.Dir(thisFile), tc.goldenPath)

			if *updateKnowledgeHelpGolden {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
					t.Fatalf("MkdirAll(%s): %v", filepath.Dir(goldenPath), err)
				}
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatalf("WriteFile(%s): %v", goldenPath, err)
				}
				t.Logf("updated golden: %s (%d bytes)", goldenPath, len(got))
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("ReadFile(%s): %v — run `go test ./cmd/ -run TestKnowledgeHelpGolden -update` to generate", goldenPath, err)
			}

			// Normalize CRLF → LF on both sides so goldens committed on Windows
			// compare equal to subprocess output regardless of line-ending convention.
			gotNorm := normalizeLF(got)
			wantNorm := normalizeLF(want)

			if !bytes.Equal(gotNorm, wantNorm) {
				t.Errorf("help output for %q does not match golden %s\n"+
					"  got  %d bytes (normalized)\n"+
					"  want %d bytes (normalized)\n"+
					"run `go test ./cmd/ -run TestKnowledgeHelpGolden -update` to deliberately accept changes",
					tc.name, tc.goldenPath, len(gotNorm), len(wantNorm))
			}
		})
	}
}

// normalizeLF strips \r so that goldens committed with CRLF line endings
// (Windows git default) compare equal to subprocess output with LF endings.
func normalizeLF(b []byte) []byte {
	return []byte(strings.ReplaceAll(string(b), "\r\n", "\n"))
}
