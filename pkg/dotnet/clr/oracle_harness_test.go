//go:build oracle

/*
Copyright (c) 2026 Security Research
*/
package clr_test

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func filepathBase(p string) string { return filepath.Base(p) }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ilspyAssemblyRefs runs `ilspycmd --il <asm>` and scrapes ".assembly extern X"
// declarations. DOTNET_ROLL_FORWARD=Major lets 8.2 run on any installed SDK.
func ilspyAssemblyRefs(t *testing.T, ilspy, asm string) []string {
	t.Helper()
	cmd := exec.Command(ilspy, "--il", asm)
	cmd.Env = append(os.Environ(), "DOTNET_ROLL_FORWARD=Major")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("ilspycmd failed (%v) — treat oracle as unavailable", err)
	}

	var refs []string
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, ".assembly extern ") {
			name := strings.TrimSpace(strings.TrimPrefix(line, ".assembly extern "))
			name = strings.TrimSuffix(name, " {")
			name = strings.Trim(name, "'")
			if name != "" {
				refs = append(refs, name)
			}
		}
	}
	sort.Strings(refs)
	return refs
}
