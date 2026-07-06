//go:build goresym

package goresym

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
)

// goVersionRe matches a legitimate Go toolchain version string (e.g. "go1.26.4")
// so an attacker-supplied .go.buildinfo version cannot smuggle a flag into argv.
var goVersionRe = regexp.MustCompile(`^go[0-9]+(\.[0-9]+){0,2}$`)

// goresymBinaryNames lists the executable names probed on PATH, in order.
// The canonical `go install github.com/mandiant/GoReSym@latest` produces a
// mixed-case `GoReSym` binary, so that name is tried first; a lowercase
// `goresym` (some package managers / manual symlinks) is the fallback. On
// Windows exec.LookPath appends the `.exe` suffix automatically and is
// case-insensitive, so either name resolves there; on case-sensitive
// Linux/macOS the explicit `GoReSym` candidate is what actually finds the
// canonical install. This mirrors the pkg/android/tools runtime
// exec.LookPath pattern: a miss degrades to ErrNotImplemented rather than a
// hard failure.
var goresymBinaryNames = []string{"GoReSym", "goresym"}

// goresymBinary is the label used in error/log messages (the canonical tool
// name). It is independent of which on-disk candidate lookupGoresym resolves.
const goresymBinary = "GoReSym"

// lookupGoresym resolves the GoReSym executable by trying each candidate name
// in goresymBinaryNames and returning the first absolute path found. It
// returns the last exec.LookPath error (an *exec.Error wrapping
// exec.ErrNotFound) when no candidate is present, so callers can map a miss to
// ErrNotImplemented.
func lookupGoresym() (string, error) {
	var lastErr error
	for _, name := range goresymBinaryNames {
		if bin, err := exec.LookPath(name); err == nil {
			return bin, nil
		} else {
			lastErr = err
		}
	}
	return "", lastErr
}

// goresymOutput mirrors the JSON document emitted by GoReSym
// (Mandiant, MIT-licensed) v1.7.x. GoReSym marshals its ExtractMetadata
// struct with default Go field names (no json tags), so the keys are
// PascalCase. Only the fields we consume are declared here; unknown
// keys are ignored by encoding/json.
type goresymOutput struct {
	Version       string           `json:"Version"`
	BuildId       string           `json:"BuildId"`
	UserFunctions []goresymFunc    `json:"UserFunctions"`
	StdFunctions  []goresymFunc    `json:"StdFunctions"`
	Types         []goresymType    `json:"Types"`
	Interfaces    []goresymType    `json:"Interfaces"`
	BuildInfo     goresymBuildInfo `json:"BuildInfo"`
}

type goresymFunc struct {
	Start       uint64 `json:"Start"`
	End         uint64 `json:"End"`
	PackageName string `json:"PackageName"`
	FullName    string `json:"FullName"`
}

// goresymType mirrors objfile.Type from GoReSym v1.7.x: VA is the type's
// virtual address, Str the Go type name (e.g. "*main.GreeterWidget"), Kind
// the reflect.Kind ("struct", "interface", …), and Reconstructed the
// optional re-emitted Go source for structs/interfaces (only populated
// when GoReSym can rebuild the definition). The `-t` flag enumerates the
// moduledata typelinks (→ Types) and itablinks (→ Interfaces); when those
// regions resolve to zero (e.g. GoReSym v1.7.1 against a Go 1.26 binary,
// where the moduledata layout has drifted) both arrays come back JSON
// null and the mapping below yields an empty Result.Types — see
// docs/design/2026-goresym-backend.md §O3.
type goresymType struct {
	VA            uint64 `json:"VA"`
	Str           string `json:"Str"`
	Kind          string `json:"Kind"`
	Reconstructed string `json:"Reconstructed"`
}

type goresymBuildInfo struct {
	GoVersion string        `json:"GoVersion"`
	Path      string        `json:"Path"`
	Main      goresymModule `json:"Main"`
}

type goresymModule struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

// Recover drives the GoReSym CLI to recover function and type names from
// the binary at path. It compiles in only under the `goresym` build tag.
//
// Backend selection:
//   - "" / "goresym": use the GoReSym CLI (this implementation).
//   - "redress":      reserved future seam — returns ErrNotImplemented.
//   - anything else:  rejected.
//
// When the goresym executable is not on PATH the function returns
// ErrNotImplemented (matching the package contract and the
// pkg/android/tools precedent). A non-zero exit or unparseable output
// (e.g. the PE-stripped "failed to locate pclntab" case) is a normal
// wrapped error — NOT ErrNotImplemented — so callers can surface it.
func Recover(ctx context.Context, path string, opts Options) (*Result, error) {
	if path == "" {
		return nil, fmt.Errorf("goresym: path is required")
	}

	switch opts.Backend {
	case "", "goresym":
		// handled below
	case "pure":
		// Explicit request for the dependency-free pure-Go pclntab parser
		// (recover_pure.go), bypassing the CLI entirely.
		return recoverPure(ctx, path, opts)
	case "redress":
		// redress is enumerated as a future fallback backend (see
		// docs/design/2026-goresym-backend.md O2/O7) but is not wired up.
		return nil, ErrNotImplemented
	default:
		return nil, fmt.Errorf("goresym: unknown backend %q", opts.Backend)
	}

	bin, err := lookupGoresym()
	if err != nil {
		// Tool absent: fall back to the pure-Go parser before degrading to
		// the ErrNotImplemented sentinel, so a default install still recovers.
		if res, perr := recoverPure(ctx, path, opts); perr == nil && res != nil && len(res.Symbols) > 0 {
			return res, nil
		}
		return nil, ErrNotImplemented
	}

	args := buildGoresymArgs(opts, path)

	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		// Surface stderr (GoReSym also emits JSON {"error":...} to stdout
		// in some failure modes, but a non-zero exit lands here).
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("goresym: %s exited: %s: %w", goresymBinary, string(exitErr.Stderr), err)
		}
		return nil, fmt.Errorf("goresym: running %s failed: %w", goresymBinary, err)
	}

	var parsed goresymOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("goresym: parsing %s output failed: %w", goresymBinary, err)
	}

	res := mapGoresymOutput(&parsed, opts)
	if len(res.Symbols) == 0 {
		// CLI ran but recovered nothing (e.g. a layout the installed GoReSym
		// version can't parse): try the pure-Go parser before giving up.
		if pres, perr := recoverPure(ctx, path, opts); perr == nil && pres != nil && len(pres.Symbols) > 0 {
			return pres, nil
		}
	}
	return res, nil
}

// buildGoresymArgs assembles the GoReSym argv with argument-injection guards.
//
// SEC: both attacker-influenced values (opts.GoVersion from the binary's
// .go.buildinfo, and path) are neutralised:
//   - GoVersion is only passed when it matches the `goN.NN.N` shape, so a value
//     like "-d" or "-manualload=evil" cannot be reinterpreted as a flag.
//   - path is absolutised (a leading-dash basename cannot become a flag) and
//     placed after a "--" end-of-options marker so GoReSym's flag parser treats
//     it strictly as the positional binary path.
func buildGoresymArgs(opts Options, path string) []string {
	args := []string{"-p"}
	if opts.IncludeStdLib {
		args = append(args, "-d")
	}
	args = append(args, "-t")
	if opts.GoVersion != "" && goVersionRe.MatchString(opts.GoVersion) {
		args = append(args, "-v", opts.GoVersion)
	}
	absPath, absErr := filepath.Abs(path)
	if absErr != nil {
		absPath = path
	}
	return append(args, "--", absPath)
}

// mapGoresymOutput projects the GoReSym JSON document onto goresym.Result.
func mapGoresymOutput(o *goresymOutput, opts Options) *Result {
	res := &Result{
		BuildID:    o.BuildId,
		GoVersion:  o.BuildInfo.GoVersion,
		ModulePath: o.BuildInfo.Main.Path,
	}
	// BuildInfo is empty on stripped binaries; fall back to the
	// top-level Version (e.g. "1.26.4") and the buildinfo Path.
	if res.GoVersion == "" {
		res.GoVersion = o.Version
	}
	if res.ModulePath == "" {
		res.ModulePath = o.BuildInfo.Path
	}

	appendFuncs := func(fns []goresymFunc) {
		for _, f := range fns {
			name := f.FullName
			if name == "" {
				name = f.PackageName
			}
			if name == "" {
				continue
			}
			res.Symbols = append(res.Symbols, Symbol{Name: name, Address: f.Start})
		}
	}
	appendFuncs(o.UserFunctions)
	if opts.IncludeStdLib {
		appendFuncs(o.StdFunctions)
	}

	seen := make(map[string]struct{}, len(o.Types)+len(o.Interfaces))
	appendTypes := func(ts []goresymType) {
		for _, t := range ts {
			if t.Str == "" {
				continue
			}
			if _, ok := seen[t.Str]; ok {
				continue
			}
			seen[t.Str] = struct{}{}
			res.Types = append(res.Types, t.Str)
		}
	}
	appendTypes(o.Types)
	appendTypes(o.Interfaces)

	return res
}
