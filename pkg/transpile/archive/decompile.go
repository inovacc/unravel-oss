package archive

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler"
)

// perFileTimeout is the maximum time allowed for decompiling a single .class file.
const perFileTimeout = 10 * time.Second

// DecompileClasses attempts to decompile .class files in the extracted archive
// to .java source files. It skips .class files that already have a corresponding
// .java source file.
//
// When the native decompiler is enabled (default), it is used as the primary
// method. If native decompilation fails for a file, it falls back to an
// external JAR decompiler (if available).
func (e *Extractor) DecompileClasses(ctx context.Context, info *ArchiveInfo) error {
	if len(info.ClassFiles) == 0 {
		return nil
	}

	// Build set of existing .java files for dedup
	javaSet := make(map[string]struct{}, len(info.JavaFiles))
	for _, jf := range info.JavaFiles {
		javaSet[jf] = struct{}{}
	}

	// Find external decompiler JAR as fallback
	externalDecompiler := e.findDecompiler()

	if !e.useNativeDecompiler && externalDecompiler == "" {
		e.logger.Warn("no decompiler available, skipping .class decompilation",
			"class_files", len(info.ClassFiles),
		)

		return nil
	}

	native := &decompiler.NativeDecompiler{}

	var decompiled, skipped int
	total := len(info.ClassFiles)

	for i, classRel := range info.ClassFiles {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if (i+1)%100 == 0 || i == 0 {
			e.logger.Info("decompiling progress", "current", i+1, "total", total)
		}

		// Check if corresponding .java already exists
		javaRel := strings.TrimSuffix(classRel, ".class") + ".java"
		if _, ok := javaSet[javaRel]; ok {
			continue
		}

		classPath := filepath.Join(info.ExtractDir, filepath.FromSlash(classRel))
		outputDir := filepath.Dir(classPath)
		javaPath := filepath.Join(info.ExtractDir, filepath.FromSlash(javaRel))

		var ok bool

		// Try native decompiler first (with timeout and panic recovery)
		if e.useNativeDecompiler {
			nErr := decompileWithTimeout(native, classPath, outputDir, perFileTimeout)
			if nErr != nil {
				e.logger.Debug("native decompile failed, trying fallback",
					"class", classRel, "error", nErr)
				skipped++
			} else if _, err := os.Stat(javaPath); err == nil {
				ok = true
			}
		}

		// Fall back to external JAR decompiler
		if !ok && externalDecompiler != "" {
			if err := e.decompileOne(ctx, externalDecompiler, classPath, outputDir); err != nil {
				e.logger.Warn("decompile failed", "class", classRel, "error", err)
				continue
			}

			if _, err := os.Stat(javaPath); err == nil {
				ok = true
			}
		}

		if ok {
			info.JavaFiles = append(info.JavaFiles, javaRel)
			decompiled++
		}
	}

	e.logger.Info("decompilation complete",
		"decompiled", decompiled,
		"skipped", skipped,
		"total", total,
		"native", e.useNativeDecompiler,
	)

	return nil
}

// decompileWithTimeout runs the native decompiler with a timeout and panic recovery.
func decompileWithTimeout(native *decompiler.NativeDecompiler, classPath, outputDir string, timeout time.Duration) error {
	type result struct {
		err error
	}

	ch := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: fmt.Errorf("panic: %v", r)}
			}
		}()
		ch <- result{err: native.Decompile(classPath, outputDir)}
	}()

	select {
	case res := <-ch:
		return res.err
	case <-time.After(timeout):
		return fmt.Errorf("timeout after %s", timeout)
	}
}

// findDecompiler looks for a Java decompiler in known locations.
func (e *Extractor) findDecompiler() string {
	// 1. Explicit path from option
	if e.decompilerPath != "" {
		if _, err := os.Stat(e.decompilerPath); err == nil {
			return e.decompilerPath
		}
	}

	// 2. tools/cfr.jar in project directory
	if _, err := os.Stat("tools/cfr.jar"); err == nil {
		abs, err := filepath.Abs("tools/cfr.jar")
		if err == nil {
			return abs
		}
	}

	// 3. User cache directory
	if cacheDir, err := os.UserCacheDir(); err == nil {
		cfrPath := filepath.Join(cacheDir, "togo", "tools", "cfr.jar")
		if _, err := os.Stat(cfrPath); err == nil {
			return cfrPath
		}

		fernflowerPath := filepath.Join(cacheDir, "togo", "tools", "fernflower.jar")
		if _, err := os.Stat(fernflowerPath); err == nil {
			return fernflowerPath
		}
	}

	return ""
}

// decompileOne runs the decompiler on a single .class file.
func (e *Extractor) decompileOne(ctx context.Context, decompilerJar, classPath, outputDir string) error {
	// Check if Java is available
	javaPath, err := exec.LookPath("java")
	if err != nil {
		return fmt.Errorf("java not found in PATH: %w", err)
	}

	// Absolutize the (untrusted, in-archive) class path so it can never be
	// parsed as a flag by the decompiler/javap (argument injection, CWE-88).
	if abs, absErr := filepath.Abs(classPath); absErr == nil {
		classPath = abs
	}

	// Try CFR-style decompiler first
	cmd := exec.CommandContext(ctx, javaPath, "-jar", decompilerJar, classPath, "--outputdir", outputDir)
	cmd.Dir = outputDir

	if _, err := cmd.CombinedOutput(); err == nil {
		return nil
	}

	// Try Fernflower-style (different CLI args)
	cmd = exec.CommandContext(ctx, javaPath, "-jar", decompilerJar, classPath, outputDir)
	cmd.Dir = outputDir

	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	// Last resort: javap disassembly
	javapPath, err := exec.LookPath("javap")
	if err != nil {
		return fmt.Errorf("decompilation failed: %s", strings.TrimSpace(string(output)))
	}

	javaFile := strings.TrimSuffix(classPath, ".class") + ".java"

	cmd = exec.CommandContext(ctx, javapPath, "-c", "-p", classPath)

	javapOutput, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("javap failed: %w", err)
	}

	// Write javap output as a .java file (will be partial, but better than nothing)
	header := fmt.Sprintf("// Decompiled from %s using javap (disassembly only)\n// Manual review required\n\n",
		filepath.Base(classPath))

	if err := os.WriteFile(javaFile, []byte(header+string(javapOutput)), 0o644); err != nil {
		return fmt.Errorf("write javap output: %w", err)
	}

	return nil
}

// FindDecompiler returns the path to a Java decompiler, or empty string if none found.
func (e *Extractor) FindDecompiler() string {
	return e.findDecompiler()
}
