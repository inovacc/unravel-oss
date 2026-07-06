package analysis

import (
	"context"
	"log/slog"
)

// Options configures the analysis run.
type Options struct {
	IncludeGraph bool // include the full include/import dependency graph
	Symbols      bool // include the full symbol table
	MaxDepth     int  // max directory depth (0 = unlimited)
	Subsystems   []*SubsystemDef
}

// Analyzer orchestrates all analysis steps for a source codebase.
type Analyzer struct {
	scanner     *Scanner
	categorizer *Categorizer
	logger      *slog.Logger
	opts        Options
}

// NewAnalyzer creates a new analyzer for the given root directory.
func NewAnalyzer(root string, logger *slog.Logger, opts Options) *Analyzer {
	scanner := NewScanner(root)
	scanner.MaxDepth = opts.MaxDepth

	return &Analyzer{
		scanner:     scanner,
		categorizer: NewCategorizer(opts.Subsystems),
		logger:      logger,
		opts:        opts,
	}
}

// Analyze performs the full codebase analysis and returns a Report.
func (a *Analyzer) Analyze(_ context.Context) (*Report, error) {
	// Step 1: Scan source tree
	a.logger.Info("scanning source tree", "root", a.scanner.Root)

	files, err := a.scanner.Scan()
	if err != nil {
		return nil, err
	}

	a.logger.Info("discovered source files", "count", len(files))

	if len(files) == 0 {
		return &Report{
			Root:       a.scanner.Root,
			TotalFiles: 0,
		}, nil
	}

	// Partition files by language
	var cppFiles, pyFiles, javaFiles []*SourceFile

	for _, f := range files {
		switch {
		case IsPython(f):
			pyFiles = append(pyFiles, f)
		case IsJava(f):
			javaFiles = append(javaFiles, f)
		default:
			cppFiles = append(cppFiles, f)
		}
	}

	a.logger.Info("files by language", "cpp", len(cppFiles), "python", len(pyFiles), "java", len(javaFiles))

	report := &Report{
		Root:        a.scanner.Root,
		TotalFiles:  len(files),
		SourceFiles: files,
		FileLOC:     make(map[string]LOCStats, len(files)),
	}

	// Step 2: Count LOC for each file (language-aware)
	a.logger.Info("counting lines of code")

	for _, f := range files {
		stats, err := CountFileAuto(f.Path)
		if err != nil {
			a.logger.Warn("failed to count LOC", "file", f.RelPath, "error", err)
			continue
		}

		report.FileLOC[f.RelPath] = stats
		report.TotalLOC.Add(stats)
	}

	a.logger.Info("LOC analysis complete",
		"total_lines", report.TotalLOC.Lines,
		"code", report.TotalLOC.Code,
		"comments", report.TotalLOC.Comments,
	)

	// Step 3: Build largest files ranking
	report.LargestFiles = buildLargestFiles(report.FileLOC)

	// Step 4: Categorize into subsystems
	a.logger.Info("categorizing files into subsystems")

	subsystems := a.categorizer.Categorize(files)

	// Compute LOC per subsystem
	for _, sub := range subsystems {
		for _, f := range sub.Files {
			if stats, ok := report.FileLOC[f.RelPath]; ok {
				sub.LOC.Add(stats)
			}
		}
	}

	report.Subsystems = subsystems

	// --- C/C++ analysis path ---
	if len(cppFiles) > 0 {
		// Step 5: Detect C/C++ libraries
		a.logger.Info("detecting C/C++ libraries")

		report.Libraries = DetectLibraries(cppFiles)

		a.logger.Info("C/C++ libraries detected", "count", len(report.Libraries))

		// Step 6: Build include graph
		if a.opts.IncludeGraph {
			a.logger.Info("building C/C++ include graph")

			report.IncludeGraph = BuildIncludeGraph(cppFiles, a.scanner.Root)

			a.logger.Info("include graph built", "nodes", len(report.IncludeGraph.Nodes))
		}

		// Step 7: Build C/C++ symbol table + hierarchy
		if a.opts.Symbols {
			a.logger.Info("building C/C++ symbol table")

			report.Symbols = BuildSymbolTable(cppFiles)

			a.logger.Info("symbol table built",
				"classes", len(report.Symbols.Classes),
				"functions", len(report.Symbols.Functions),
				"enums", len(report.Symbols.Enums),
			)

			a.logger.Info("building C/C++ class hierarchy")

			report.Hierarchy = BuildHierarchy(report.Symbols)

			a.logger.Info("hierarchy built",
				"roots", len(report.Hierarchy.Roots),
				"depth", report.Hierarchy.Depth(),
			)
		}
	}

	// --- Python analysis path ---
	if len(pyFiles) > 0 {
		// Detect Python frameworks
		a.logger.Info("detecting Python frameworks")

		report.PyFrameworks = DetectPythonFrameworks(pyFiles)

		a.logger.Info("Python frameworks detected", "count", len(report.PyFrameworks))

		// Build Python import graph
		if a.opts.IncludeGraph {
			a.logger.Info("building Python import graph")

			report.PyImportGraph = BuildImportGraph(pyFiles, a.scanner.Root)

			a.logger.Info("import graph built", "nodes", len(report.PyImportGraph.Nodes))
		}

		// Build Python symbol table + hierarchy
		if a.opts.Symbols {
			a.logger.Info("building Python symbol table")

			report.PySymbols = BuildPythonSymbolTable(pyFiles)

			a.logger.Info("Python symbol table built",
				"classes", len(report.PySymbols.Classes),
				"functions", len(report.PySymbols.Functions),
			)

			a.logger.Info("building Python class hierarchy")

			report.PyHierarchy = BuildPythonHierarchy(report.PySymbols)

			a.logger.Info("Python hierarchy built",
				"roots", len(report.PyHierarchy.Roots),
				"depth", report.PyHierarchy.Depth(),
			)
		}
	}

	// --- Java analysis path ---
	if len(javaFiles) > 0 {
		a.logger.Info("detecting Java frameworks")

		report.JavaFrameworks = DetectJavaFrameworks(javaFiles)

		a.logger.Info("Java frameworks detected", "count", len(report.JavaFrameworks))
	}

	return report, nil
}

// buildLargestFiles returns files sorted by code lines (descending).
func buildLargestFiles(fileLOC map[string]LOCStats) []*FileSizeEntry {
	entries := make([]*FileSizeEntry, 0, len(fileLOC))
	for path, stats := range fileLOC {
		entries = append(entries, &FileSizeEntry{Path: path, LOC: stats})
	}

	// Sort by code lines descending (insertion sort, fine for this size)
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].LOC.Code > entries[j-1].LOC.Code; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}

	return entries
}
