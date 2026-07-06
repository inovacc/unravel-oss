package analysis

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/dominikbraun/graph"
)

// IsWithinRoot reports whether resolved is the root itself or a true
// subpath of root. It enforces a path-separator boundary so that a
// sibling directory sharing a name prefix (e.g. "/proj/src-evil" vs the
// root "/proj/src") is correctly rejected (T-03-01, D-02).
// Exported so the judge package and orchestrator CLI can reuse the same
// path-safety guard without duplicating the logic.
func IsWithinRoot(cleanRoot, resolved string) bool {
	if resolved == cleanRoot {
		return true
	}
	return strings.HasPrefix(resolved, cleanRoot+string(filepath.Separator))
}

// ConversionUnit is the stable orchestrator input contract (D-01, D-04).
// Field names must not be renamed without versioning the schema.
type ConversionUnit struct {
	// ID is the stable key for this unit. For C++: the stem relative path
	// (e.g., "src/foo" for foo.h + foo.cpp). For Python and Java: the
	// RelPath of the single file.
	ID       string `json:"id"`
	Language string `json:"language"` // "cpp", "python", "java"
	// Files lists all member files (relative paths). C++ units may have 2+.
	Files []string `json:"files"`
	// IsSCC is true when this unit was collapsed from a strongly-connected
	// component (mutually-dependent files). Per D-02.
	IsSCC bool `json:"is_scc"`
	// DepsIDs lists the IDs of units this unit depends on (already converted
	// before this unit). Leaf units have empty DepsIDs.
	DepsIDs []string `json:"deps_ids"`
}

// SymbolEntry records where a symbol is defined.
type SymbolEntry struct {
	UnitID   string `json:"unit_id"`
	Language string `json:"language"`
	// Kind is one of: "struct", "class", "enum", "interface", "func", "const"
	Kind string `json:"kind"`
}

// SymbolRegistry is the global cross-unit symbol map (D-05).
// Contains only exported/public symbols visible across unit boundaries.
// Java entries are empty for Phase 1 (Java gets registry in Phase 6).
type SymbolRegistry struct {
	Types     map[string]SymbolEntry `json:"types"`     // type/class/enum name → entry
	Functions map[string]SymbolEntry `json:"functions"` // exported function name → entry
}

// UnitsOutput is the stable JSON schema consumed by the Phase 3 orchestrator (D-04).
// This type and its field names are part of the orchestrator input contract.
type UnitsOutput struct {
	Root     string           `json:"root"`
	Total    int              `json:"total_units"`
	Units    []ConversionUnit `json:"units"` // ordered leaf-first; SCCs collapsed
	Registry *SymbolRegistry  `json:"registry"`
}

// cppHeaderExts are C/C++ header extensions.
var cppHeaderExts = map[string]struct{}{
	".h": {}, ".hpp": {}, ".hxx": {},
}

// cppImplExts are C/C++ implementation extensions.
var cppImplExts = map[string]struct{}{
	".c": {}, ".cpp": {}, ".cc": {}, ".cxx": {}, ".c++": {},
}

// langFromSourceFile maps SourceFile.Language to the canonical lang string.
func langFromSourceFile(sf *SourceFile) string {
	lang := sf.Language
	switch {
	case lang == "C Source" || lang == "C++ Source" || lang == "C/C++ Header":
		return "cpp"
	case lang == "Python Source":
		return "python"
	case lang == "Java Source":
		return "java"
	default:
		return ""
	}
}

// stripCppExt removes any C/C++ file extension and returns the bare stem.
func stripCppExt(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	_, isHeader := cppHeaderExts[ext]
	_, isImpl := cppImplExts[ext]
	if isHeader || isImpl {
		return strings.TrimSuffix(name, filepath.Ext(name))
	}
	return name
}

// groupFiles groups SourceFiles into raw ConversionUnit values by language rule.
// C++: pairs headers and impl files sharing the same directory/stem.
// Python/Java: one file = one unit.
func groupFiles(files []*SourceFile) []ConversionUnit {
	stemToFiles := make(map[string][]string)
	var units []ConversionUnit

	for _, f := range files {
		lang := langFromSourceFile(f)
		switch lang {
		case "cpp":
			dir := filepath.ToSlash(filepath.Dir(f.RelPath))
			base := filepath.Base(f.RelPath)
			stem := stripCppExt(base)
			var key string
			if dir == "." {
				key = filepath.ToSlash(stem)
			} else {
				key = filepath.ToSlash(filepath.Join(dir, stem))
			}
			stemToFiles[key] = append(stemToFiles[key], f.RelPath)
		case "python":
			units = append(units, ConversionUnit{
				ID:       f.RelPath,
				Language: "python",
				Files:    []string{f.RelPath},
			})
		case "java":
			units = append(units, ConversionUnit{
				ID:       f.RelPath,
				Language: "java",
				Files:    []string{f.RelPath},
			})
		}
		// unknown: skip
	}

	// Build C++ units from stem groups
	stems := make([]string, 0, len(stemToFiles))
	for stem := range stemToFiles {
		stems = append(stems, stem)
	}
	sort.Strings(stems)
	for _, stem := range stems {
		files := stemToFiles[stem]
		sort.Strings(files)
		units = append(units, ConversionUnit{
			ID:       stem,
			Language: "cpp",
			Files:    files,
		})
	}

	return units
}

// BuildConversionUnits constructs a topologically sorted slice of ConversionUnit
// values from the analysis Report, plus a global SymbolRegistry of exported symbols.
//
// The report must have been produced with Options.IncludeGraph=true and
// Options.Symbols=true; otherwise the returned slice will have no ordering edges.
//
// Order is leaf-first: a unit appears before any unit that depends on it.
// Strongly-connected components (cycles) are collapsed into a single unit (D-02).
//
// Java units are treated as independent (no JavaImportGraph in Phase 1); their
// ordering within the Java group is alphabetical. This is a known limitation;
// Java inter-class ordering is deferred to Phase 6.
func BuildConversionUnits(report *Report) ([]ConversionUnit, *SymbolRegistry, error) {
	registry := &SymbolRegistry{
		Types:     make(map[string]SymbolEntry),
		Functions: make(map[string]SymbolEntry),
	}

	if len(report.SourceFiles) == 0 {
		return []ConversionUnit{}, registry, nil
	}

	// Step 1: Group files into raw units by language rule.
	rawUnits := groupFiles(report.SourceFiles)
	if len(rawUnits) == 0 {
		return []ConversionUnit{}, registry, nil
	}

	// Step 2: Build file → unit ID index.
	fileToUnit := make(map[string]string, len(report.SourceFiles))
	for _, u := range rawUnits {
		for _, f := range u.Files {
			fileToUnit[f] = u.ID
		}
	}

	// Step 3: Resolve edges per unit (with path traversal guard).
	cleanRoot := filepath.Clean(report.Root)
	unitByID := make(map[string]*ConversionUnit, len(rawUnits))
	for i := range rawUnits {
		unitByID[rawUnits[i].ID] = &rawUnits[i]
	}

	for i := range rawUnits {
		u := &rawUnits[i]
		depsSet := make(map[string]struct{})

		for _, f := range u.Files {
			switch u.Language {
			case "cpp":
				if report.IncludeGraph != nil {
					if node, ok := report.IncludeGraph.Nodes[f]; ok {
						for _, dep := range node.LocalDeps {
							// Path traversal guard (T-03-01)
							resolved := filepath.Clean(filepath.Join(report.Root, dep))
							if !IsWithinRoot(cleanRoot, resolved) {
								continue
							}
							depUnit, ok := fileToUnit[dep]
							if !ok || depUnit == u.ID {
								continue
							}
							depsSet[depUnit] = struct{}{}
						}
					}
				}
			case "python":
				if report.PyImportGraph != nil {
					if node, ok := report.PyImportGraph.Nodes[f]; ok {
						for _, dep := range node.LocalDeps {
							// Path traversal guard (T-03-01)
							resolved := filepath.Clean(filepath.Join(report.Root, dep))
							if !IsWithinRoot(cleanRoot, resolved) {
								continue
							}
							depUnit, ok := fileToUnit[dep]
							if !ok || depUnit == u.ID {
								continue
							}
							depsSet[depUnit] = struct{}{}
						}
					}
				}
				// java: no inter-unit edges in Phase 1 (A1)
			}
		}

		if len(depsSet) > 0 {
			deps := make([]string, 0, len(depsSet))
			for d := range depsSet {
				deps = append(deps, d)
			}
			sort.Strings(deps)
			u.DepsIDs = deps
		}
	}

	// Step 4: Build dominikbraun/graph DAG.
	g := graph.New(graph.StringHash, graph.Directed())
	for _, u := range rawUnits {
		_ = g.AddVertex(u.ID)
	}
	// Edge orientation contract: edges point dependent → dependency
	// (u depends on depID). graph.StableTopologicalSort returns sources
	// (units nothing depends on) last for this orientation, so the
	// result slice is reversed below to produce leaf-first order.
	// See TestBuildConversionUnits_DiamondTopoOrder which exercises a
	// multi-level diamond (A→B, A→C, B→D, C→D) to lock this contract.
	for _, u := range rawUnits {
		for _, depID := range u.DepsIDs {
			_ = g.AddEdge(u.ID, depID) // ignore "already exists" errors
		}
	}

	// Step 5: SCC detection and collapse (D-02).
	sccs, err := graph.StronglyConnectedComponents(g)
	if err != nil {
		return nil, nil, fmt.Errorf("strongly-connected components: %w", err)
	}

	// Build a map from member ID → merged unit ID (lex-min of SCC members).
	memberToMergedID := make(map[string]string, len(rawUnits))
	for _, scc := range sccs {
		if len(scc) <= 1 {
			if len(scc) == 1 {
				memberToMergedID[scc[0]] = scc[0]
			}
			continue
		}
		sorted := make([]string, len(scc))
		copy(sorted, scc)
		sort.Strings(sorted)
		mergedID := sorted[0]
		for _, m := range sorted {
			memberToMergedID[m] = mergedID
		}
	}

	// Build merged units map. For cross-language SCCs the merged
	// Language is derived deterministically as the lexicographically
	// smallest member language so D-04 output is stable across runs
	// regardless of rawUnits iteration order (WR-01).
	mergedMap := make(map[string]*ConversionUnit)
	for _, u := range rawUnits {
		mergedID := memberToMergedID[u.ID]
		existing, ok := mergedMap[mergedID]
		if !ok {
			cu := ConversionUnit{
				ID:       mergedID,
				Language: u.Language,
				Files:    append([]string{}, u.Files...),
				IsSCC:    mergedID != u.ID, // true only if this is a multi-member SCC
			}
			mergedMap[mergedID] = &cu
		} else {
			existing.Files = append(existing.Files, u.Files...)
			existing.IsSCC = true // merging additional members confirms SCC
			if u.Language != "" && (existing.Language == "" || u.Language < existing.Language) {
				existing.Language = u.Language
			}
		}
	}

	// If a single-member SCC maps to itself, IsSCC stays false (correct).
	// For multi-member SCCs, IsSCC=true was set above. Now update file-to-unit index.
	fileToMergedUnit := make(map[string]string, len(report.SourceFiles))
	for mergedID, mu := range mergedMap {
		sort.Strings(mu.Files)
		for _, f := range mu.Files {
			fileToMergedUnit[f] = mergedID
		}
	}

	// Rebuild DepsIDs for merged units (union of member deps, excluding self-refs).
	for _, u := range rawUnits {
		mergedID := memberToMergedID[u.ID]
		mu := mergedMap[mergedID]
		for _, depID := range u.DepsIDs {
			resolvedDep := memberToMergedID[depID]
			if resolvedDep == "" || resolvedDep == mergedID {
				continue
			}
			// Add dep if not already present
			found := slices.Contains(mu.DepsIDs, resolvedDep)
			if !found {
				mu.DepsIDs = append(mu.DepsIDs, resolvedDep)
			}
		}
	}
	for _, mu := range mergedMap {
		sort.Strings(mu.DepsIDs)
	}

	// Step 6: Build the merged DAG for topological sort.
	mergedGraph := graph.New(graph.StringHash, graph.Directed())
	for mergedID := range mergedMap {
		_ = mergedGraph.AddVertex(mergedID)
	}
	for _, mu := range mergedMap {
		for _, depID := range mu.DepsIDs {
			_ = mergedGraph.AddEdge(mu.ID, depID)
		}
	}

	// Topological sort (leaf-first after reversal).
	order, err := graph.StableTopologicalSort(mergedGraph, func(a, b string) bool { return a < b })
	if err != nil {
		return nil, nil, fmt.Errorf("topological sort: %w", err)
	}
	// Reverse for leaf-first (StableTopologicalSort returns sources last).
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}

	// Build final slice in topo order.
	result := make([]ConversionUnit, 0, len(order))
	for _, id := range order {
		if mu, ok := mergedMap[id]; ok {
			result = append(result, *mu)
		}
	}

	// Step 7: Build SymbolRegistry (D-05, exported only).
	// C++ symbols: use report.Symbols (SymbolTable).
	if report.Symbols != nil {
		for name, c := range report.Symbols.Classes {
			unitID := fileToMergedUnit[relPathFromAbs(report.Root, c.File)]
			registry.Types[name] = SymbolEntry{UnitID: unitID, Language: "cpp", Kind: c.Kind}
		}
		for name, f := range report.Symbols.Functions {
			// C++ FunctionInfo has no IsStatic field; all functions are registered.
			unitID := fileToMergedUnit[relPathFromAbs(report.Root, f.File)]
			registry.Functions[name] = SymbolEntry{UnitID: unitID, Language: "cpp", Kind: "func"}
		}
		for name, e := range report.Symbols.Enums {
			unitID := fileToMergedUnit[relPathFromAbs(report.Root, e.File)]
			registry.Types[name] = SymbolEntry{UnitID: unitID, Language: "cpp", Kind: "enum"}
		}
	}

	// Python symbols: use report.PySymbols; if nil, parse from source files.
	pySymbols := report.PySymbols
	if pySymbols == nil {
		// Build from source files on the fly for the registry.
		var pyFiles []*SourceFile
		for _, sf := range report.SourceFiles {
			if langFromSourceFile(sf) == "python" {
				pyFiles = append(pyFiles, sf)
			}
		}
		if len(pyFiles) > 0 {
			pySymbols = BuildPythonSymbolTable(pyFiles)
		}
	}
	if pySymbols != nil {
		for name, c := range pySymbols.Classes {
			if strings.HasPrefix(name, "_") {
				continue // unexported
			}
			relKey := relPathFromAbs(report.Root, c.File)
			unitID := fileToMergedUnit[relKey]
			if unitID == "" {
				// Fall back to the pre-merge index, keyed consistently
				// on RelPath (WR-02).
				unitID = fileToUnit[relKey]
			}
			registry.Types[name] = SymbolEntry{UnitID: unitID, Language: "python", Kind: "class"}
		}
		for name, f := range pySymbols.Functions {
			if strings.HasPrefix(name, "_") {
				continue // unexported
			}
			relKey := relPathFromAbs(report.Root, f.File)
			unitID := fileToMergedUnit[relKey]
			if unitID == "" {
				unitID = fileToUnit[relKey]
			}
			registry.Functions[name] = SymbolEntry{UnitID: unitID, Language: "python", Kind: "func"}
		}
	}

	return result, registry, nil
}

// relPathFromAbs converts an absolute file path to a relative path within root.
// Returns the input unchanged if it is already relative or the conversion fails.
func relPathFromAbs(root, absPath string) string {
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		return absPath
	}
	return filepath.ToSlash(rel)
}
