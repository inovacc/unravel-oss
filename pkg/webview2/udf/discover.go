/*
Copyright (c) 2026 Security Research
*/

package udf

import (
	"os"
	"path/filepath"
	"strings"
)

// UDFInfo describes a candidate WebView2 User Data Folder. Declared locally
// to avoid a package cycle with the root webview2 package; the top-level
// Analyze function translates these into UDFInfo values.
type UDFInfo struct {
	Path string `json:"path"`
	// Source is one of: "default" | "localappdata" | "localappdata-userdata"
	// | "registry-policy" | "user-override" | "uwp-localcache" | "override".
	Source string `json:"source"`
	Exists bool   `json:"exists"`
}

// DiscoverOptions tunes the candidate-resolution pipeline.
//
// Override, when non-empty, causes the resolver to:
//   - Prepend the override path as the first candidate with Source="override".
//   - Surface the candidate even when Exists=false (caller's choice is visible).
//   - Short-circuit default-candidate resolution when the override path exists.
type DiscoverOptions struct {
	Override string
}

// ProfileInfo names a Chromium profile within a UDF. Declared locally to
// avoid a package cycle with the root webview2 package.
type ProfileInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// DiscoverUDFs returns the full list of WebView2 User Data Folder candidates
// for the given executable path with their provenance. Callers evaluate each
// candidate — the function never silently picks one (pitfall 2, D-02/D-03).
//
// Sources (in order):
//  1. "default":              <exeDir>/<exeBase>.WebView2/EBWebView
//  2. "localappdata":         %LOCALAPPDATA%/<exeBaseNoExt>/EBWebView
//  3. "localappdata-userdata": %LOCALAPPDATA%/<exeBaseNoExt>/User Data
//  4. "registry-policy":      HKCU\Software\Policies\Microsoft\Edge\WebView2\UserDataDir (Windows)
//
// Path traversal (T-03-06): exePath is Cleaned; candidates with ".." segments
// after Clean are rejected.
func DiscoverUDFs(exePath string) ([]UDFInfo, error) {
	return DiscoverUDFsWithOptions(exePath, DiscoverOptions{})
}

// DiscoverUDFsWithOptions is the option-aware variant of DiscoverUDFs.
// When opts.Override is set, the override candidate is prepended; if the
// override exists on disk, default-candidate resolution is short-circuited.
func DiscoverUDFsWithOptions(exePath string, opts DiscoverOptions) ([]UDFInfo, error) {
	var out []UDFInfo

	// Override candidate (Task 2 / D-02): prepended; never filtered out.
	if opts.Override != "" {
		o := UDFInfo{Path: filepath.Clean(opts.Override), Source: "override"}
		if st, err := os.Lstat(o.Path); err == nil && st.IsDir() {
			o.Exists = true
		}
		out = append(out, o)
		// Short-circuit when the override resolves on disk — caller's
		// choice is authoritative.
		if o.Exists {
			return out, nil
		}
	}

	if exePath == "" {
		return out, nil
	}
	exePath = filepath.Clean(exePath)
	exeDir := filepath.Dir(exePath)
	exeBase := filepath.Base(exePath)
	exeBaseNoExt := strings.TrimSuffix(exeBase, filepath.Ext(exeBase))

	// UWP-package branch (Task 1 / D-01): when the input lives under
	// WindowsApps\<PFN> or has an AppxManifest sibling, walk
	// %LOCALAPPDATA%\Packages\<PFN>\LocalCache for any EBWebView dir.
	if uwp := resolveUWPCandidates(exePath); len(uwp) > 0 {
		out = append(out, uwp...)
	}

	// 1. Default: <exeDir>/<exeBase>.WebView2/EBWebView
	defaultPath := filepath.Join(exeDir, exeBase+".WebView2", EBWebViewDir)
	if !hasDotDot(defaultPath) {
		out = append(out, probeUDF(defaultPath, "default"))
	}

	// 2. LOCALAPPDATA/<exeBaseNoExt>/EBWebView
	lad := os.Getenv("LOCALAPPDATA")
	if lad != "" && exeBaseNoExt != "" {
		p := filepath.Join(lad, exeBaseNoExt, EBWebViewDir)
		if !hasDotDot(p) {
			out = append(out, probeUDF(p, "localappdata"))
		}
		// 3. LOCALAPPDATA/<exeBaseNoExt>/User Data (alt variant)
		p2 := filepath.Join(lad, exeBaseNoExt, "User Data")
		if !hasDotDot(p2) {
			out = append(out, probeUDF(p2, "localappdata-userdata"))
		}
	}

	// 4. Registry policy (Windows only)
	for _, p := range policyUDFCandidates() {
		pc := filepath.Clean(p)
		if hasDotDot(pc) {
			continue
		}
		out = append(out, probeUDF(pc, "registry-policy"))
	}

	return out, nil
}

// uwpResolveMaxCandidates caps the UWP-localcache candidate list (D-01).
const uwpResolveMaxCandidates = 8

// uwpResolveMaxDepth bounds the recursive walk under
// %LOCALAPPDATA%\Packages\<PFN>\LocalCache to depth ≤ 3 to keep the search
// cheap on vendor-nested layouts (Teams: LocalCache/Microsoft/MSTeams/EBWebView).
const uwpResolveMaxDepth = 3

// resolveUWPCandidates implements the UWP-package branch of the resolver.
//
// Trigger conditions (either is sufficient):
//   - exePath (or any of its parents) is the form WindowsApps/<PFN>/...
//   - an AppxManifest.xml sibling exists next to exePath (or in an ancestor
//     directory).
//
// On trigger, derives the Package Family Name (the <Name>_<PublisherHash>
// folder under WindowsApps, with the version+arch tokens stripped), then
// walks %LOCALAPPDATA%\Packages\<PFN>\LocalCache (depth ≤ 3) collecting any
// directory whose base name equals "EBWebView". All matches are returned with
// Source="uwp-localcache" and Exists:true. Caps at uwpResolveMaxCandidates.
func resolveUWPCandidates(exePath string) []UDFInfo {
	pfn := uwpPackageFamilyName(exePath)
	if pfn == "" {
		return nil
	}
	lad := os.Getenv("LOCALAPPDATA")
	if lad == "" {
		return nil
	}
	root := filepath.Join(lad, "Packages", pfn, "LocalCache")
	st, err := os.Lstat(root)
	if err != nil || !st.IsDir() {
		return nil
	}

	var out []UDFInfo
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// Bound depth relative to root.
		if rel, rerr := filepath.Rel(root, path); rerr == nil && rel != "." {
			depth := 1 + strings.Count(rel, string(filepath.Separator))
			if depth > uwpResolveMaxDepth {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == EBWebViewDir {
			out = append(out, UDFInfo{Path: path, Source: "uwp-localcache", Exists: true})
			if len(out) >= uwpResolveMaxCandidates {
				return filepath.SkipAll
			}
			// Don't descend into a matched EBWebView (its children aren't
			// further EBWebView dirs).
			return filepath.SkipDir
		}
		return nil
	})
	return out
}

// uwpPackageFamilyName extracts the PFN (Name_PublisherHash) for a path
// pointing into a WindowsApps install, or returns "" if the path isn't a UWP
// install or doesn't carry an AppxManifest sibling.
//
// WindowsApps install folders look like:
//
//	C:\Program Files\WindowsApps\<Name>_<Version>_<Arch>__<PublisherHash>
//
// The PFN that LOCALAPPDATA\Packages uses is "<Name>_<PublisherHash>".
func uwpPackageFamilyName(exePath string) string {
	clean := filepath.Clean(exePath)
	parts := strings.Split(filepath.ToSlash(clean), "/")

	// 1. Direct: locate the WindowsApps anchor and pick the immediate child.
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "WindowsApps") {
			return uwpFolderToPFN(parts[i+1])
		}
	}

	// 2. AppxManifest sibling (or ancestor) heuristic. Walk up from exePath
	//    looking for AppxManifest.xml in the same directory; if found, that
	//    directory's basename gives us the install-folder name.
	dir := clean
	if st, err := os.Stat(clean); err == nil && !st.IsDir() {
		dir = filepath.Dir(clean)
	}
	for depth := 0; depth < 4 && dir != "" && dir != filepath.Dir(dir); depth++ {
		if _, err := os.Stat(filepath.Join(dir, "AppxManifest.xml")); err == nil {
			return uwpFolderToPFN(filepath.Base(dir))
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

// uwpFolderToPFN converts a WindowsApps install folder name into the Package
// Family Name used under LOCALAPPDATA\Packages.
//
// Input  : "5319275A.WhatsAppDesktop_2.2615.101.0_x64__cv1g1gvanyjgm"
// Output : "5319275A.WhatsAppDesktop_cv1g1gvanyjgm"
//
// Rule: take the underscore-separated tokens, keep the first (Name) and the
// last (PublisherHash); discard middle tokens (Version, Arch, optional resource).
// If the folder name doesn't contain "__" (already a PFN), return as-is.
func uwpFolderToPFN(folder string) string {
	if folder == "" {
		return ""
	}
	// Already a PFN form (Name_Hash, no double underscore separator)?
	if !strings.Contains(folder, "__") {
		// Validate it has at least Name_Hash.
		if strings.Count(folder, "_") >= 1 {
			return folder
		}
		return ""
	}
	// Install-folder form: Name_Version_Arch[_Resource]__PublisherHash
	idx := strings.LastIndex(folder, "__")
	if idx < 0 {
		return folder
	}
	hash := folder[idx+2:]
	head := folder[:idx]
	// First underscore-separated token of head is the Name.
	if cut := strings.Index(head, "_"); cut >= 0 {
		return head[:cut] + "_" + hash
	}
	return head + "_" + hash
}

// probeUDF Lstat's a candidate path and returns a UDFInfo with Exists set
// accordingly. Lstat (not Stat) is used so symlinks do NOT count as "exists"
// without the caller explicitly opting in (T-03-07, V12 ASVS).
func probeUDF(path, source string) UDFInfo {
	info := UDFInfo{Path: path, Source: source}
	st, err := os.Lstat(path)
	if err == nil && st.IsDir() {
		info.Exists = true
	}
	return info
}

// hasDotDot returns true if p contains a ".." path segment after cleaning.
func hasDotDot(p string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}
