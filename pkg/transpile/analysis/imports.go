package analysis

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages"
)

// ImportGraph represents the import dependency graph of a Python codebase.
type ImportGraph struct {
	Nodes map[string]*ImportNode `json:"nodes"` // keyed by relative path
}

// ImportNode represents a file in the import graph.
type ImportNode struct {
	File       *SourceFile `json:"file"`
	Imports    []string    `json:"imports"`               // raw import names
	ImportedBy []string    `json:"imported_by,omitempty"` // relative paths of files importing this module
	LocalDeps  []string    `json:"local_deps,omitempty"`  // resolved local module paths
	StdlibDeps []string    `json:"stdlib_deps,omitempty"` // standard library imports
	ThirdParty []string    `json:"third_party,omitempty"` // third-party package imports
	Frameworks []string    `json:"frameworks,omitempty"`  // detected framework names
}

// BuildImportGraph constructs an import dependency graph from Python source files.
// It resolves local imports via filename-to-module mapping and classifies remaining
// imports as stdlib or third-party.
func BuildImportGraph(pyFiles []*SourceFile, root string) *ImportGraph {
	graph := &ImportGraph{
		Nodes: make(map[string]*ImportNode, len(pyFiles)),
	}

	// Build module name to relative path mapping for local resolution.
	moduleToFile := make(map[string]string, len(pyFiles))
	for _, f := range pyFiles {
		modName := pathToModule(f.RelPath)
		if modName != "" {
			moduleToFile[modName] = f.RelPath
		}
	}

	lang, ok := languages.ForExtension(".py")
	if !ok {
		return graph
	}

	for _, f := range pyFiles {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}

		imports := lang.DetectImports(string(data))

		node := &ImportNode{
			File:    f,
			Imports: imports,
		}

		fwSeen := make(map[string]struct{})

		for _, imp := range imports {
			// Try local resolution
			if resolved := resolveImport(imp, moduleToFile); resolved != "" {
				node.LocalDeps = append(node.LocalDeps, resolved)
				continue
			}

			// Check if it's a framework
			if fw, ok := frameworkModules[imp]; ok {
				if _, seen := fwSeen[fw]; !seen {
					fwSeen[fw] = struct{}{}
					node.Frameworks = append(node.Frameworks, fw)
				}
			}

			// Classify as stdlib or third-party
			if isStdlib(imp) {
				node.StdlibDeps = append(node.StdlibDeps, imp)
			} else {
				node.ThirdParty = append(node.ThirdParty, imp)
			}
		}

		graph.Nodes[f.RelPath] = node
	}

	// Build reverse edges (ImportedBy)
	for relPath, node := range graph.Nodes {
		for _, dep := range node.LocalDeps {
			if target, ok := graph.Nodes[dep]; ok {
				target.ImportedBy = append(target.ImportedBy, relPath)
			}
		}
	}

	return graph
}

// DetectPythonFrameworks returns a deduplicated, sorted list of framework names
// detected across all Python files.
func DetectPythonFrameworks(files []*SourceFile) []string {
	lang, ok := languages.ForExtension(".py")
	if !ok {
		return nil
	}

	seen := make(map[string]struct{})

	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}

		imports := lang.DetectImports(string(data))
		for _, imp := range imports {
			if fw, ok := frameworkModules[imp]; ok {
				seen[fw] = struct{}{}
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	result := make([]string, 0, len(seen))
	for fw := range seen {
		result = append(result, fw)
	}

	sortStrings(result)

	return result
}

// DetectJavaFrameworks returns a deduplicated, sorted list of framework names
// detected across all Java files by scanning import statements.
func DetectJavaFrameworks(files []*SourceFile) []string {
	lang, ok := languages.ForExtension(".java")
	if !ok {
		return nil
	}

	seen := make(map[string]struct{})

	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}

		imports := lang.DetectImports(string(data))
		for _, imp := range imports {
			if fw, ok := javaFrameworkNames[imp]; ok {
				seen[fw] = struct{}{}
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	result := make([]string, 0, len(seen))
	for fw := range seen {
		result = append(result, fw)
	}

	sortStrings(result)

	return result
}

// javaFrameworkNames maps Java rule names to their display names.
var javaFrameworkNames = map[string]string{
	"spring":       "Spring Framework",
	"junit":        "JUnit",
	"jackson":      "Jackson",
	"lombok":       "Lombok",
	"slf4j":        "SLF4J",
	"hibernate":    "Hibernate",
	"jpa":          "JPA",
	"mockito":      "Mockito",
	"guava":        "Google Guava",
	"commons_lang": "Apache Commons Lang",
	"commons_io":   "Apache Commons IO",
	"gson":         "Gson",
	"retrofit":     "Retrofit",
	"okhttp":       "OkHttp",
	"rxjava":       "RxJava",
	"netty":        "Netty",
	"kafka":        "Apache Kafka",
	"vertx":        "Vert.x",
	"testng":       "TestNG",
	"log4j":        "Log4j",
	"servlet":      "Java Servlet API",
	"ejb":          "Enterprise JavaBeans",
	"jndi":         "JNDI",
	"javaee":       "Java EE / Jakarta EE",
}

// resolveImport tries to find a local Python module matching the import name.
func resolveImport(importName string, moduleToFile map[string]string) string {
	// Direct match
	if relPath, ok := moduleToFile[importName]; ok {
		return relPath
	}

	// Try as package (import name could be a package with __init__.py)
	for modName, relPath := range moduleToFile {
		if strings.HasPrefix(modName, importName+".") {
			return relPath
		}
	}

	return ""
}

// pathToModule converts a relative file path to a Python module name.
func pathToModule(relPath string) string {
	if strings.HasSuffix(relPath, "__init__.py") {
		dir := filepath.Dir(relPath)
		if dir == "." {
			return ""
		}

		return strings.ReplaceAll(filepath.ToSlash(dir), "/", ".")
	}

	name := strings.TrimSuffix(relPath, ".py")
	name = filepath.ToSlash(name)

	return strings.ReplaceAll(name, "/", ".")
}

// isStdlib returns true if the import name is a Python standard library module.
func isStdlib(name string) bool {
	_, ok := stdlibModules[name]
	return ok
}

// stdlibModules is a set of Python 3.10+ standard library top-level module names.
var stdlibModules = map[string]struct{}{
	"abc": {}, "argparse": {}, "array": {}, "ast": {},
	"asyncio": {}, "atexit": {},
	"base64": {}, "binascii": {}, "bisect": {},
	"builtins": {}, "bz2": {},
	"calendar": {}, "cmath": {},
	"cmd": {}, "code": {}, "codecs": {}, "collections": {},
	"colorsys": {}, "compileall": {}, "concurrent": {}, "configparser": {},
	"contextlib": {}, "contextvars": {}, "copy": {},
	"csv": {}, "ctypes": {}, "curses": {},
	"dataclasses": {}, "datetime": {}, "dbm": {}, "decimal": {},
	"difflib": {}, "dis": {}, "doctest": {},
	"email": {}, "encodings": {}, "enum": {}, "errno": {},
	"faulthandler": {}, "filecmp": {}, "fileinput": {},
	"fnmatch": {}, "fractions": {}, "ftplib": {}, "functools": {},
	"gc": {}, "getopt": {}, "getpass": {}, "gettext": {}, "glob": {},
	"graphlib": {}, "gzip": {},
	"hashlib": {}, "heapq": {}, "hmac": {}, "html": {}, "http": {},
	"importlib": {}, "inspect": {}, "io": {}, "ipaddress": {}, "itertools": {},
	"json":      {},
	"keyword":   {},
	"linecache": {}, "locale": {}, "logging": {}, "lzma": {},
	"math": {}, "mimetypes": {}, "mmap": {}, "multiprocessing": {},
	"numbers":  {},
	"operator": {}, "optparse": {}, "os": {},
	"pathlib": {}, "pdb": {}, "platform": {}, "pprint": {},
	"profile": {}, "pstats": {},
	"queue":  {},
	"random": {}, "re": {}, "reprlib": {},
	"sched": {}, "secrets": {}, "select": {}, "selectors": {}, "shelve": {},
	"shlex": {}, "shutil": {}, "signal": {}, "site": {},
	"smtplib": {}, "socket": {}, "socketserver": {},
	"sqlite3": {}, "ssl": {}, "stat": {}, "statistics": {},
	"string": {}, "struct": {}, "subprocess": {},
	"symtable": {}, "sys": {}, "sysconfig": {},
	"tarfile": {}, "tempfile": {},
	"test": {}, "textwrap": {}, "threading": {}, "time": {},
	"timeit": {}, "tkinter": {}, "token": {}, "tokenize": {}, "tomllib": {},
	"trace": {}, "traceback": {}, "tracemalloc": {}, "types": {}, "typing": {},
	"unicodedata": {}, "unittest": {}, "urllib": {}, "uuid": {},
	"venv":     {},
	"warnings": {}, "weakref": {}, "webbrowser": {},
	"xml": {}, "xmlrpc": {},
	"zipfile": {}, "zipimport": {}, "zlib": {}, "zoneinfo": {},
}

// frameworkModules maps top-level import names to their framework display names.
var frameworkModules = map[string]string{
	"django":     "Django",
	"flask":      "Flask",
	"fastapi":    "FastAPI",
	"pytest":     "pytest",
	"celery":     "Celery",
	"sqlalchemy": "SQLAlchemy",
	"pydantic":   "Pydantic",
	"requests":   "Requests",
	"httpx":      "HTTPX",
	"aiohttp":    "aiohttp",
	"boto3":      "boto3",
	"redis":      "Redis",
	"docker":     "Docker",
	"grpc":       "gRPC",
	"uvicorn":    "Uvicorn",
	"click":      "Click",
	"jinja2":     "Jinja2",
	"websocket":  "WebSocket",
	"yaml":       "PyYAML",
	"toml":       "TOML",
	"numpy":      "NumPy",
	"pandas":     "Pandas",
	"scipy":      "SciPy",
	"sklearn":    "scikit-learn",
	"tensorflow": "TensorFlow",
	"torch":      "PyTorch",
	"matplotlib": "Matplotlib",
}
