package plugin

import (
	"fmt"
	"slices"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

// builtinAdapter wraps existing unravel analyzers behind the Analyzer interface.
// Each adapter declares the file types it handles. The AnalyzeFunc and ExtractFunc
// fields are wired at registration time to call the real analysis logic.
type builtinAdapter struct {
	name        string
	version     string
	description string
	types       []detect.FileType
	analyzeFunc func(path string, opts AnalyzeOpts) (any, error)
	extractFunc func(path string, outputDir string) error
}

func (b *builtinAdapter) Name() string        { return b.name }
func (b *builtinAdapter) Version() string     { return b.version }
func (b *builtinAdapter) Description() string { return b.description }

func (b *builtinAdapter) SupportedTypes() []detect.FileType {
	return b.types
}

func (b *builtinAdapter) CanHandle(_ string, result *detect.DetectResult) bool {
	if result == nil {
		return false
	}
	return slices.Contains(b.types, result.FileType)
}

func (b *builtinAdapter) Analyze(path string, opts AnalyzeOpts) (any, error) {
	if b.analyzeFunc != nil {
		return b.analyzeFunc(path, opts)
	}
	return nil, fmt.Errorf("plugin %q: analyze not implemented", b.name)
}

func (b *builtinAdapter) Extract(path string, outputDir string) error {
	if b.extractFunc != nil {
		return b.extractFunc(path, outputDir)
	}
	return fmt.Errorf("plugin %q: extract not implemented", b.name)
}

// BuiltinDef defines a built-in analyzer for registration.
type BuiltinDef struct {
	Name        string
	Version     string
	Description string
	Types       []detect.FileType
	AnalyzeFunc func(path string, opts AnalyzeOpts) (any, error)
	ExtractFunc func(path string, outputDir string) error
}

// RegisterBuiltin registers a single built-in analyzer with the given registry.
func RegisterBuiltin(r *Registry, def BuiltinDef) error {
	return r.Register(&builtinAdapter{
		name:        def.Name,
		version:     def.Version,
		description: def.Description,
		types:       def.Types,
		analyzeFunc: def.AnalyzeFunc,
		extractFunc: def.ExtractFunc,
	})
}

// builtins defines the built-in analyzer adapters with types only.
// AnalyzeFunc/ExtractFunc are nil until wired by the application.
var builtins = []BuiltinDef{
	{
		Name:        "android",
		Version:     "0.1.0",
		Description: "Android APK/AAB/XAPK analysis",
		Types:       []detect.FileType{detect.TypeAPK, detect.TypeAAB, detect.TypeXAPK, detect.TypeAPKS, detect.TypeAPKM},
	},
	{
		Name:        "ios",
		Version:     "0.1.0",
		Description: "iOS IPA application analysis",
		Types:       []detect.FileType{detect.TypeIPA},
	},
	{
		Name:        "npm",
		Version:     "0.1.0",
		Description: "NPM package analysis",
		Types:       []detect.FileType{detect.TypeNPMPackage, detect.TypeNodeModule, detect.TypeMCPServer},
	},
	{
		Name:        "java",
		Version:     "0.1.0",
		Description: "Java archive analysis (JAR/WAR/EAR)",
		Types:       []detect.FileType{detect.TypeJAR, detect.TypeWAR, detect.TypeEAR, detect.TypeJavaClass},
	},
	{
		Name:        "electron",
		Version:     "0.1.0",
		Description: "Electron application analysis",
		Types:       []detect.FileType{detect.TypeElectronApp, detect.TypeASAR},
	},
	{
		Name:        "tauri",
		Version:     "0.1.0",
		Description: "Tauri application analysis",
		Types:       []detect.FileType{detect.TypeTauriApp},
	},
	{
		Name:        "msi",
		Version:     "0.1.0",
		Description: "Windows MSI/MSIX installer analysis",
		Types:       []detect.FileType{detect.TypeMSI, detect.TypeMSIX},
	},
	{
		Name:        "deb",
		Version:     "0.1.0",
		Description: "Debian package analysis",
		Types:       []detect.FileType{detect.TypeDEB},
	},
	{
		Name:        "rpm",
		Version:     "0.1.0",
		Description: "RPM package analysis",
		Types:       []detect.FileType{detect.TypeRPM},
	},
	{
		Name:        "binary",
		Version:     "0.1.0",
		Description: "PE/ELF/Mach-O binary analysis",
		Types:       []detect.FileType{detect.TypePE, detect.TypeELF, detect.TypeMachO, detect.TypeMachOFat, detect.TypeGoBinary, detect.TypeUPXPacked},
	},
	{
		Name:        "packages",
		Version:     "0.1.0",
		Description: "NSIS and Advanced Installer analysis",
		Types:       []detect.FileType{detect.TypeNSIS, detect.TypeAdvancedInstaller},
	},
	{
		Name:        "web",
		Version:     "0.1.0",
		Description: "JavaScript, source maps, browser extensions",
		Types:       []detect.FileType{detect.TypeJavaScript, detect.TypeSourceMap, detect.TypeBrowserExtPkg},
	},
	{
		Name:        "data",
		Version:     "0.1.0",
		Description: "LevelDB and Chromium cache analysis",
		Types:       []detect.FileType{detect.TypeLevelDB, detect.TypeChromiumCache},
	},
}

// RegisterBuiltins registers all built-in analyzers with the given registry.
func RegisterBuiltins(r *Registry) {
	for _, def := range builtins {
		if err := RegisterBuiltin(r, def); err != nil {
			panic(fmt.Sprintf("register builtin %q: %v", def.Name, err))
		}
	}
}
