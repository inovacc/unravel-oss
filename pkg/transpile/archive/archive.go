// Package archive handles detection, extraction, and analysis of Java archives
// (JAR, WAR, EAR) for the togo converter pipeline.
package archive

import (
	"log/slog"
	"net/http"
	"time"
)

// ArchiveType identifies the kind of Java archive.
type ArchiveType int

const (
	ArchiveUnknown ArchiveType = iota
	ArchiveJAR
	ArchiveWAR
	ArchiveEAR
)

// String returns the display name for the archive type.
func (t ArchiveType) String() string {
	switch t {
	case ArchiveJAR:
		return "JAR"
	case ArchiveWAR:
		return "WAR"
	case ArchiveEAR:
		return "EAR"
	default:
		return "Unknown"
	}
}

// ArchiveInfo holds all metadata and file listings extracted from a Java archive.
type ArchiveInfo struct {
	Type         ArchiveType    `json:"type"`
	Path         string         `json:"path"`        // original archive path
	ExtractDir   string         `json:"extract_dir"` // temp directory with extracted contents
	Manifest     *ManifestInfo  `json:"manifest,omitempty"`
	WebXML       *WebXMLInfo    `json:"web_xml,omitempty"`
	AppXML       *AppXMLInfo    `json:"app_xml,omitempty"`
	POM          *POMInfo       `json:"pom,omitempty"`
	SpringConfig *SpringConfig  `json:"spring_config,omitempty"`
	JavaFiles    []string       `json:"java_files,omitempty"`  // .java paths (relative to extract dir)
	ClassFiles   []string       `json:"class_files,omitempty"` // .class paths needing decompilation
	NestedJARs   []string       `json:"nested_jars,omitempty"` // lib/*.jar paths
	Patterns     *PatternReport `json:"patterns,omitempty"`
}

// Extractor handles archive detection, extraction, and decompilation.
type Extractor struct {
	decompilerPath      string
	useNativeDecompiler bool
	logger              *slog.Logger
	httpClient          *http.Client
	maxNestedDepth      int
}

// Option configures the Extractor.
type Option func(*Extractor)

// WithDecompiler sets the path to a Java decompiler JAR (e.g., cfr.jar).
func WithDecompiler(path string) Option {
	return func(e *Extractor) {
		e.decompilerPath = path
	}
}

// WithNativeDecompiler enables the built-in Go decompiler (no Java required).
// When enabled, the native decompiler is used as the primary decompilation method.
// External JAR decompilers are used as fallback if the native decompiler fails.
func WithNativeDecompiler() Option {
	return func(e *Extractor) {
		e.useNativeDecompiler = true
	}
}

// New creates a new Extractor with the given logger and options.
func New(logger *slog.Logger, opts ...Option) *Extractor {
	e := &Extractor{
		logger:              logger,
		httpClient:          &http.Client{Timeout: 30 * time.Second},
		maxNestedDepth:      2,
		useNativeDecompiler: true, // native decompiler enabled by default
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}
