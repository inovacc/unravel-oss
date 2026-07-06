/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	javabeautify "github.com/inovacc/unravel-oss/pkg/java/beautify"
)

// JavaClassDisplay holds metadata for a single .class file.
type JavaClassDisplay struct {
	ClassName        string
	JavaVersion      string
	AccessFlags      string
	SuperClass       string
	Interfaces       []string
	FieldCount       int
	MethodCount      int
	SourceFile       string
	ConstantPoolSize int
}

// JavaArchiveDisplay holds metadata for a JAR/WAR/EAR archive.
type JavaArchiveDisplay struct {
	Type              string // JAR, WAR, EAR
	Path              string
	ClassCount        int
	JavaCount         int // .java files
	NestedJARs        []string
	ManifestMainClass string
	ManifestVersion   string
	SpringBoot        bool
	HasWebXML         bool
	HasAppXML         bool
	HasPOM            bool
	Dependencies      []string // from POM
}

// JavaDecompileSummary holds decompilation results.
type JavaDecompileSummary struct {
	TotalClasses int
	Decompiled   int
	Errors       int
	OutputDir    string
	ErrorDetails []string
}

// JavaManifestDisplay holds MANIFEST.MF and descriptor contents.
type JavaManifestDisplay struct {
	MainClass       string
	ClassPath       string
	ManifestVersion string
	Entries         map[string]string // all manifest entries
	WebXML          *WebXMLDisplay
	AppXML          *AppXMLDisplay
	POM             *POMDisplay
}

// WebXMLDisplay holds web.xml descriptor info.
type WebXMLDisplay struct {
	DisplayName string
	Servlets    []string
	Filters     []string
	Listeners   []string
}

// AppXMLDisplay holds application.xml descriptor info.
type AppXMLDisplay struct {
	DisplayName string
	Modules     []string
}

// POMDisplay holds pom.xml metadata.
type POMDisplay struct {
	GroupID      string
	ArtifactID   string
	Version      string
	Dependencies []string
}

// PrintJavaClassInfo displays metadata for a single .class file.
func PrintJavaClassInfo(info *JavaClassDisplay) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  JAVA CLASS ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Class: %-*s║\n", w-8, Truncate(info.ClassName, w-9))
	fmt.Printf("╠%s╣\n", border)

	fmt.Printf("║ %-*s║\n", w-1, "CLASS METADATA")

	if info.JavaVersion != "" {
		fmt.Printf("║   Java Version:    %-*s║\n", w-21, info.JavaVersion)
	}

	if info.AccessFlags != "" {
		fmt.Printf("║   Access Flags:    %-*s║\n", w-21, Truncate(info.AccessFlags, w-22))
	}

	if info.SuperClass != "" {
		fmt.Printf("║   Super Class:     %-*s║\n", w-21, Truncate(info.SuperClass, w-22))
	}

	if info.SourceFile != "" {
		fmt.Printf("║   Source File:     %-*s║\n", w-21, Truncate(info.SourceFile, w-22))
	}

	fmt.Printf("║   Constant Pool:   %-*d║\n", w-21, info.ConstantPoolSize)
	fmt.Printf("║   Fields:          %-*d║\n", w-21, info.FieldCount)
	fmt.Printf("║   Methods:         %-*d║\n", w-21, info.MethodCount)

	// Interfaces
	if len(info.Interfaces) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("INTERFACES (%d)", len(info.Interfaces)))

		for _, iface := range info.Interfaces {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(iface, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintJavaArchiveInfo displays metadata for a JAR/WAR/EAR archive.
func PrintJavaArchiveInfo(info *JavaArchiveDisplay) {
	w := 66
	border := strings.Repeat("═", w)

	title := fmt.Sprintf("  %s ARCHIVE ANALYSIS", info.Type)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, title)
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, Truncate(info.Path, w-8))
	fmt.Printf("║ Type: %-*s║\n", w-7, info.Type)
	fmt.Printf("╠%s╣\n", border)

	// Contents
	fmt.Printf("║ %-*s║\n", w-1, "CONTENTS")
	fmt.Printf("║   Classes:    %-*d║\n", w-16, info.ClassCount)

	if info.JavaCount > 0 {
		fmt.Printf("║   Sources:    %-*d║\n", w-16, info.JavaCount)
	}

	if len(info.NestedJARs) > 0 {
		fmt.Printf("║   Nested JARs:%-*d║\n", w-16, len(info.NestedJARs))
	}

	// Manifest
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "MANIFEST")

	if info.ManifestMainClass != "" {
		fmt.Printf("║   Main-Class: %-*s║\n", w-16, Truncate(info.ManifestMainClass, w-17))
	}

	if info.ManifestVersion != "" {
		fmt.Printf("║   Version:    %-*s║\n", w-16, info.ManifestVersion)
	}

	// Features
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "FEATURES")
	fmt.Printf("║   Spring Boot: %-*s║\n", w-17, BoolYesNo(info.SpringBoot))
	fmt.Printf("║   web.xml:     %-*s║\n", w-17, BoolYesNo(info.HasWebXML))
	fmt.Printf("║   app.xml:     %-*s║\n", w-17, BoolYesNo(info.HasAppXML))
	fmt.Printf("║   pom.xml:     %-*s║\n", w-17, BoolYesNo(info.HasPOM))

	// Nested JARs
	if len(info.NestedJARs) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("NESTED JARS (%d)", len(info.NestedJARs)))

		for _, jar := range info.NestedJARs {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(jar, w-4))
		}
	}

	// Dependencies
	if len(info.Dependencies) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("DEPENDENCIES (%d)", len(info.Dependencies)))

		for _, dep := range info.Dependencies {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(dep, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintJavaDecompileSummary shows decompilation results.
func PrintJavaDecompileSummary(summary *JavaDecompileSummary) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  JAVA DECOMPILATION SUMMARY")
	fmt.Printf("╠%s╣\n", border)

	fmt.Printf("║ Total Classes: %-*d║\n", w-16, summary.TotalClasses)
	fmt.Printf("║ Decompiled:    %-*d║\n", w-16, summary.Decompiled)
	fmt.Printf("║ Errors:        %-*d║\n", w-16, summary.Errors)
	fmt.Printf("║ Output:        %-*s║\n", w-16, Truncate(summary.OutputDir, w-17))

	if summary.TotalClasses > 0 {
		pct := float64(summary.Decompiled) / float64(summary.TotalClasses) * 100
		fmt.Printf("║ Success Rate:  %-*.1f%%║\n", w-17, pct)
	}

	// Error details
	if len(summary.ErrorDetails) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("ERRORS (%d)", len(summary.ErrorDetails)))

		for _, e := range summary.ErrorDetails {
			for _, line := range WrapText(e, w-5) {
				fmt.Printf("║   %-*s║\n", w-3, line)
			}
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintJavaBeautifyReport prints a structured summary of a Java
// beautification run (06-04 Task 1, mirrors Phase 5 dotnet style).
func PrintJavaBeautifyReport(report *javabeautify.BeautifyReport, w io.Writer) {
	if report == nil {
		_, _ = fmt.Fprintln(w, "java beautify: nil report")
		return
	}
	width := 66
	border := strings.Repeat("=", width)

	fmt.Fprintf(w, "%s\n", border)
	fmt.Fprintf(w, "  JAVA BEAUTIFY REPORT\n")
	fmt.Fprintf(w, "%s\n", border)
	fmt.Fprintf(w, "  Run ID:         %s\n", report.RunID)
	fmt.Fprintf(w, "  Output Dir:     %s\n", Truncate(report.OutputDir, width-18))
	fmt.Fprintf(w, "  Raw Tree:       %s\n", Truncate(report.RawTree, width-18))
	if report.BeautifiedTree != "" {
		fmt.Fprintf(w, "  Beautified:     %s\n", Truncate(report.BeautifiedTree, width-18))
	}

	totalFiles := 0
	beautifiedJars := 0
	for _, j := range report.Jars {
		totalFiles += j.FileCount
		if j.Beautified {
			beautifiedJars++
		}
	}
	fmt.Fprintf(w, "  JARs:           %d (beautified: %d)\n", len(report.Jars), beautifiedJars)
	fmt.Fprintf(w, "  Files:          %d total .java\n", totalFiles)

	if len(report.Errors) > 0 {
		fmt.Fprintf(w, "  Errors:         %d\n", len(report.Errors))
		for _, e := range report.Errors {
			fmt.Fprintf(w, "    - %s\n", Truncate(e, width-6))
		}
	}
	fmt.Fprintf(w, "%s\n", border)
}

// PrintJavaManifest displays MANIFEST.MF and descriptor contents.
func PrintJavaManifest(info *JavaManifestDisplay) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  JAVA MANIFEST & DESCRIPTORS")
	fmt.Printf("╠%s╣\n", border)

	// MANIFEST.MF
	fmt.Printf("║ %-*s║\n", w-1, "MANIFEST.MF")

	if info.ManifestVersion != "" {
		fmt.Printf("║   Manifest-Version: %-*s║\n", w-22, info.ManifestVersion)
	}

	if info.MainClass != "" {
		fmt.Printf("║   Main-Class:       %-*s║\n", w-22, Truncate(info.MainClass, w-23))
	}

	if info.ClassPath != "" {
		for _, line := range WrapText(info.ClassPath, w-24) {
			fmt.Printf("║   Class-Path:       %-*s║\n", w-22, line)
		}
	}

	// Additional manifest entries
	if len(info.Entries) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("MANIFEST ENTRIES (%d)", len(info.Entries)))

		// Sort keys for deterministic output
		keys := make([]string, 0, len(info.Entries))
		for k := range info.Entries {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			v := info.Entries[k]
			line := fmt.Sprintf("%s: %s", k, v)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	// web.xml
	if info.WebXML != nil {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "WEB.XML (web.xml)")

		if info.WebXML.DisplayName != "" {
			fmt.Printf("║   Display Name: %-*s║\n", w-18, Truncate(info.WebXML.DisplayName, w-19))
		}

		if len(info.WebXML.Servlets) > 0 {
			fmt.Printf("║   Servlets (%d):\n", len(info.WebXML.Servlets))

			for _, s := range info.WebXML.Servlets {
				fmt.Printf("║     %-*s║\n", w-5, Truncate(s, w-6))
			}
		}

		if len(info.WebXML.Filters) > 0 {
			fmt.Printf("║   Filters (%d):\n", len(info.WebXML.Filters))

			for _, f := range info.WebXML.Filters {
				fmt.Printf("║     %-*s║\n", w-5, Truncate(f, w-6))
			}
		}

		if len(info.WebXML.Listeners) > 0 {
			fmt.Printf("║   Listeners (%d):\n", len(info.WebXML.Listeners))

			for _, l := range info.WebXML.Listeners {
				fmt.Printf("║     %-*s║\n", w-5, Truncate(l, w-6))
			}
		}
	}

	// application.xml
	if info.AppXML != nil {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "APPLICATION.XML (application.xml)")

		if info.AppXML.DisplayName != "" {
			fmt.Printf("║   Display Name: %-*s║\n", w-18, Truncate(info.AppXML.DisplayName, w-19))
		}

		if len(info.AppXML.Modules) > 0 {
			fmt.Printf("║   Modules (%d):\n", len(info.AppXML.Modules))

			for _, m := range info.AppXML.Modules {
				fmt.Printf("║     %-*s║\n", w-5, Truncate(m, w-6))
			}
		}
	}

	// POM
	if info.POM != nil {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "POM (pom.xml)")

		if info.POM.GroupID != "" {
			fmt.Printf("║   Group ID:    %-*s║\n", w-17, Truncate(info.POM.GroupID, w-18))
		}

		if info.POM.ArtifactID != "" {
			fmt.Printf("║   Artifact ID: %-*s║\n", w-17, Truncate(info.POM.ArtifactID, w-18))
		}

		if info.POM.Version != "" {
			fmt.Printf("║   Version:     %-*s║\n", w-17, info.POM.Version)
		}

		if len(info.POM.Dependencies) > 0 {
			fmt.Printf("║   Dependencies (%d):\n", len(info.POM.Dependencies))

			for _, dep := range info.POM.Dependencies {
				fmt.Printf("║     %-*s║\n", w-5, Truncate(dep, w-6))
			}
		}
	}

	fmt.Printf("╚%s╝\n", border)
}
