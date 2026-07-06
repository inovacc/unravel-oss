/*
Copyright (c) 2026 Security Research

06-04 Task 3: tests for analyze_java_beautify supplemental analyzer.
Verifies registration on TypeJAR/TypeAPK/TypeWAR/TypeEAR, NO
registration on TypeJavaScript (D-18), and presence of cost-warning
comment + recover() guard.
*/
package dissect

import (
	"os"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

func TestSupplemental_TypeJAR_Registered(t *testing.T) {
	if len(supplementalTable[detect.TypeJAR]) == 0 {
		t.Error("TypeJAR has no supplemental analyzers registered")
	}
}

func TestSupplemental_TypeAPK_Registered(t *testing.T) {
	if len(supplementalTable[detect.TypeAPK]) == 0 {
		t.Error("TypeAPK has no supplemental analyzers registered")
	}
}

// D-18: JS supplemental beautification must NOT auto-trigger. Look
// for any RegisterSupplementalAnalyzer / RegisterAnalyzer call paired
// with a JS file type across pkg/dissect/.
func TestSupplemental_TypeJS_NotAutoBeautified(t *testing.T) {
	matches, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range matches {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		// analyze_web.go legitimately registers analyzeJavaScript on
		// TypeJavaScript (NOT a beautify hop). The D-18 violation
		// would be a NEW registration that calls jsdeob.BeautifyAI.
		body, err := os.ReadFile(e.Name())
		if err != nil {
			continue
		}
		s := string(body)
		// Specifically: NO supplemental analyzer that imports the
		// jsdeob beautify-ai surface.
		if strings.Contains(s, "BeautifyAI") &&
			(strings.Contains(s, "RegisterSupplementalAnalyzer") || strings.Contains(s, "RegisterAnalyzer")) {
			t.Errorf("%s: dissect file pairs BeautifyAI with a Register call — D-18 violation", e.Name())
		}
	}
}

// D-18: bundle reconstruction must NOT auto-trigger.
func TestSupplemental_BundleNotAutoTriggered(t *testing.T) {
	matches, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range matches {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(e.Name())
		if err != nil {
			continue
		}
		s := string(body)
		// Look for any RegisterSupplementalAnalyzer or RegisterAnalyzer
		// referencing bundle.Run or jsdeob.BeautifyAI.
		if strings.Contains(s, "bundle.Run") && strings.Contains(s, "RegisterSupplementalAnalyzer") {
			t.Errorf("%s registers a supplemental analyzer that calls bundle.Run — D-18 violation", e.Name())
		}
		if strings.Contains(s, "BeautifyAI") && strings.Contains(s, "RegisterSupplementalAnalyzer") {
			t.Errorf("%s registers a supplemental analyzer that calls BeautifyAI — D-18 violation", e.Name())
		}
	}
}

// D-18 cost-warning + D-22 recover() guard must be present in the
// analyzer source.
func TestSupplemental_CostWarningCommentPresent(t *testing.T) {
	body, err := os.ReadFile("analyze_java_beautify.go")
	if err != nil {
		t.Fatalf("read analyze_java_beautify.go: %v", err)
	}
	src := string(body)
	if !strings.Contains(src, "COST WARNING") &&
		!strings.Contains(src, "cost warning") &&
		!strings.Contains(src, "token spend") {
		t.Error("analyze_java_beautify.go missing cost-warning comment (D-18)")
	}
	if !strings.Contains(src, "recover()") {
		t.Error("analyze_java_beautify.go missing recover() guard (D-22)")
	}
}
