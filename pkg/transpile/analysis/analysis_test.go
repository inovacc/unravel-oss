package analysis

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	// Register language plugins for DetectImports / ForExtension.
	_ "github.com/inovacc/unravel-oss/pkg/transpile/languages/python"
)

func TestAnalyzer_Analyze_Basic(t *testing.T) {
	dir := t.TempDir()

	// Create a small C++ project
	writeTestFile(t, dir, "main.cpp", `#include <iostream>
#include "util.h"

// Main entry point
int main() {
    std::cout << "Hello" << std::endl;
    return 0;
}
`)

	writeTestFile(t, dir, "util.h", `#pragma once

/*
 * Utility functions
 */
void helper();
int add(int a, int b);
`)

	writeTestFile(t, dir, "util.cpp", `#include "util.h"

void helper() {}

int add(int a, int b) {
    return a + b;
}
`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	analyzer := NewAnalyzer(dir, logger, Options{
		IncludeGraph: true,
		Symbols:      true,
	})

	report, err := analyzer.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if report.TotalFiles != 3 {
		t.Errorf("TotalFiles = %d, want 3", report.TotalFiles)
	}

	if report.TotalLOC.Lines == 0 {
		t.Error("TotalLOC.Lines should be > 0")
	}

	if report.TotalLOC.Code == 0 {
		t.Error("TotalLOC.Code should be > 0")
	}

	if report.TotalLOC.Comments == 0 {
		t.Error("TotalLOC.Comments should be > 0")
	}

	// Check libraries
	if len(report.Libraries) == 0 {
		t.Error("expected at least one library detected")
	}

	// Check include graph
	if report.IncludeGraph == nil {
		t.Fatal("IncludeGraph should not be nil")
	}

	if len(report.IncludeGraph.Nodes) != 3 {
		t.Errorf("include graph nodes = %d, want 3", len(report.IncludeGraph.Nodes))
	}

	// Check symbols
	if report.Symbols == nil {
		t.Fatal("Symbols should not be nil")
	}

	// Check hierarchy
	if report.Hierarchy == nil {
		t.Fatal("Hierarchy should not be nil")
	}

	// Check largest files
	if len(report.LargestFiles) != 3 {
		t.Errorf("LargestFiles = %d, want 3", len(report.LargestFiles))
	}

	// Verify largest files are sorted descending
	if len(report.LargestFiles) > 1 {
		for i := 1; i < len(report.LargestFiles); i++ {
			if report.LargestFiles[i].LOC.Code > report.LargestFiles[i-1].LOC.Code {
				t.Error("LargestFiles not sorted by code lines descending")
			}
		}
	}
}

func TestAnalyzer_Analyze_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	analyzer := NewAnalyzer(dir, logger, Options{})

	report, err := analyzer.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if report.TotalFiles != 0 {
		t.Errorf("TotalFiles = %d, want 0", report.TotalFiles)
	}
}

func TestAnalyzer_Analyze_WithClasses(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "shape.h", `class Shape {
public:
    virtual double area() = 0;
    virtual ~Shape() {}
};

class Circle : public Shape {
public:
    Circle(double r) : radius(r) {}
    double area();
private:
    double radius;
};
`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	analyzer := NewAnalyzer(dir, logger, Options{Symbols: true})

	report, err := analyzer.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if report.Symbols == nil {
		t.Fatal("Symbols should not be nil")
	}

	if len(report.Symbols.Classes) < 2 {
		t.Errorf("classes = %d, want >= 2", len(report.Symbols.Classes))
	}

	if report.Hierarchy == nil {
		t.Fatal("Hierarchy should not be nil")
	}
}

func TestAnalyzer_Analyze_WithSubdirs(t *testing.T) {
	dir := t.TempDir()

	subDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeTestFile(t, dir, "main.cpp", "int main() {}")
	writeTestFile(t, subDir, "lib.cpp", "void lib() {}")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	analyzer := NewAnalyzer(dir, logger, Options{})

	report, err := analyzer.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if report.TotalFiles != 2 {
		t.Errorf("TotalFiles = %d, want 2", report.TotalFiles)
	}
}

func TestAnalyzer_Analyze_Python_Basic(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "models.py", `from dataclasses import dataclass
from typing import Optional
import json

@dataclass
class User:
    name: str
    age: int
    email: Optional[str] = None

    def greet(self) -> str:
        return f"Hello, {self.name}"

class Admin(User):
    role: str = "admin"

    def permissions(self) -> list[str]:
        return ["read", "write", "delete"]
`)

	writeTestFile(t, dir, "utils.py", `import os
import logging

logger = logging.getLogger(__name__)

def read_config(path: str) -> dict:
    """Read a JSON config file."""
    with open(path) as f:
        return json.load(f)

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	analyzer := NewAnalyzer(dir, logger, Options{
		IncludeGraph: true,
		Symbols:      true,
	})

	report, err := analyzer.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if report.TotalFiles != 2 {
		t.Errorf("TotalFiles = %d, want 2", report.TotalFiles)
	}

	if report.TotalLOC.Code == 0 {
		t.Error("expected code lines > 0")
	}

	// Check Python import graph
	if report.PyImportGraph == nil {
		t.Fatal("PyImportGraph should not be nil for Python files")
	}

	if len(report.PyImportGraph.Nodes) < 2 {
		t.Errorf("import graph nodes = %d, want >= 2", len(report.PyImportGraph.Nodes))
	}

	// Check Python symbols
	if report.PySymbols == nil {
		t.Fatal("PySymbols should not be nil")
	}

	if len(report.PySymbols.Classes) < 2 {
		t.Errorf("classes = %d, want >= 2 (User, Admin)", len(report.PySymbols.Classes))
	}

	if len(report.PySymbols.Functions) < 1 {
		t.Errorf("functions = %d, want >= 1", len(report.PySymbols.Functions))
	}

	// Check Python hierarchy
	if report.PyHierarchy == nil {
		t.Fatal("PyHierarchy should not be nil")
	}

	// C++ fields should be nil for Python-only project
	if report.IncludeGraph != nil {
		t.Error("C++ IncludeGraph should be nil for Python-only project")
	}

	if report.Symbols != nil {
		t.Error("C++ Symbols should be nil for Python-only project")
	}
}

func TestAnalyzer_Analyze_Python_Frameworks(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "app.py", `from flask import Flask, jsonify
from sqlalchemy import create_engine
import redis

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})
`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	analyzer := NewAnalyzer(dir, logger, Options{})

	report, err := analyzer.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(report.PyFrameworks) == 0 {
		t.Error("expected Python frameworks to be detected (flask, sqlalchemy, redis)")
	}

	// Check specific frameworks
	found := make(map[string]bool)
	for _, fw := range report.PyFrameworks {
		found[fw] = true
	}

	for _, want := range []string{"Flask", "SQLAlchemy", "Redis"} {
		if !found[want] {
			t.Errorf("expected framework %q to be detected, got %v", want, report.PyFrameworks)
		}
	}
}

func TestAnalyzer_Analyze_Python_MixedWithCpp(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "main.cpp", `#include <iostream>
int main() { return 0; }
`)

	writeTestFile(t, dir, "script.py", `import os

def run():
    print("hello")
`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	analyzer := NewAnalyzer(dir, logger, Options{
		IncludeGraph: true,
		Symbols:      true,
	})

	report, err := analyzer.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if report.TotalFiles != 2 {
		t.Errorf("TotalFiles = %d, want 2", report.TotalFiles)
	}

	// Both C++ and Python analysis should run
	if report.IncludeGraph == nil {
		t.Error("C++ IncludeGraph should be set for mixed project")
	}

	if report.PyImportGraph == nil {
		t.Error("Python ImportGraph should be set for mixed project")
	}
}

func TestAnalyzer_Analyze_WithoutOptionalSteps(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "main.cpp", "int main() { return 0; }")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// IncludeGraph and Symbols disabled
	analyzer := NewAnalyzer(dir, logger, Options{})

	report, err := analyzer.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if report.IncludeGraph != nil {
		t.Error("IncludeGraph should be nil when not requested")
	}

	if report.Symbols != nil {
		t.Error("Symbols should be nil when not requested")
	}

	if report.Hierarchy != nil {
		t.Error("Hierarchy should be nil when not requested")
	}
}
