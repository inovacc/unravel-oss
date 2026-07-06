package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildIncludeGraph_LocalIncludes(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "main.cpp", `#include "util.h"
#include <iostream>
int main() { return 0; }`)

	writeTestFile(t, dir, "util.h", `#pragma once
void util();`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "main.cpp"), RelPath: "main.cpp"},
		{Path: filepath.Join(dir, "util.h"), RelPath: "util.h"},
	}

	graph := BuildIncludeGraph(files, dir)

	if len(graph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(graph.Nodes))
	}

	mainNode := graph.Nodes["main.cpp"]
	if mainNode == nil {
		t.Fatal("main.cpp node not found")
	}

	if len(mainNode.Includes) != 2 {
		t.Errorf("main.cpp includes = %d, want 2", len(mainNode.Includes))
	}

	if len(mainNode.LocalDeps) != 1 {
		t.Errorf("main.cpp local deps = %d, want 1", len(mainNode.LocalDeps))
	}

	if len(mainNode.SystemDeps) != 1 {
		t.Errorf("main.cpp system deps = %d, want 1", len(mainNode.SystemDeps))
	}

	// util.h should have main.cpp in IncludedBy
	utilNode := graph.Nodes["util.h"]
	if utilNode == nil {
		t.Fatal("util.h node not found")
	}

	if len(utilNode.IncludedBy) != 1 {
		t.Errorf("util.h included_by = %d, want 1", len(utilNode.IncludedBy))
	}
}

func TestBuildIncludeGraph_LibraryDetection(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "app.cpp", `#include <vector>
#include <map>
#include <boost/asio.hpp>
void run() {}`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "app.cpp"), RelPath: "app.cpp"},
	}

	graph := BuildIncludeGraph(files, dir)

	node := graph.Nodes["app.cpp"]
	if node == nil {
		t.Fatal("app.cpp node not found")
	}

	libSet := make(map[string]bool)
	for _, lib := range node.Libraries {
		libSet[lib] = true
	}

	if !libSet["stl"] {
		t.Error("expected 'stl' library detection")
	}

	if !libSet["asio"] {
		t.Error("expected 'asio' library detection")
	}
}

func TestBuildIncludeGraph_Edges(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "a.cpp", `#include "b.h"
#include <iostream>`)
	writeTestFile(t, dir, "b.h", `#pragma once`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "a.cpp"), RelPath: "a.cpp"},
		{Path: filepath.Join(dir, "b.h"), RelPath: "b.h"},
	}

	graph := BuildIncludeGraph(files, dir)
	edges := graph.Edges()

	if len(edges) != 2 {
		t.Errorf("got %d edges, want 2", len(edges))
	}

	// Check that we have both a local and system edge
	hasLocal := false
	hasSystem := false

	for _, e := range edges {
		if e.IsSystem {
			hasSystem = true
		} else {
			hasLocal = true
		}
	}

	if !hasLocal {
		t.Error("expected at least one local include edge")
	}

	if !hasSystem {
		t.Error("expected at least one system include edge")
	}
}

func TestBuildIncludeGraph_SubdirIncludes(t *testing.T) {
	dir := t.TempDir()

	subDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeTestFile(t, subDir, "main.cpp", `#include "helper.h"
int main() {}`)

	writeTestFile(t, subDir, "helper.h", `#pragma once
void help();`)

	files := []*SourceFile{
		{Path: filepath.Join(subDir, "main.cpp"), RelPath: "src/main.cpp"},
		{Path: filepath.Join(subDir, "helper.h"), RelPath: "src/helper.h"},
	}

	graph := BuildIncludeGraph(files, dir)

	mainNode := graph.Nodes["src/main.cpp"]
	if mainNode == nil {
		t.Fatal("src/main.cpp node not found")
	}

	if len(mainNode.LocalDeps) != 1 {
		t.Errorf("local deps = %d, want 1", len(mainNode.LocalDeps))
	}
}
