package typescript

import (
	"context"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages"
)

func TestRegisteredForExtensions(t *testing.T) {
	for _, ext := range []string{".ts", ".tsx", ".mts", ".cts"} {
		lang, err := languages.ForFile("example" + ext)
		if err != nil {
			t.Fatalf("ForFile(%q): %v", ext, err)
		}

		if lang.Name() != "TypeScript" {
			t.Fatalf("ForFile(%q) = %q, want TypeScript", ext, lang.Name())
		}
	}
}

func TestDetectImports(t *testing.T) {
	src := `
import express from 'express';
import { z } from "zod";
import * as fs from 'node:fs';
import './local-only';
const ax = require('axios');
import type { Foo } from '@nestjs/common';
const lazy = await import("rxjs");
`

	got := New().DetectImports(src)

	want := map[string]bool{
		"express": true,
		"zod":     true,
		"fs":      true,
		"axios":   true,
		"nestjs":  true,
		"rxjs":    true,
	}

	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected import %q", g)
		}

		delete(want, g)
	}

	for missing := range want {
		t.Errorf("missing import %q (got %v)", missing, got)
	}

	for _, g := range got {
		if strings.HasPrefix(g, ".") || strings.HasPrefix(g, "/") {
			t.Errorf("relative import %q should be skipped", g)
		}
	}
}

func TestSystemPromptForWithoutRules(t *testing.T) {
	l := New()

	prompt, err := l.SystemPromptFor(context.Background(), "import express from 'express';")
	if err != nil {
		t.Fatalf("SystemPromptFor: %v", err)
	}

	if !strings.Contains(prompt, "TypeScript-to-Go") {
		t.Fatalf("base system prompt missing")
	}
}

func TestRawPrompt(t *testing.T) {
	out := New().ConvertRawPrompt("a.ts", "const x = 1;")
	if !strings.Contains(out, "a.ts") || !strings.Contains(out, "const x = 1;") {
		t.Fatalf("raw prompt missing filename or source: %q", out)
	}
}
