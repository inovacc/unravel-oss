package converter

import (
	"strings"
	"testing"
)

// TestAssertGoParsesValid checks the syntactic compile gate (C7, Tier 1):
// well-formed Go source must pass the go/parser gate with no error.
func TestAssertGoParsesValid(t *testing.T) {
	const src = `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`

	if err := assertGoParses([]byte(src)); err != nil {
		t.Fatalf("assertGoParses rejected valid Go: %v", err)
	}
}

// TestAssertGoParsesInvalid is the heart of the C7 gate: deliberately broken
// codegen output (invalid Go) MUST be rejected, and the error MUST carry a
// source location so operators can find the fault.
func TestAssertGoParsesInvalid(t *testing.T) {
	// Syntactically invalid: a func declaration with garbage braces.
	const broken = `package main

func {{{
`

	err := assertGoParses([]byte(broken))
	if err == nil {
		t.Fatal("assertGoParses accepted invalid Go — the compile gate is not asserting anything")
	}

	// The error should surface a source location (line:col) from go/parser.
	if !strings.Contains(err.Error(), ":") {
		t.Fatalf("error %q does not carry a source location", err.Error())
	}
}

// TestAssertGoParsesEmpty rejects empty output: a package with no declarations
// at all is not a missing-package error, but a truly empty buffer has no
// package clause and must fail.
func TestAssertGoParsesEmpty(t *testing.T) {
	if err := assertGoParses(nil); err == nil {
		t.Fatal("assertGoParses accepted an empty buffer — expected a parse error (no package clause)")
	}
}
