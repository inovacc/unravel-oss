/*
Copyright (c) 2026 Security Research
*/

package jsdeob

import (
	"strings"
	"testing"
)

func TestStripBundlerBoilerplate_EsbuildAliases(t *testing.T) {
	in := `var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
function realCode() { return 42; }
`
	out, n := StripBundlerBoilerplate(in)
	if n != 4 {
		t.Errorf("stripped %d lines, want 4", n)
	}
	if !strings.Contains(out, "function realCode()") {
		t.Errorf("removed real code: %q", out)
	}
	if strings.Contains(out, "__defProp") || strings.Contains(out, "__hasOwnProp") {
		t.Errorf("alias survived: %q", out)
	}
}

func TestStripBundlerBoilerplate_WebpackRMarkerOnly(t *testing.T) {
	in := `__webpack_require__.r(__webpack_exports__);
__webpack_require__.d(__webpack_exports__, {MyAPI: () => MyAPI});
function MyAPI() {}
`
	out, n := StripBundlerBoilerplate(in)
	if n != 1 {
		t.Errorf("stripped %d, want 1", n)
	}
	if strings.Contains(out, "__webpack_require__.r(") {
		t.Errorf(".r() marker survived: %q", out)
	}
	if !strings.Contains(out, "__webpack_require__.d(") {
		t.Errorf(".d() export table dropped — must preserve: %q", out)
	}
	if !strings.Contains(out, "MyAPI") {
		t.Errorf("real symbol lost: %q", out)
	}
}

func TestStripBundlerBoilerplate_ESMMarker(t *testing.T) {
	in := `Object.defineProperty(exports, "__esModule", { value: true });
Object.defineProperty(exports, "__esModule", { value: !0 });
Object.defineProperty(exports, "myCustomProp", { value: 42 });
`
	out, n := StripBundlerBoilerplate(in)
	if n != 2 {
		t.Errorf("stripped %d, want 2", n)
	}
	if strings.Contains(out, "__esModule") {
		t.Errorf("__esModule marker survived: %q", out)
	}
	if !strings.Contains(out, "myCustomProp") {
		t.Errorf("user-defined property collateral-damaged: %q", out)
	}
}

func TestStripBundlerBoilerplate_StringLiteralCollision(t *testing.T) {
	// A string LITERAL containing the boilerplate text must NOT be stripped;
	// only full-line matches qualify.
	in := `var msg = "did you call __webpack_require__.r(exports) yourself?";
console.log(msg);
`
	out, n := StripBundlerBoilerplate(in)
	if n != 0 {
		t.Errorf("stripped %d from inside a string literal — must be 0: %q", n, out)
	}
}

func TestStripBundlerBoilerplate_NoMatchLeavesCodeUnchanged(t *testing.T) {
	in := `function ordinary() { return 1; }
const x = 42;
`
	out, n := StripBundlerBoilerplate(in)
	if n != 0 || out != in {
		t.Errorf("clean input mutated: n=%d out=%q", n, out)
	}
}

func TestDeobfuscate_StripBundlerCruftIntegration(t *testing.T) {
	in := `var __defProp = Object.defineProperty;
__webpack_require__.r(__webpack_exports__);
function real() { return 1; }
`
	result, err := Deobfuscate(in, Options{StripBundlerCruft: true})
	if err != nil {
		t.Fatalf("Deobfuscate: %v", err)
	}
	if !strings.Contains(result.Code, "function real()") {
		t.Errorf("real code dropped: %q", result.Code)
	}
	if strings.Contains(result.Code, "__defProp") || strings.Contains(result.Code, ".r(") {
		t.Errorf("boilerplate survived: %q", result.Code)
	}
	wantTransform := "Stripped 2 bundler-runtime boilerplate lines"
	found := false
	for _, tr := range result.Transformations {
		if tr == wantTransform {
			found = true
		}
	}
	if !found {
		t.Errorf("transformation log missing %q; got %v", wantTransform, result.Transformations)
	}
}
