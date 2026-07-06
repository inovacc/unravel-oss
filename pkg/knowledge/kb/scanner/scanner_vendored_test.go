package scanner

import (
	"strings"
	"testing"
)

func TestIsVendoredBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "node_modules path",
			body: `//# sourceMappingURL=node_modules/react-dom/cjs/react-dom.min.js.map`,
			want: true,
		},
		{
			name: "bang license banner",
			body: `/*! For license information please see vendor.js.LICENSE.txt */ var x=1;`,
			want: true,
		},
		{
			name: "at-license tag",
			body: `/** @license React v18.2.0 */ function f(){return 1}`,
			want: true,
		},
		{
			name: "umd factory banner",
			body: `(function (global, factory) { typeof exports === 'object' ...`,
			want: true,
		},
		{
			name: "umd exports object banner minified",
			body: `!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):0}()`,
			// This uses a different shape; should NOT match (conservative).
			want: false,
		},
		{
			name: "umd canonical minified exports check",
			body: `(function(g,f){typeof exports==="object"&&typeof module!=="undefined"?f(exports):0})()`,
			want: true,
		},
		{
			name: "scoped npm import",
			body: `import {x} from "@scope/pkg"; export const y = x;`,
			want: true,
		},
		{
			name: "scoped npm require",
			body: `var a = require("@babel/runtime/helpers/typeof");`,
			want: true,
		},
		{
			name: "first-party esModule marker only",
			body: `Object.defineProperty(exports,"__esModule",{value:!0});function sendMessage(){}`,
			want: false,
		},
		{
			name: "first-party app module",
			body: `function WAWebMsgCollection(){return require("WAWebDb")} module.exports=WAWebMsgCollection;`,
			want: false,
		},
		{
			name: "textmate grammar (shiki highlighter) body",
			body: `{"displayName":"Ballerina","name":"ballerina","scopeName":"source.ballerina","patterns":[{"include":"#comments"}],"repository":{}}`,
			want: true,
		},
		{
			name: "vscode color theme (shiki) body",
			body: `{"name":"everforest-light","type":"light","tokenColors":[{"scope":"comment","settings":{"foreground":"#939f91"}}]}`,
			want: true,
		},
		{
			name: "first-party uses scopeName as bare identifier (no quotes)",
			body: `function scopeName(p){return p.patterns} const repository = {};`,
			want: false,
		},
		{
			name: "clerk library body (clerk.com url)",
			body: `var u="https://dashboard.clerk.com/~/api-keys";throw new Error("Clerk: useAPIKeysContext called outside")`,
			want: true,
		},
		{
			name: "mermaid diagram library body",
			body: `/*mermaid*/function vennDiagram(e){return drawVenn(e)}`,
			want: true,
		},
		{
			name: "first-party mentions clerkship but not clerk.com",
			body: `const role="clerkship";function apply(){return fetch("/jobs")}`,
			want: false,
		},
		{
			name: "grammar with marker deep in body (bundler wrapper preamble) is flagged",
			// shiki grammars place "scopeName" tens of KB in, after the JSON
			// wrapper preamble — full-body matching must still catch it.
			body: strings.Repeat(`{"repository":{"x":1},`, 4000) +
				`"patterns":[{"include":"#x"}],"scopeName":"source.cpp"}`,
			want: true,
		},
		{
			name: "empty body",
			body: ``,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVendoredBody([]byte(tt.body)); got != tt.want {
				t.Errorf("IsVendoredBody(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestIsVendoredName(t *testing.T) {
	tests := []struct {
		name string
		mod  string
		want bool
	}{
		{name: "react chunk", mod: "react-BVAPS1vU", want: true},
		{name: "react-dom chunk", mod: "react-dom-client-9aQ2", want: true},
		{name: "cytoscape esm chunk", mod: "cytoscape.esm-DlC-8Ftf", want: true},
		{name: "pdf worker", mod: "pdf.worker", want: true},
		{name: "pdf worker min", mod: "pdf.worker.min", want: true},
		{name: "firebase storage chunk", mod: "firebase-storage-x9Kd", want: true},
		{name: "cff_parser pdfjs submodule", mod: "cff_parser", want: true},
		{name: "first-party SignIn", mod: "SignIn-Bat6X-QX", want: false},
		{name: "first-party _sessionId", mod: "_sessionId-DB5J3BXQ", want: false},
		{name: "first-party mainApp", mod: "mainApp.6083ad34", want: false},
		{name: "first-party AppleSpeechService", mod: "AppleSpeechService", want: false},
		{name: "html grammar name not in table (body-detected instead)", mod: "html-BTGQVY8y", want: false},
		{name: "empty name", mod: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVendoredName(tt.mod); got != tt.want {
				t.Errorf("IsVendoredName(%q) = %v, want %v", tt.mod, got, tt.want)
			}
		})
	}
}

func TestIsVendored(t *testing.T) {
	// name-only signal
	if !IsVendored("react-BVAPS1vU", []byte(`function x(){}`)) {
		t.Error("IsVendored should flag a known-library name even with opaque body")
	}
	// body-only signal (name first-party, body is a grammar)
	if !IsVendored("html-BTGQVY8y", []byte(`{"scopeName":"text.html.basic","patterns":[]}`)) {
		t.Error("IsVendored should flag a grammar body even with non-table name")
	}
	// neither signal
	if IsVendored("SignIn-Bat6X-QX", []byte(`function signIn(){return fetch('/login')}`)) {
		t.Error("IsVendored should NOT flag first-party name + first-party body")
	}
}
