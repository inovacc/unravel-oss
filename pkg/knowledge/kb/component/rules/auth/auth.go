/*
Copyright (c) 2026 Security Research

Package auth registers positive rules that classify modules into the auth
taxonomy bucket. Rules fire via init() through component.Register and become
active on any consumer that blank-imports this package (typically through
pkg/knowledge/kb/component/runtime).
*/
package auth

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathAuth  = regexp.MustCompile(`(?i)(^|/)(auth|login|session|oauth|sso)/`)
	nameAuth  = regexp.MustCompile(`(?i)(Auth|Login|Session|Token|OAuth|JWT|Credential)`)
	nameLogin = regexp.MustCompile(`(?i)Login|SignIn|SignUp`)
	pathToken = regexp.MustCompile(`(?i)token|jwt`)
)

func init() {
	component.Register(component.Rule{
		Name: "auth/path-name-symbol", Component: "auth", Confidence: 0.95, Priority: 10,
		PathRegex: pathAuth, NameRegex: nameAuth,
		SymbolKeywords: []string{"oauth", "jwt", "login", "session", "password", "hmac"},
	})
	component.Register(component.Rule{
		Name: "auth/name-symbol", Component: "auth", Confidence: 0.80, Priority: 10,
		NameRegex:      nameAuth,
		SymbolKeywords: []string{"oauth", "jwt", "session", "password", "credential"},
	})
	component.Register(component.Rule{
		Name: "auth/path-symbol", Component: "auth", Confidence: 0.80, Priority: 10,
		PathRegex:      pathToken,
		SymbolKeywords: []string{"token", "bearer", "jwt"},
	})
	component.Register(component.Rule{
		Name: "auth/login-name-only", Component: "auth", Confidence: 0.65, Priority: 10,
		NameRegex: nameLogin,
	})
}
