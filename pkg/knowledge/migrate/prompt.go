/*
Copyright (c) 2026 Security Research
*/
package migrate

import _ "embed"

//go:embed migration.md
var promptTemplate string

// MigrationPrompt returns the embedded migration prompt template body.
//
// The template uses Go text/template directives (`{{.Framework}}`,
// `{{.Component}}`, `{{range .Files}}`) and contains the literal sentinel
// boundaries `<<<USER_SOURCE_BEGIN>>>` / `<<<USER_SOURCE_END>>>` to defend
// against prompt injection from beautified source content (T-07-03).
func MigrationPrompt() string { return promptTemplate }
