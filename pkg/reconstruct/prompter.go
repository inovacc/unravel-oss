package reconstruct

import (
	"fmt"
	"strings"
)

// BuildPrompt generates an MCP delegation prompt for code reconstruction.
// The prompt is returned as content for the MCP host LLM to process naturally,
// following the same delegation pattern as pkg/schema.GenerateSchemaPrompt.
func BuildPrompt(artifact Artifact, chunks []Chunk, lang Language) string {
	var b strings.Builder

	b.WriteString("# Code Reconstruction Task\n\n")

	// Metadata section.
	b.WriteString("## Metadata\n\n")
	fmt.Fprintf(&b, "- **Language:** %s\n", lang)
	if artifact.SourceTool != "" {
		fmt.Fprintf(&b, "- **Source tool:** %s (decompiler output)\n", artifact.SourceTool)
	}
	fmt.Fprintf(&b, "- **Original file:** %s\n", artifact.Path)
	fmt.Fprintf(&b, "- **Chunks:** %d\n\n", len(chunks))

	// Instructions section.
	b.WriteString("## Instructions\n\n")
	b.WriteString("Reconstruct this decompiled source into clean, readable, production-quality code.\n\n")
	b.WriteString("Requirements:\n")
	b.WriteString("1. Rename obfuscated variables and parameters to meaningful names based on usage context\n")
	b.WriteString("2. Add documentation comments (Javadoc, JSDoc, or language-appropriate) for public APIs\n")
	b.WriteString("3. Preserve ALL original logic exactly -- do not add, remove, or change any behavior\n")
	b.WriteString("4. Flag any sections where reconstruction is uncertain with `// UNCERTAIN: reason` comments\n")
	b.WriteString("5. Maintain original method signatures (parameter count and types)\n")
	b.WriteString("6. Use idiomatic patterns for the target language\n")

	// Language-specific hints.
	switch lang {
	case LangJava:
		b.WriteString("7. Use standard Java naming conventions (camelCase methods, PascalCase classes)\n")
		b.WriteString("8. Replace raw types with proper generics where inferable\n")
	case LangJavaScript, LangTypeScript:
		b.WriteString("7. Use modern ES6+ syntax (const/let, arrow functions, destructuring)\n")
		b.WriteString("8. Convert CommonJS require() to ES module imports where appropriate\n")
	case LangCSharp:
		b.WriteString("7. Use C# naming conventions (PascalCase methods and properties)\n")
		b.WriteString("8. Use expression-bodied members where concise\n")
	case LangGo:
		b.WriteString("7. Follow Go conventions (exported names PascalCase, unexported camelCase)\n")
		b.WriteString("8. Use error wrapping with fmt.Errorf and %w\n")
	case LangPython:
		b.WriteString("7. Follow PEP 8 naming conventions (snake_case functions, PascalCase classes)\n")
		b.WriteString("8. Add type hints for function signatures\n")
	}

	b.WriteString("\n")

	// Code section(s).
	if len(chunks) == 1 {
		b.WriteString("## Source Code\n\n")
		b.WriteString("```" + string(lang) + "\n")
		b.WriteString(chunks[0].Content)
		if !strings.HasSuffix(chunks[0].Content, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("```\n")
	} else {
		for i, chunk := range chunks {
			fmt.Fprintf(&b, "## Chunk %d of %d (lines %d-%d)\n\n", i+1, chunk.Total, chunk.StartLine, chunk.EndLine)
			if chunk.Context != "" {
				fmt.Fprintf(&b, "%s\n\n", chunk.Context)
			}
			b.WriteString("```" + string(lang) + "\n")
			b.WriteString(chunk.Content)
			if !strings.HasSuffix(chunk.Content, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n\n")
		}
	}

	b.WriteString("\n## Output Format\n\n")
	b.WriteString("Return ONLY the reconstructed source code in a single fenced code block. ")
	b.WriteString("Do not include explanations outside the code block.\n")

	return b.String()
}

// BuildRetryPrompt generates a follow-up prompt that includes verification
// failure feedback, allowing the LLM to correct its reconstruction.
func BuildRetryPrompt(original string, reconstructed string, failures []string) string {
	var b strings.Builder

	b.WriteString("# Code Reconstruction Retry\n\n")
	b.WriteString("Your previous reconstruction had verification failures. Please fix them.\n\n")

	b.WriteString("## Verification Failures\n\n")
	for _, f := range failures {
		fmt.Fprintf(&b, "- %s\n", f)
	}
	b.WriteString("\n")

	b.WriteString("## Your Previous Output\n\n")
	b.WriteString("```\n")
	b.WriteString(reconstructed)
	if !strings.HasSuffix(reconstructed, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("```\n\n")

	b.WriteString("## Original Cleaned Source\n\n")
	b.WriteString("```\n")
	b.WriteString(original)
	if !strings.HasSuffix(original, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("```\n\n")

	b.WriteString("Fix the verification failures while preserving all original logic. ")
	b.WriteString("Return ONLY the corrected source code in a single fenced code block.\n")

	return b.String()
}
