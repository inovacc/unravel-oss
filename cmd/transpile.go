/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/inovacc/unravel-oss/internal/mcp"
	"github.com/inovacc/unravel-oss/pkg/transpile/core/converter"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages"

	"github.com/spf13/cobra"
)

var (
	transpileLanguage string
	transpileOffline  bool
)

var transpileCmd = &cobra.Command{
	Use:   "transpile <file>",
	Short: "Transpile a source file to Go (C++, Java, Python, TypeScript)",
	Long: `Transpile source code into idiomatic Go code using a hybrid deterministic+LLM pipeline.

Supported languages: C++, Java, Python, TypeScript.

Offline mode (--offline) uses only the deterministic AST->IR->Go pipeline and
does not require an MCP/LLM session. For complex bodies that the deterministic
pipeline cannot handle, the output will contain LLM-assistance prompts instead
of Go code.`,
	Args: cobra.ExactArgs(1),
	Run:  runTranspile,
}

func init() {
	rootCmd.AddCommand(transpileCmd)
	transpileCmd.Flags().StringVar(&transpileLanguage, "language", "", "Override language detection (C++, Java, Python, TypeScript)")
	transpileCmd.Flags().BoolVar(&transpileOffline, "offline", false, "Disable LLM fallbacks (deterministic only)")
}

func runTranspile(_ *cobra.Command, args []string) {
	path := args[0]

	source, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read file: %v\n", err)
		os.Exit(1)
	}

	var lang languages.Language
	if transpileLanguage != "" {
		for _, l := range languages.All() {
			if strings.EqualFold(l.Name(), transpileLanguage) {
				lang = l
				break
			}
		}
		if lang == nil {
			fmt.Fprintf(os.Stderr, "Error: unsupported language override: %s\n", transpileLanguage)
			os.Exit(1)
		}
	} else {
		lang, err = languages.ForFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: detect language: %v\n", err)
			os.Exit(1)
		}
	}

	var opts []converter.Option
	if !transpileOffline {
		llmClient := mcp.TranspileClient()
		opts = append(opts, converter.WithLLM(llmClient))
	}

	conv := converter.New(slog.Default(), opts...)

	ctx := context.Background()
	var result *converter.PromptResult

	if dl, ok := lang.(languages.DeterministicLanguage); ok {
		result, err = conv.ConvertWithDeterministic(ctx, dl, path, source)
	} else if al, ok := lang.(languages.ASTLanguage); ok {
		result, err = conv.ConvertWithLanguageAST(ctx, al, path, source)
	} else {
		result, err = conv.ConvertWithLanguage(ctx, lang, path, source)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: transpile: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(result.Format())
}
