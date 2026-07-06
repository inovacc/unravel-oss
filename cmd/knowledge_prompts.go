/*
Copyright (c) 2026 Security Research
*/
// cmd/knowledge_prompts.go wires the embedded prompt registry into the
// `unravel knowledge prompts {list,show}` CLI surface so analysts can
// inspect what the LLM-driven loop will send before triggering it.
package cmd

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/prompts"

	"github.com/spf13/cobra"
)

var kbPromptsCmd = &cobra.Command{
	Use:   "prompts",
	Short: "Inspect the embedded LLM prompt registry",
}

var kbPromptsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered prompt op names",
	RunE: func(_ *cobra.Command, _ []string) error {
		ops := prompts.List()
		if len(ops) == 0 {
			fmt.Println("(no prompts registered)")
			return nil
		}
		for _, op := range ops {
			p, err := prompts.Get(op)
			if err != nil {
				fmt.Printf("%-20s  (load error: %v)\n", op, err)
				continue
			}
			fmt.Printf("%-20s  %s\n", op, p.Description)
		}
		return nil
	},
}

var kbPromptsShowCmd = &cobra.Command{
	Use:   "show <op>",
	Short: "Print frontmatter and body for one prompt op",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		p, err := prompts.Get(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("op:             %s\n", p.Op)
		fmt.Printf("description:    %s\n", p.Description)
		fmt.Printf("language_hint:  %s\n", p.LanguageHint)
		fmt.Printf("output_format:  %s\n", p.OutputFormat)
		fmt.Printf("schema:         %s\n", p.Schema)
		fmt.Printf("max_tokens:     %d\n", p.MaxTokens)
		fmt.Println("---")
		fmt.Print(p.Body)
		if len(p.Body) > 0 && p.Body[len(p.Body)-1] != '\n' {
			fmt.Println()
		}
		return nil
	},
}

func init() {
	kbPromptsCmd.AddCommand(kbPromptsListCmd, kbPromptsShowCmd)
	kbCatalogCmd.AddCommand(kbPromptsCmd)
}
