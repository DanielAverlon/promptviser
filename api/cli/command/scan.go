package command

import (
	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/internal/config"
	"github.com/effective-security/promptviser/internal/llm"
	"github.com/effective-security/promptviser/internal/scanner"
)

// ScanCmd scans prompts and returns the findings
type ScanCmd struct {
	Path string `arg:"" help:"Path to the project directory to scan" type:"existingdir"`
}

// Run the command
func (a *ScanCmd) Run(c *cli.Cli) error {
	cfg, err := config.Load(c.Cfg)
	if err != nil {
		return err
	}
	provider, err := llm.New(cfg.LLM)
	if err != nil {
		return err
	}

	// 1. Run locally, no prompt text leaves the machine
	result, err := scanner.Scan(c.Context(), a.Path, provider)
	if err != nil {
		return err
	}

	// TODO: add back adviser and then match the rules
	_, err = c.AdviserClient(true)
	if err != nil {
		return err
	}

	// 2. Only scores + triggers go to the server
	// findings, err := adviser.MatchRules(c.Context(), result.ToMatchRulesRequest())
	// if err != nil {
	// 	return err
	// }

	return c.Print(result)
}
