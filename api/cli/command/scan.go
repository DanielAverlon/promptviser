package command

import (
	"fmt"

	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/pb"
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
	ctx := c.Context()

	fmt.Fprintf(c.ErrWriter(), "loading config: %s\n", c.Cfg)
	cfg, err := config.Load(c.Cfg)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	provider, err := llm.New(cfg.LLM)
	if err != nil {
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}

	fmt.Fprintf(c.ErrWriter(), "scanning: %s\n", a.Path)
	results, err := scanner.Scan(ctx, a.Path, provider)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	fmt.Fprintf(c.ErrWriter(), "scanned %d file(s)\n", len(results))

	adviser, err := c.AdviserClient(true)
	if err != nil {
		return fmt.Errorf("failed to connect to adviser: %w", err)
	}

	fmt.Fprintf(c.ErrWriter(), "matching rules...\n")
	resp, err := adviser.MatchRules(ctx, &pb.MatchRulesRequest{
		FileResults: results,
	})
	if err != nil {
		return fmt.Errorf("rule matching failed: %w", err)
	}
	fmt.Fprintf(c.ErrWriter(), "found findings in %d file(s)\n", len(resp.Findings))

	return c.Print(resp)
}
