package command

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/config"
	"github.com/effective-security/promptviser/internal/llm"
	"github.com/effective-security/promptviser/internal/reporter"
)

// ScanRemediateCmd loads a saved scan by ID and generates LLM remediation
// suggestions for every file that has findings.
type ScanRemediateCmd struct {
	ID string `arg:"" help:"Scan ID (from 'scan-list') to generate remediations for"`
}

func (a *ScanRemediateCmd) Run(c *cli.Cli) error {
	ctx := c.Context()

	fmt.Fprintf(c.ErrWriter(), "%s\tloading config: %s\n", reporter.Working, c.Cfg)
	cfg, err := config.Load(c.Cfg)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s\tfailed to load config: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to load config: %w", err)
	}

	provider, err := llm.New(cfg.LLM)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s\tfailed to create LLM provider: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}

	filename, err := findScanByID(a.ID)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s\t%v\n", reporter.Warn, err)
		return err
	}

	path := filepath.Join(getScansDir(), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s\tfailed to read scan file: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to read scan file: %w", err)
	}

	var resp pb.MatchRulesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s\tfailed to parse scan file: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to parse scan file: %w", err)
	}

	fmt.Fprintf(c.ErrWriter(), "%s\tgenerating remediations for scan %s\n", reporter.Info, a.ID)
	runRemediation(ctx, c, provider, &resp)
	return nil
}
