package command

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/config"
	"github.com/effective-security/promptviser/internal/llm"
	"github.com/effective-security/promptviser/internal/scanner"
)

// ScanCmd scans prompts and returns the findings
type ScanCmd struct {
	Path string `arg:"" help:"Path to the project directory to scan" type:"existingdir"`
	Save bool   `help:"Save scan results to ~/.config/promptviser/scans/"`
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

	if a.Save {
		if err := saveScanResult(a.Path, resp); err != nil {
			// non-fatal: print warning but still show results
			fmt.Fprintf(c.ErrWriter(), "warning: failed to save scan: %v\n", err)
		}
	}

	return c.Print(resp)
}

// saveScanResult writes the findings to ~/.config/promptviser/scans/<slug>_<timestamp>.json
func saveScanResult(scanPath string, resp *pb.MatchRulesResponse) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	scansDir := filepath.Join(home, ".config", "promptviser", "scans")
	if err := os.MkdirAll(scansDir, 0o700); err != nil {
		return err
	}

	// build a filesystem-safe slug from the scanned path
	abs, _ := filepath.Abs(scanPath)
	slug := strings.NewReplacer("/", "_", "\\", "_", " ", "-", ":", "").Replace(strings.TrimPrefix(abs, "/"))
	ts := time.Now().UTC().Format("20060102T150405Z")
	filename := fmt.Sprintf("%s_%s.json", slug, ts)

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return err
	}

	dest := filepath.Join(scansDir, filename)
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return err
	}

	fmt.Printf("saved: %s\n", dest)
	return nil
}
