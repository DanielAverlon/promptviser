package command

import (
	"crypto/sha256"
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
	"github.com/effective-security/promptviser/internal/reporter"
	"github.com/effective-security/promptviser/internal/scanner"
)

// ScanCmd scans prompts and returns the findings
type ScanCmd struct {
	Path    string `arg:"" help:"Path to the project directory to scan" type:"existingdir"`
	Save    bool   `help:"Save scan results to ~/.config/promptviser/scans/"`
	Verbose bool   `short:"v" help:"Verbose output"`
}

// Run the command
func (a *ScanCmd) Run(c *cli.Cli) error {
	ctx := c.Context()

	fmt.Fprintf(c.ErrWriter(), "%s	loading config: %s\n", reporter.Working, c.Cfg)
	cfg, err := config.Load(c.Cfg)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	failed to load config: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to load config: %w", err)
	}

	provider, err := llm.New(cfg.LLM)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	failed to create LLM provider: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}

	fmt.Fprintf(c.ErrWriter(), "%s	scanning: %s\n", reporter.Working, a.Path)
	results, err := scanner.Scan(ctx, a.Path, provider)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	scan failed: %v\n", reporter.Warn, err)
		return fmt.Errorf("scan failed: %w", err)
	}
	fmt.Fprintf(c.ErrWriter(), "%s	scanned %d file(s)\n", reporter.Info, len(results))

	adviser, err := c.AdviserClient(true)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	failed to connect to adviser: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to connect to adviser: %w", err)
	}

	fmt.Fprintf(c.ErrWriter(), "%s	matching rules...\n", reporter.Working)
	resp, err := adviser.MatchRules(ctx, &pb.MatchRulesRequest{
		FileResults: results,
	})
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	rule matching failed: %v\n", reporter.Warn, err)
		return fmt.Errorf("rule matching failed: %w", err)
	}
	fmt.Fprintf(c.ErrWriter(), "%s	found findings in %d file(s)\n", reporter.Info, len(resp.Findings))

	if a.Save {
		scanID, err := saveScanResult(a.Path, resp)
		if err != nil {
			// non-fatal: print warning but still show results
			fmt.Fprintf(c.ErrWriter(), "%s	warning: failed to save scan: %v\n", reporter.Warn, err)
		} else {
			fmt.Fprintf(c.ErrWriter(), "%s	saved scan: %s\n", reporter.Info, scanID)
		}
		if a.Verbose || !reporter.IsTerminal() {
			return c.Print(resp)
		}
		reporter.PrintScanSummary(resp, scanID)
		return nil
	}

	if a.Verbose || !reporter.IsTerminal() {
		return c.Print(resp)
	}

	reporter.PrintScanSummary(resp, "")
	return nil
}

// saveScanResult writes the findings to ~/.config/promptviser/scans/<slug>_<id>_<timestamp>.json
// and returns the scan ID derived from the content hash.
func saveScanResult(scanPath string, resp *pb.MatchRulesResponse) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	scansDir := filepath.Join(home, ".config", "promptviser", "scans")
	if err := os.MkdirAll(scansDir, 0o700); err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", err
	}

	// derive a stable 8-char ID from the content hash
	hash := sha256.Sum256(data)
	id := fmt.Sprintf("%x", hash[:4])

	// build a filesystem-safe slug from the scanned path
	abs, _ := filepath.Abs(scanPath)
	slug := reporter.ShortPath(abs)
	slug = strings.NewReplacer("/", "_", "\\", "_", " ", "-", ":", "").Replace(strings.TrimPrefix(slug, "/"))
	ts := time.Now().UTC().Format("20060102T150405Z")
	filename := fmt.Sprintf("%s_%s_%s.json", slug, id, ts)

	dest := filepath.Join(scansDir, filename)
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return "", err
	}

	fmt.Printf("%s\tsaved: %s\n", reporter.Info, dest)
	return id, nil
}
