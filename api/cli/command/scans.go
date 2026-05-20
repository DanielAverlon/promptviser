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
	"github.com/effective-security/promptviser/internal/reporter"
)

// ScanListCmd lists saved scans, optionally filtered by project path substring.
type ScanListCmd struct {
	Path string `arg:"" optional:"" help:"Filter by project path substring"`
}

func (a *ScanListCmd) Run(c *cli.Cli) error {
	scans, err := listScans()
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  failed to list scans: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to list scans: %w", err)
	}

	if !reporter.IsTerminal() {
		// plain output for piping: one line per scan
		for _, entries := range scans {
			for _, s := range entries {
				if a.Path == "" || strings.Contains(s.ProjectPath, a.Path) {
					fmt.Fprintf(c.Writer(), "%s  %-12s  %s  %s\n",
						s.ID, s.Filename, s.ProjectPath, s.Timestamp.Format(time.RFC3339))
				}
			}
		}
		return nil
	}

	// filter if path provided
	if a.Path != "" {
		filtered := make(map[string][]*reporter.ScanInfo)
		for project, entries := range scans {
			if strings.Contains(project, a.Path) {
				filtered[project] = entries
			}
		}
		scans = filtered
	}

	reporter.PrintScansList(scans)
	return nil
}

// ScanViewCmd prints the contents of a saved scan file.
type ScanViewCmd struct {
	ID      string `arg:"" help:"Scan filename (from 'scan-list') to view"`
	Verbose bool   `short:"v" help:"Verbose output"`
}

func (a *ScanViewCmd) Run(c *cli.Cli) error {
	filename, err := findScanByID(a.ID)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  %v\n", reporter.Warn, err)
		return err
	}

	path := filepath.Join(getScansDir(), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  failed to read scan file: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to read scan file: %w", err)
	}

	if a.Verbose || !reporter.IsTerminal() {
		_, err = c.Writer().Write(data)
		return err
	}

	var resp *pb.MatchRulesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  failed to parse scan file: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to parse scan file: %w", err)
	}

	reporter.PrintScanSummary(resp, a.ID)
	return nil
}

// ScanDeleteCmd deletes a saved scan file.
type ScanDeleteCmd struct {
	ID      string `arg:"" optional:"" help:"Scan ID (from 'scan-list') to delete"`
	Project string `short:"p" help:"Delete all scans whose project path contains this substring"`
}

func (a *ScanDeleteCmd) Run(c *cli.Cli) error {
	if a.Project != "" {
		scans, err := listScans()
		if err != nil {
			fmt.Fprintf(c.ErrWriter(), "%s  failed to list scans: %v\n", reporter.Warn, err)
			return fmt.Errorf("failed to list scans: %w", err)
		}
		deleted := 0
		for project, entries := range scans {
			if strings.Contains(project, a.Project) {
				for _, s := range entries {
					path := filepath.Join(getScansDir(), s.Filename)
					if err := os.Remove(path); err != nil {
						fmt.Fprintf(c.ErrWriter(), "%s  failed to delete %s: %v\n", reporter.Warn, s.ID, err)
						continue
					}
					fmt.Fprintf(c.Writer(), "%s  deleted: %s  (%s)\n", reporter.Info, s.ID, s.Filename)
					deleted++
				}
			}
		}
		if deleted == 0 {
			fmt.Fprintf(c.Writer(), "%s  no scans found for project: %s\n", reporter.Warn, a.Project)
		}
		return nil
	}

	if a.ID == "" {
		return fmt.Errorf("provide a scan ID or --project flag")
	}

	filename, err := findScanByID(a.ID)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  %v\n", reporter.Warn, err)
		return err
	}
	path := filepath.Join(getScansDir(), filename)
	if err := os.Remove(path); err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  failed to delete scan: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to delete scan: %w", err)
	}
	fmt.Fprintf(c.Writer(), "%s  deleted: %s\n", reporter.Info, a.ID)
	return nil
}

// ScanDiffCmd compares two saved scan files and reports new/resolved findings.
type ScanDiffCmd struct {
	A string `arg:"" help:"Earlier scan filename"`
	B string `arg:"" help:"Later scan filename"`
}

func (a *ScanDiffCmd) Run(c *cli.Cli) error {
	// TODO: implement diff logic
	fmt.Fprintf(c.Writer(), "diff: %s vs %s (not yet implemented)\n", a.A, a.B)
	return nil
}

func listScans() (map[string][]*reporter.ScanInfo, error) {
	scansDir := getScansDir()
	if _, err := os.Stat(scansDir); os.IsNotExist(err) {
		return nil, nil
	}
	files, err := os.ReadDir(scansDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read scans directory: %w", err)
	}

	// Supported filename formats:
	//   new: <slug>_<id>_<timestamp>.json  (id = 8 hex chars)
	//   old: <slug>_<timestamp>.json
	scans := make(map[string][]*reporter.ScanInfo)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		base := strings.TrimSuffix(name, ".json")
		if base == name {
			continue
		}

		parts := strings.Split(base, "_")
		if len(parts) < 2 {
			continue
		}

		var id, slug, tsStr string
		timestampStr := parts[len(parts)-1]
		_, tsErr := time.Parse("20060102T150405Z", timestampStr)
		if tsErr != nil {
			continue
		}
		tsStr = timestampStr

		// check if second-to-last segment is an 8-char hex ID (new format)
		if len(parts) >= 3 && isHexID(parts[len(parts)-2]) {
			id = parts[len(parts)-2]
			slug = strings.Join(parts[:len(parts)-2], "_")
		} else {
			// old format: derive ID from filename hash
			hash := sha256.Sum256([]byte(name))
			id = fmt.Sprintf("%x", hash[:4])
			slug = strings.Join(parts[:len(parts)-1], "_")
		}

		ts, _ := time.Parse("20060102T150405Z", tsStr)
		projectPath := "/" + strings.ReplaceAll(slug, "_", "/")

		scans[projectPath] = append(scans[projectPath], &reporter.ScanInfo{
			ID:          id,
			Filename:    name,
			ProjectPath: projectPath,
			Timestamp:   ts,
		})
	}
	return scans, nil
}

// isHexID returns true if s is exactly 8 lowercase hex characters.
func isHexID(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// findScanByID scans the scans directory and returns the filename whose ID matches.
func findScanByID(id string) (string, error) {
	scans, err := listScans()
	if err != nil {
		return "", err
	}
	for _, entries := range scans {
		for _, s := range entries {
			if s.ID == id {
				return s.Filename, nil
			}
		}
	}
	return "", fmt.Errorf("scan not found: %s", id)
}

func getScansDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "promptviser", "scans")
}
