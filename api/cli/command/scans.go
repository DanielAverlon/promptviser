package command

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/effective-security/promptviser/api/cli"
)

// ScanInfo holds the parsed metadata from a saved scan filename.
type ScanInfo struct {
	Filename    string
	ProjectPath string    `json:"project_path"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScanListCmd lists saved scans, optionally filtered by project path substring.
type ScanListCmd struct {
	Path string `arg:"" optional:"" help:"Filter by project path substring"`
}

func (a *ScanListCmd) Run(c *cli.Cli) error {
	scans, err := listScans()
	if err != nil {
		return fmt.Errorf("failed to list scans: %w", err)
	}

	for _, scan := range scans {
		if a.Path == "" || strings.Contains(scan.ProjectPath, a.Path) {
			fmt.Fprintf(c.Writer(), "%-80s  %s\n", scan.Filename, scan.Timestamp.Format(time.RFC3339))
		}
	}
	return nil
}

// ScanViewCmd prints the contents of a saved scan file.
type ScanViewCmd struct {
	File string `arg:"" help:"Scan filename (from 'scan-list') to view"`
}

func (a *ScanViewCmd) Run(c *cli.Cli) error {
	path := filepath.Join(getScansDir(), a.File)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read scan file: %w", err)
	}
	_, err = c.Writer().Write(data)
	return err
}

// ScanDeleteCmd deletes a saved scan file.
type ScanDeleteCmd struct {
	File string `arg:"" help:"Scan filename (from 'scan-list') to delete"`
}

func (a *ScanDeleteCmd) Run(c *cli.Cli) error {
	path := filepath.Join(getScansDir(), a.File)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}
	fmt.Fprintf(c.Writer(), "deleted: %s\n", a.File)
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

func listScans() ([]*ScanInfo, error) {
	scansDir := getScansDir()
	if _, err := os.Stat(scansDir); os.IsNotExist(err) {
		return nil, nil
	}
	files, err := os.ReadDir(scansDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read scans directory: %w", err)
	}

	// Parse each scan filename into project path + timestamp.
	// Format: <slug>_<20060102T150405Z>.json
	// slug = absolute path with '/' replaced by '_', leading '/' stripped.
	// Timestamp is always the last '_'-delimited segment before ".json".
	var scans []*ScanInfo
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		base := strings.TrimSuffix(name, ".json")
		if base == name {
			continue
		}

		lastUnderscore := strings.LastIndex(base, "_")
		if lastUnderscore < 0 {
			continue
		}
		tsStr := base[lastUnderscore+1:]
		slug := base[:lastUnderscore]

		ts, err := time.Parse("20060102T150405Z", tsStr)
		if err != nil {
			continue
		}

		projectPath := "/" + strings.ReplaceAll(slug, "_", "/")
		scans = append(scans, &ScanInfo{
			Filename:    name,
			ProjectPath: projectPath,
			Timestamp:   ts,
		})
	}
	return scans, nil
}

func getScansDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "promptviser", "scans")
}
