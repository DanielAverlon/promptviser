package reporter

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/diff"
	"golang.org/x/term"
)

// ScanInfo holds the parsed metadata from a saved scan filename.
type ScanInfo struct {
	ID          string
	Filename    string
	ProjectPath string
	Timestamp   time.Time
}

var (
	Info    = lipgloss.NewStyle().Foreground(lipgloss.Color("32")).Render("✓")
	Working = lipgloss.NewStyle().Foreground(lipgloss.Color("33")).Render("→")
	Warn    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✗")
)

var (
	high    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	med     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	low     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("34"))
	muted   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	bold    = lipgloss.NewStyle().Bold(true)
	divider = strings.Repeat("─", 56)
)

func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func SevStyle(sev string) lipgloss.Style {
	switch strings.ToLower(sev) {
	case "high":
		return high
	case "medium", "med":
		return med
	default:
		return low
	}
}

// PrintScanSummary renders the human-readable scan report
func PrintScanSummary(results *pb.MatchRulesResponse, scanID string) {
	totalFindings := 0
	highCount, medCount, lowCount := 0, 0, 0

	fmt.Println()
	fmt.Println(bold.Render("SCAN COMPLETE") + "  " + muted.Render(scanID))
	fmt.Println(divider)

	for _, ff := range results.Findings {
		if len(ff.Findings) == 0 {
			continue
		}
		// print filename, stripped to relative path
		fmt.Println()
		fmt.Println("  " + bold.Render(ShortPath(ff.FileName)))

		for i, f := range ff.Findings {
			totalFindings++
			connector := "├─"
			if i == len(ff.Findings)-1 {
				connector = "└─"
			}

			sevLabel := fmt.Sprintf("[%s]", strings.ToUpper(f.Severity))
			styled := SevStyle(f.Severity).Render(sevLabel)

			fmt.Printf("  %s %s  %-8s %s\n",
				connector, styled, f.RuleID, f.Title)

			switch strings.ToLower(f.Severity) {
			case "high":
				highCount++
			case "medium", "med":
				medCount++
			default:
				lowCount++
			}
		}
	}

	fmt.Println()
	fmt.Println(divider)
	summary := fmt.Sprintf("  %d finding(s)  (%s · %s · %s)",
		totalFindings,
		high.Render(fmt.Sprintf("%d high", highCount)),
		med.Render(fmt.Sprintf("%d med", medCount)),
		low.Render(fmt.Sprintf("%d low", lowCount)),
	)
	fmt.Println(summary)
	fmt.Println(muted.Render("  Run with -v to see full JSON · pvctl scan-view <id> -v for details"))
	fmt.Println()
}

func ShortPath(full string) string {
	// show path from "prompts/" onwards if present
	if idx := strings.Index(full, "prompts/"); idx != -1 {
		return full[idx:]
	}
	parts := strings.Split(full, "/")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return full
}

// PrintRulesList renders pvctl rules output
func PrintRulesList(rules *pb.GetRulesResponse) {
	fmt.Println()
	fmt.Printf("%s  %s\n",
		bold.Render("PROMPTVISER RULES"),
		muted.Render(fmt.Sprintf("(%d total)", len(rules.Rules))))
	fmt.Println(divider)

	for _, r := range rules.Rules {
		sevStyled := SevStyle(r.Severity).Render(
			fmt.Sprintf("%-6s", strings.ToUpper(r.Severity)))
		fmt.Printf(" %-8s %s  %s\n", r.RuleID, sevStyled, r.Title)
		fmt.Printf("          %s  %s\n\n",
			muted.Render("Standards:"),
			muted.Render(strings.Join(r.Standards, " · ")))
	}
	fmt.Println(divider)
}

// PrintScansList renders pvctl scan-list output grouped by project path.
// scans is a map of project path → list of scan entries.
func PrintScansList(scans map[string][]*ScanInfo) {
	total := 0
	for _, entries := range scans {
		total += len(entries)
	}

	fmt.Println()
	fmt.Println(bold.Render("SAVED SCANS") + "  " + muted.Render(fmt.Sprintf("(%d total)", total)))
	fmt.Println(divider)

	for project, entries := range scans {
		fmt.Println()
		fmt.Println("  " + bold.Render(project))
		for i, s := range entries {
			connector := "├─"
			if i == len(entries)-1 {
				connector = "└─"
			}
			fmt.Printf("  %s %s  %s\n",
				connector,
				bold.Render(s.ID),
				muted.Render(s.Timestamp.Format("2006-01-02 15:04:05")))
		}
	}

	fmt.Println()
	fmt.Println(divider)
	fmt.Println(muted.Render("  Use pvctl scan-view <id> to view a saved scan"))
	fmt.Println()
}

func PrintScanDiff(diff *diff.ScanDiff, idA, idB string) {
	fmt.Println()
	fmt.Printf("%s  %s\n",
		bold.Render("SCAN COMPARISON"),
		muted.Render(fmt.Sprintf("(%s vs %s)", idA, idB)))
	fmt.Println(divider)

	printDiffSection(fmt.Sprintf("Only in %s", idA), diff.OnlyInA)
	printDiffSection(fmt.Sprintf("Only in %s", idB), diff.OnlyInB)
	printDiffSection("In Both", diff.InBoth)

	fmt.Println(divider)
	fmt.Println(muted.Render("  Use pvctl scan-view <id> -v to see full details of each scan"))
	fmt.Println()
}

func printDiffSection(label string, entries []diff.DiffEntry) {
	fmt.Printf("  %s  %d finding(s)\n", muted.Render(label), len(entries))
	if len(entries) == 0 {
		return
	}

	byFile := make(map[string][]diff.DiffEntry)
	fileOrder := make([]string, 0)
	for _, e := range entries {
		if _, ok := byFile[e.FilePath]; !ok {
			fileOrder = append(fileOrder, e.FilePath)
		}
		byFile[e.FilePath] = append(byFile[e.FilePath], e)
	}

	for i, file := range fileOrder {
		fileConnector := "├─"
		childPrefix := "  │   "
		if i == len(fileOrder)-1 {
			fileConnector = "└─"
			childPrefix = "      "
		}
		fmt.Printf("  %s  %s\n", fileConnector, bold.Render(ShortPath(file)))

		findings := byFile[file]
		for j, entry := range findings {
			findingConnector := "├─"
			if j == len(findings)-1 {
				findingConnector = "└─"
			}
			sevLabel := fmt.Sprintf("[%s]", strings.ToUpper(entry.Severity))
			sevStyled := SevStyle(entry.Severity).Render(sevLabel)
			ruleName := entry.RuleName
			if ruleName == "" {
				ruleName = entry.Description
			}
			fmt.Printf("%s%s %s  %-8s %s\n", childPrefix, findingConnector, sevStyled, entry.ID, ruleName)
		}
	}
	fmt.Println()
}
