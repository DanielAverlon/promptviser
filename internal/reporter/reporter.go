package reporter

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/diff"
	"github.com/effective-security/promptviser/internal/llm"
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

// termWidth returns the current terminal column width, or 120 as a safe default.
func termWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 120
}

// truncate returns a MaxWidth style that clips text to fit within cols columns.
func truncate(cols int) lipgloss.Style {
	if cols < 10 {
		cols = 10
	}
	return lipgloss.NewStyle().MaxWidth(cols)
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

		// prefix: "  ├─ [HIGH]  SEC-001  " ≈ 26 chars
		nameWidth := termWidth() - 26
		for i, f := range ff.Findings {
			totalFindings++
			connector := "├─"
			if i == len(ff.Findings)-1 {
				connector = "└─"
			}

			sevLabel := fmt.Sprintf("[%s]", strings.ToUpper(f.Severity))
			styled := SevStyle(f.Severity).Render(sevLabel)

			fmt.Printf("  %s %s  %-8s %s\n",
				connector, styled, f.RuleID, truncate(nameWidth).Render(f.Title))

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

	// prefix: " SEC-001  HIGH    " ≈ 20 chars
	nameWidth := termWidth() - 20
	for _, r := range rules.Rules {
		sevStyled := SevStyle(r.Severity).Render(
			fmt.Sprintf("%-6s", strings.ToUpper(r.Severity)))
		fmt.Printf(" %-8s %s  %s\n", r.RuleID, sevStyled, truncate(nameWidth).Render(r.Title))
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
			// childPrefix(6) + "├─ [HIGH]  SEC-001  " ≈ 30 chars
			nameWidth := termWidth() - 30
			fmt.Printf("%s%s %s  %-8s %s\n", childPrefix, findingConnector, sevStyled, entry.ID, truncate(nameWidth).Render(ruleName))
		}
	}
	fmt.Println()
}

var (
	remDel = lipgloss.NewStyle().Foreground(lipgloss.Color("196")) // red  for - lines
	remAdd = lipgloss.NewStyle().Foreground(lipgloss.Color("34"))  // green for + lines
	remHdr = lipgloss.NewStyle().Bold(true)
	remRsn = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Italic(true)
)

// PrintRemediations renders lint-style remediation output for one file.
// Each edit shows the original snippet (red -) and replacement (green +),
// making it easy to build a programmatic diff downstream.
func PrintRemediations(fileName string, edits []llm.RemediationEdit) {
	if len(edits) == 0 {
		return
	}
	fmt.Printf("%s\n", remHdr.Render(fileName))
	for i, e := range edits {
		connector := "├─"
		childPrefix := "  │   "
		if i == len(edits)-1 {
			connector = "└─"
			childPrefix = "      "
		}
		// prefix: "  ├─ [HIGH]  SEC-001  " ≈ 26 chars
		reasonWidth := termWidth() - 26
		sevLabel := SevStyle(e.Severity).Render(fmt.Sprintf("[%s]", strings.ToUpper(e.Severity)))
		fmt.Printf("  %s %s  %-8s %s\n", connector, sevLabel, e.RuleID, truncate(reasonWidth).Render(e.Reason))

		if e.Original == "" {
			fmt.Printf("%s%s\n", childPrefix, remDel.Render("- (pure addition)"))
		} else {
			for _, line := range strings.Split(e.Original, "\n") {
				fmt.Printf("%s%s\n", childPrefix, remDel.Render("- "+line))
			}
		}
		for _, line := range strings.Split(e.Replacement, "\n") {
			fmt.Printf("%s%s\n", childPrefix, remAdd.Render("+ "+line))
		}
		// childPrefix(6) + "↳ " ≈ 8 chars
		fmt.Printf("%s%s\n", childPrefix, remRsn.Render(truncate(termWidth()-8).Render("↳ "+e.Reason)))
	}
	fmt.Println()
}

// PrintStats renders the top-N violated rules returned by GetStats.
func PrintStats(resp *pb.GetStatsResponse) {
	fmt.Println()
	heading := bold.Render("TOP RULE VIOLATIONS")
	if resp.TotalScans > 0 {
		heading += "  " + muted.Render(fmt.Sprintf("(across %d scan(s))", resp.TotalScans))
	}
	fmt.Println(heading)
	fmt.Println(divider)

	if len(resp.TopViolations) == 0 {
		fmt.Println(muted.Render("  No findings recorded yet."))
		fmt.Println()
		return
	}

	// prefix: "  1.  [HIGH]  PRIV-001  count:999  " ≈ 38 chars
	nameWidth := termWidth() - 38
	for i, v := range resp.TopViolations {
		sevLabel := SevStyle(v.Severity).Render(fmt.Sprintf("[%-6s]", strings.ToUpper(v.Severity)))
		countStr := muted.Render(fmt.Sprintf("×%d", v.Count))
		fmt.Printf("  %2d.  %s  %-8s  %s  %s\n",
			i+1, sevLabel, v.RuleID, countStr, truncate(nameWidth).Render(v.Title))
		if len(v.Standards) > 0 {
			fmt.Printf("         %s  %s\n",
				muted.Render("Standards:"),
				muted.Render(strings.Join(v.Standards, " · ")))
		}
		if v.Domain != "" {
			fmt.Printf("         %s  %s\n\n",
				muted.Render("Domain:   "),
				muted.Render(v.Domain))
		} else {
			fmt.Println()
		}
	}
	fmt.Println(divider)
	fmt.Println()
}
