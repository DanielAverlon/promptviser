package reporter

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/effective-security/promptviser/api/pb"
	"golang.org/x/term"
)

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
		fmt.Println("  " + bold.Render(shortPath(ff.FileName)))

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

func shortPath(full string) string {
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
