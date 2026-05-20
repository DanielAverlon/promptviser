package diff

import (
	"sort"

	"github.com/effective-security/promptviser/api/pb"
)

type ScanDiff struct {
	OnlyInA []DiffEntry
	OnlyInB []DiffEntry
	InBoth  []DiffEntry
}

type DiffEntry struct {
	ID          string
	RuleName    string
	Description string
	Severity    string
	FilePath    string
}

func CompareScans(scanA, scanB *pb.MatchRulesResponse) (*ScanDiff, error) {
	aByFile := findingsByFile(scanA)
	bByFile := findingsByFile(scanB)

	aIndex := flattenFindings(aByFile)
	bIndex := flattenFindings(bByFile)

	out := &ScanDiff{}
	for key, entry := range aIndex {
		if _, ok := bIndex[key]; ok {
			out.InBoth = append(out.InBoth, entry)
			continue
		}
		out.OnlyInA = append(out.OnlyInA, entry)
	}

	for key, entry := range bIndex {
		if _, ok := aIndex[key]; ok {
			continue
		}
		out.OnlyInB = append(out.OnlyInB, entry)
	}

	sortEntries(out.OnlyInA)
	sortEntries(out.OnlyInB)
	sortEntries(out.InBoth)

	return out, nil
}

// findingsByFile normalizes findings into a file-path keyed map for easier diffing.
func findingsByFile(scan *pb.MatchRulesResponse) map[string][]*pb.Finding {
	byFile := map[string][]*pb.Finding{}
	if scan == nil {
		return byFile
	}

	for _, pf := range scan.Findings {
		if pf == nil || len(pf.Findings) == 0 {
			continue
		}
		byFile[pf.FileName] = append(byFile[pf.FileName], pf.Findings...)
	}

	return byFile
}

func flattenFindings(byFile map[string][]*pb.Finding) map[string]DiffEntry {
	index := make(map[string]DiffEntry)
	for filePath, findings := range byFile {
		for _, f := range findings {
			if f == nil {
				continue
			}
			key := filePath + "|" + f.RuleID + "|" + f.Title + "|" + f.Severity
			index[key] = DiffEntry{
				ID:          f.RuleID,
				RuleName:    f.Title,
				Description: f.Title,
				Severity:    f.Severity,
				FilePath:    filePath,
			}
		}
	}
	return index
}

func sortEntries(entries []DiffEntry) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]

		// Define severity order
		severityOrder := map[string]int{
			"Critical": 1,
			"High":     2,
			"Medium":   3,
			"Low":      4,
			"Info":     5,
		}

		// Compare by severity using the defined order
		if severityOrder[a.Severity] != severityOrder[b.Severity] {
			return severityOrder[a.Severity] < severityOrder[b.Severity]
		}

		// Fallback comparisons
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.RuleName != b.RuleName {
			return a.RuleName < b.RuleName
		}
		return a.Description < b.Description
	})
}
