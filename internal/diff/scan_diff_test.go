package diff

import (
	"testing"

	"github.com/effective-security/promptviser/api/pb"
	"github.com/stretchr/testify/require"
)

func TestCompareScans(t *testing.T) {
	scanA := &pb.MatchRulesResponse{
		Findings: []*pb.PromptFindings{
			{
				FileName: "a.txt",
				Findings: []*pb.Finding{
					{RuleID: "SEC-001", Title: "Delimiter missing", Severity: "High"},
					{RuleID: "REL-001", Title: "No uncertainty clause", Severity: "Medium"},
				},
			},
			{
				FileName: "b.txt",
				Findings: []*pb.Finding{
					{RuleID: "PRIV-001", Title: "PII issue", Severity: "High"},
				},
			},
		},
	}

	scanB := &pb.MatchRulesResponse{
		Findings: []*pb.PromptFindings{
			{
				FileName: "a.txt",
				Findings: []*pb.Finding{
					{RuleID: "SEC-001", Title: "Delimiter missing", Severity: "High"},
				},
			},
			{
				FileName: "c.txt",
				Findings: []*pb.Finding{
					{RuleID: "ACC-001", Title: "No disclosure", Severity: "Low"},
				},
			},
		},
	}

	out, err := CompareScans(scanA, scanB)
	require.NoError(t, err)
	require.Len(t, out.InBoth, 1)
	require.Len(t, out.OnlyInA, 2)
	require.Len(t, out.OnlyInB, 1)

	require.Equal(t, "SEC-001", out.InBoth[0].ID)
	require.Equal(t, "Delimiter missing", out.InBoth[0].RuleName)
}

func TestCompareScans_NilInputs(t *testing.T) {
	out, err := CompareScans(nil, nil)
	require.NoError(t, err)
	require.Empty(t, out.InBoth)
	require.Empty(t, out.OnlyInA)
	require.Empty(t, out.OnlyInB)
}

// ----- sortEntries tests ------------------------------------------------------

func Test_sortEntries_BySeverity(t *testing.T) {
	entries := []DiffEntry{
		{ID: "LOW-001", Severity: "Low", FilePath: "a.yaml"},
		{ID: "CRIT-001", Severity: "Critical", FilePath: "a.yaml"},
		{ID: "MED-001", Severity: "Medium", FilePath: "a.yaml"},
		{ID: "HIGH-001", Severity: "High", FilePath: "a.yaml"},
	}
	sortEntries(entries)
	require.Equal(t, "Critical", entries[0].Severity)
	require.Equal(t, "High", entries[1].Severity)
	require.Equal(t, "Medium", entries[2].Severity)
	require.Equal(t, "Low", entries[3].Severity)
}

func Test_sortEntries_SameSeverity_ByFilePath(t *testing.T) {
	entries := []DiffEntry{
		{ID: "SEC-001", Severity: "High", FilePath: "prompts/z.yaml"},
		{ID: "SEC-001", Severity: "High", FilePath: "prompts/a.yaml"},
	}
	sortEntries(entries)
	require.Equal(t, "prompts/a.yaml", entries[0].FilePath)
	require.Equal(t, "prompts/z.yaml", entries[1].FilePath)
}

func Test_sortEntries_SameSeverityAndFile_ByID(t *testing.T) {
	entries := []DiffEntry{
		{ID: "SEC-002", Severity: "High", FilePath: "prompts/agent.yaml"},
		{ID: "SEC-001", Severity: "High", FilePath: "prompts/agent.yaml"},
	}
	sortEntries(entries)
	require.Equal(t, "SEC-001", entries[0].ID)
	require.Equal(t, "SEC-002", entries[1].ID)
}

func Test_sortEntries_UnknownSeverity_SortedFirst(t *testing.T) {
	// Unknown severity maps to 0 in sortEntries, so it sorts before "Critical" (1).
	entries := []DiffEntry{
		{ID: "A-001", Severity: "High", FilePath: "a.yaml"},
		{ID: "X-001", Severity: "Unknown", FilePath: "a.yaml"},
	}
	sortEntries(entries)
	require.Equal(t, "Unknown", entries[0].Severity)
	require.Equal(t, "High", entries[1].Severity)
}

func Test_sortEntries_Empty_DoesNotPanic(t *testing.T) {
	require.NotPanics(t, func() { sortEntries(nil) })
	require.NotPanics(t, func() { sortEntries([]DiffEntry{}) })
}
