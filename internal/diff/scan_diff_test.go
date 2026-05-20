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
