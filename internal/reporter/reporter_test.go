package reporter

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/diff"
	"github.com/effective-security/promptviser/internal/llm"
	"github.com/stretchr/testify/require"
)

func Test_PrintScanSummary(t *testing.T) {
	content, err := os.ReadFile("example_resp.json")
	require.NoError(t, err)

	var matchRulesResp *pb.MatchRulesResponse
	err = json.Unmarshal(content, &matchRulesResp)
	require.NoError(t, err)

	PrintScanSummary(matchRulesResp, "scan-1234")
	// t.Fail() // uncomment to see output
}

func Test_PrintRulesList(t *testing.T) {
	content, err := os.ReadFile("example_rules.json")
	require.NoError(t, err)

	var getRulesResp *pb.GetRulesResponse
	err = json.Unmarshal(content, &getRulesResp)
	require.NoError(t, err)

	PrintRulesList(getRulesResp)
	// t.Fail() // uncomment to see output
}

func Test_ShortPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"Shorten home path", "/home/user/project/file.txt", "project/file.txt"},
		{"Shorten root path", "/project/file.txt", "project/file.txt"},
		{"No shortening", "C:\\Users\\user\\project\\file.txt", "C:\\Users\\user\\project\\file.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShortPath(tt.path)
			require.Equal(t, tt.expected, result)
		})
	}
}

func Test_SevStyle(t *testing.T) {
	tests := []struct {
		name     string
		severity string
	}{
		{"High severity", "high"},
		{"Medium severity", "medium"},
		{"Low severity", "low"},
		{"Unknown severity", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			style := SevStyle(tt.severity)
			require.NotNil(t, style)
			// We could add more assertions here to check the actual style properties if needed
		})
	}
}

func Test_IsTerminal(t *testing.T) {
	// This test is a bit tricky since it depends on the environment.
	// We can at least check that it returns a boolean without panicking.
	result := IsTerminal()
	require.IsType(t, true, result)
}

func Test_PrintScansList(t *testing.T) {
	scans := map[string][]*ScanInfo{
		"/path/to/project1": {
			{ID: "scan-1234", Filename: "project1_scan-1234.json", ProjectPath: "/path/to/project1", Timestamp: time.Now()},
			{ID: "scan-5678", Filename: "project1_scan-5678.json", ProjectPath: "/path/to/project1", Timestamp: time.Now()},
		},
		"/path/to/project2": {
			{ID: "scan-9012", Filename: "project2_scan-9012.json", ProjectPath: "/path/to/project2", Timestamp: time.Now()},
		},
	}

	PrintScansList(scans)
	// t.Fail() // uncomment to see output
}

func Test_PrintRemediations(t *testing.T) {
	fileName := "example_remediations.json"
	edits := []llm.RemediationEdit{
		{
			RuleID:      "rule-1234",
			Severity:    "high",
			Original:    "{{.UserInput}}",
			Replacement: "[REDACTED USER INPUT]",
			Reason:      "The original prompt contains sensitive information that could lead to data leaks.",
		},
		{
			RuleID:      "rule-5678",
			Severity:    "medium",
			Original:    "This is a medium severity issue that should be addressed.",
			Replacement: "Consider rephrasing the prompt to improve clarity.",
			Reason:      "The original prompt is ambiguous and may lead to misunderstandings.",
		},
	}

	PrintRemediations(fileName, edits)
	//t.Fail() // uncomment to see output
}

func Test_PrintScanDiff(t *testing.T) {
	scanDiff := &diff.ScanDiff{
		OnlyInA: []diff.DiffEntry{
			{ID: "SEC-001", RuleName: "Missing delimiter", Severity: "High", FilePath: "prompts/agent.yaml"},
		},
		OnlyInB: []diff.DiffEntry{
			{ID: "ACC-001", RuleName: "No disclosure", Severity: "Medium", FilePath: "prompts/chat.yaml"},
		},
		InBoth: []diff.DiffEntry{
			{ID: "PRIV-001", RuleName: "PII variable", Severity: "High", FilePath: "prompts/shared.yaml"},
		},
	}

	PrintScanDiff(scanDiff, "scan-aaa", "scan-bbb")
	// t.Fail() // uncomment to see output
}

func Test_PrintScanDiff_Empty(t *testing.T) {
	PrintScanDiff(&diff.ScanDiff{}, "scan-aaa", "scan-bbb")
}

func Test_PrintStats_WithViolations(t *testing.T) {
	resp := &pb.GetStatsResponse{
		TotalScans: 5,
		TopViolations: []*pb.RuleViolationCount{
			{RuleID: "SEC-001", Title: "Missing delimiter", Severity: "High", Domain: "Security", Standards: []string{"OWASP LLM01"}, Count: 42},
			{RuleID: "PRIV-001", Title: "PII variable", Severity: "High", Domain: "Privacy", Standards: []string{"GDPR Art.25"}, Count: 17},
			{RuleID: "REL-003", Title: "No human oversight", Severity: "Medium", Count: 3},
		},
	}

	PrintStats(resp)
	// t.Fail() // uncomment to see output
}

func Test_PrintStats_Empty(t *testing.T) {
	PrintStats(&pb.GetStatsResponse{})
}
