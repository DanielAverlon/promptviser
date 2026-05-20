package reporter

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/effective-security/promptviser/api/pb"
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
