package reporter

import (
	"encoding/json"
	"os"
	"testing"

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
