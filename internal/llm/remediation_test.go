package llm

import (
	"context"
	"testing"

	"github.com/effective-security/promptviser/api/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_RenderRemediationMessage(t *testing.T) {
	tests := []struct {
		name           string
		promptText     string
		violations     []RemediationViolation
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:       "No violations",
			promptText: "This is a test prompt.",
			violations: []RemediationViolation{},
			mustContain: []string{
				"### BEGIN PROMPT UNDER REVIEW",
				"This is a test prompt.",
				"### END PROMPT UNDER REVIEW ###",
				"## Violations to remediate",
			},
			mustNotContain: []string{"[High]", "[Medium]", "Trigger type:"},
		},
		{
			name:       "Single violation",
			promptText: "You are a helpful assistant. User input: {{.Input}}",
			violations: []RemediationViolation{
				{RuleID: "SEC-001", RuleName: "Missing delimiter", Severity: "High", TriggerType: "static", Remediation: "Wrap user input in structural delimiters."},
			},
			mustContain: []string{
				"### BEGIN PROMPT UNDER REVIEW",
				"You are a helpful assistant.",
				"## Violations to remediate",
				"[High] SEC-001 — Missing delimiter",
				"Trigger type: static",
				"Suggested approach: Wrap user input in structural delimiters.",
			},
		},
		{
			name:       "Multiple violations",
			promptText: "Answer the question: {{.UserQuestion}}",
			violations: []RemediationViolation{
				{RuleID: "SEC-001", RuleName: "Missing delimiter", Severity: "High", TriggerType: "static", Remediation: "Add delimiters."},
				{RuleID: "PRIV-001", RuleName: "PII variable", Severity: "Medium", TriggerType: "combined", Remediation: "Use redacted placeholder."},
			},
			mustContain: []string{
				"[High] SEC-001 — Missing delimiter",
				"Trigger type: static",
				"[Medium] PRIV-001 — PII variable",
				"Trigger type: combined",
				"Suggested approach: Use redacted placeholder.",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := RenderRemediationMessage(tt.promptText, tt.violations)
			require.NoError(t, err)
			for _, s := range tt.mustContain {
				assert.Contains(t, result, s)
			}
			for _, s := range tt.mustNotContain {
				assert.NotContains(t, result, s)
			}
		})
	}
}

func Test_parseRemediations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *RemediationResult
	}{
		{
			name: "Valid JSON",
			input: `{
				"remediations": [
					{"rule_id": "SEC-001", "severity": "High", "original": "foo", "replacement": "bar", "reason": "because"}
				]
			}`,
			expected: &RemediationResult{
				Remediations: []RemediationEdit{
					{RuleID: "SEC-001", Severity: "High", Original: "foo", Replacement: "bar", Reason: "because"},
				},
			},
		},
		{
			name:     "Empty remediations array",
			input:    `{"remediations": []}`,
			expected: &RemediationResult{Remediations: []RemediationEdit{}},
		},
		{
			name:  "Markdown json code fence",
			input: "```json\n{\"remediations\": [{\"rule_id\": \"PE-001\", \"severity\": \"Low\", \"original\": \"\", \"replacement\": \"You are an AI.\", \"reason\": \"No persona.\"}]}\n```",
			expected: &RemediationResult{
				Remediations: []RemediationEdit{
					{RuleID: "PE-001", Severity: "Low", Original: "", Replacement: "You are an AI.", Reason: "No persona."},
				},
			},
		},
		{
			name:  "Markdown plain code fence",
			input: "```\n{\"remediations\": []}\n```",
			expected: &RemediationResult{
				Remediations: []RemediationEdit{},
			},
		},
		{
			name:     "Invalid JSON",
			input:    `not valid json`,
			expected: nil,
		},
		{
			name:  "Multiple remediations",
			input: `{"remediations": [{"rule_id": "A", "severity": "High", "original": "x", "replacement": "y", "reason": "r1"}, {"rule_id": "B", "severity": "Low", "original": "p", "replacement": "q", "reason": "r2"}]}`,
			expected: &RemediationResult{
				Remediations: []RemediationEdit{
					{RuleID: "A", Severity: "High", Original: "x", Replacement: "y", Reason: "r1"},
					{RuleID: "B", Severity: "Low", Original: "p", Replacement: "q", Reason: "r2"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseRemediations(tt.input)
			if tt.expected == nil {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func Test_stubProvider_Score(t *testing.T) {
	s := &stubProvider{}
	scores, err := s.Score(context.Background(), []byte("some prompt"))
	require.NoError(t, err)
	assert.Len(t, scores, 6)

	dims := make(map[string]float64, len(scores))
	for _, d := range scores {
		dims[d.Dimension] = float64(d.Score)
	}
	assert.Contains(t, dims, "bias_risk")
	assert.Contains(t, dims, "pii_exposure")
	assert.Contains(t, dims, "human_oversight")
	assert.Contains(t, dims, "output_consequence")
	assert.Contains(t, dims, "data_persistence")
	assert.Contains(t, dims, "refusal_instructions")
	for dim, score := range dims {
		assert.InDelta(t, 0.5, score, 0.0, "expected score 0.5 for dimension %s", dim)
	}
}

func Test_stubProvider_Remediate(t *testing.T) {
	s := &stubProvider{}
	result, err := s.Remediate(context.Background(), []byte("some prompt"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Remediations)

	for _, edit := range result.Remediations {
		assert.NotEmpty(t, edit.RuleID, "RuleID should not be empty")
		assert.NotEmpty(t, edit.Severity, "Severity should not be empty")
		assert.NotEmpty(t, edit.Reason, "Reason should not be empty")
		assert.NotEmpty(t, edit.Replacement, "Replacement should not be empty")
	}

	ruleIDs := make([]string, len(result.Remediations))
	for i, e := range result.Remediations {
		ruleIDs[i] = e.RuleID
	}
	assert.Contains(t, ruleIDs, "SEC-001")
	assert.ElementsMatch(t, []string{"SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006"}, ruleIDs)
}

func Test_stubProvider_implements_Provider(t *testing.T) {
	var _ Provider = &stubProvider{}
}

// Compile-time check: RemediationResult / RemediationEdit fields match JSON tags.
func Test_RemediationEdit_JSONRoundtrip(t *testing.T) {
	original := RemediationResult{
		Remediations: []RemediationEdit{
			{RuleID: "X-001", Severity: "High", Original: "old text", Replacement: "new text", Reason: "why"},
		},
	}
	result, err := parseRemediations(`{"remediations":[{"rule_id":"X-001","severity":"High","original":"old text","replacement":"new text","reason":"why"}]}`)
	require.NoError(t, err)
	assert.Equal(t, &original, result)

	// Ensure pb type is usable (import smoke-test)
	_ = []*pb.DimensionScore{}
}
