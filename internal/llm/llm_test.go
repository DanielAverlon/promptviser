package llm

import (
	"testing"

	"github.com/effective-security/promptviser/api/pb"
	"github.com/stretchr/testify/assert"
)

func Test_parseScores(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []*pb.DimensionScore
	}{
		{
			name:  "Valid scores",
			input: `{"risk": 0.8, "complexity": 0.5}`,
			expected: []*pb.DimensionScore{
				{Dimension: "complexity", Score: 0.5},
				{Dimension: "risk", Score: 0.8},
			},
		},
		{
			name:     "Empty input",
			input:    `{}`,
			expected: []*pb.DimensionScore{},
		},
		{
			name:     "Invalid JSON",
			input:    `not a json`,
			expected: nil,
		},
		{
			name: "Whitespace and newlines",
			input: `
				      {
					"risk": 0.3,
					"complexity": 0.7
				}    
			`,
			expected: []*pb.DimensionScore{
				{Dimension: "complexity", Score: 0.7},
				{Dimension: "risk", Score: 0.3},
			},
		},
		{
			name: "2 Pass Markdown",
			input: `
				{
  "reasoning": {
    "pii_exposure": "Contains {{.SSN}} and {{.Email}} template vars — high confidence",
    "output_consequence": "Medical domain but response is informational only — moderate"
  },
  "scores": {
    "pii_exposure": 0.9,
    "output_consequence": 0.5
  }
}
			`,
			expected: []*pb.DimensionScore{
				{Dimension: "output_consequence", Score: 0.5},
				{Dimension: "pii_exposure", Score: 0.9},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseScores(tt.input)
			assert.Equal(t, tt.expected, result)
			if tt.expected == nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
