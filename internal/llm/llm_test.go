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
				{Dimension: "risk", Score: 0.8},
				{Dimension: "complexity", Score: 0.5},
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
				{Dimension: "risk", Score: 0.3},
				{Dimension: "complexity", Score: 0.7},
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
