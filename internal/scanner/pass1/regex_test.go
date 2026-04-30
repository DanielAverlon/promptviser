package pass1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_regex(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name: "No triggers",
			content: `
				This is a simple prompt file with no issues.
				It contains static text and no variables.
			`,
			expected: nil,
		},
		{
			name: "Missing delimiter",
			content: `
				Write a response to the following user input:
				{{.UserInput}}
			`,
			expected: []string{"MISSING_DELIMITER"},
		},
		{
			name: "Token-heavy prompt",
			content: `
				This prompt is very long and contains many tokens. ` + strings.Repeat("Lorem ipsum dolor sit amet, ", 1000),
			expected: []string{"TOKEN_HEAVY_PROMPT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			triggers := Check([]byte(tt.content))
			assert.ElementsMatch(t, triggers, tt.expected)
		})
	}
}
