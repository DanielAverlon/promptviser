package pass2

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		expected []string
	}{
		{
			name:     "No triggers",
			file:     "testdata/no_triggers.yaml",
			expected: nil,
		},
		{
			name:     "Non-YAML content",
			file:     "testdata/non_yaml.txt",
			expected: []string{"missing_model_id"},
		},
		{
			name:     "User facing flag",
			file:     "testdata/user_facing.yaml",
			expected: []string{"is_user_facing"},
		},
		{
			name:     "High-risk domain",
			file:     "testdata/high_risk_domain.yaml",
			expected: []string{"domain:medical"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := os.ReadFile(tt.file)
			require.NoError(t, err)
			triggers := Analyze(content)
			assert.Equal(t, tt.expected, triggers)
		})
	}
}
