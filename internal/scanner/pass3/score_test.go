package pass3

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_buildUserMessage(t *testing.T) {
	content := []byte("What is the capital of France?")
	staticTriggers := []string{"MISSING_DELIMITER", "MISSING_PERSONA"}
	metadataFlags := []string{"is_user_facing"}

	data, err := os.ReadFile("testdata/expected_user_message.md")
	require.NoError(t, err)

	expected := string(data)
	result := buildUserMessage(content, staticTriggers, metadataFlags)
	assert.Equal(t, expected, result)
}

func Test_Score(t *testing.T) {
	t.Skip()
	// This is a placeholder test. In a real test, you'd use a mock LLM provider
}
