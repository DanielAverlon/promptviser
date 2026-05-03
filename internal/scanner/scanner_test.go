package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/effective-security/promptviser/internal/llm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_collectPromptFiles(t *testing.T) {
	dir := "./testdata/fake-project"
	expectedFiles := []string{
		"testdata/fake-project/prompts/patient-intake.yaml",
		"testdata/fake-project/prompts/rag-search.yaml",
		"testdata/fake-project/prompts/more/hiring-bot.yaml",
		"testdata/fake-project/prompts/crisis-support.yaml",
		"testdata/fake-project/prompts/more/agent-executor.yaml",
	}

	// Test with a directory path
	files, err := collectPromptFiles(dir)
	require.NoError(t, err)
	require.NotEmpty(t, files)
	assert.ElementsMatch(t, files, expectedFiles)

	// Test with a file path
	path := "testdata/fake-project/prompts/patient-intake.yaml"
	files, err = collectPromptFiles(path)
	require.NoError(t, err)
	assert.ElementsMatch(t, files, []string{path})

	// Test with a non-existent path
	_, err = collectPromptFiles("nonexistent/path")
	require.Error(t, err)

	// Test with a path that has no prompt files
	files, err = collectPromptFiles("testdata/fake-project/empty-dir")
	require.NoError(t, err)
	assert.Empty(t, files)
}

func Test_Scan(t *testing.T) {
	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{
		Provider: "stub",
	})
	require.NoError(t, err)

	dir := "./testdata/fake-project"
	results, err := Scan(ctx, dir, provider)
	require.NoError(t, err)
	require.NotNil(t, results)

	// Check that we got some triggers and scores
	for _, result := range results {
		assert.NotNil(t, result.StaticTriggers)
		assert.NotNil(t, result.Scores)
	}
}

func Test_ScanReal(t *testing.T) {
	t.Skip()
	apiKey := "" // set your OpenAI API key here for testing

	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{
		Provider:   "azure",
		Model:      "gpt-5.1",
		BaseURL:    "https://secdi-ai-dev.openai.azure.com/",
		APIKey:     apiKey,
		APIVersion: "2025-04-01-preview",
	})
	require.NoError(t, err)

	dir := "./testdata/fake-project"
	results, err := Scan(ctx, dir, provider)
	require.NoError(t, err)
	require.NotNil(t, results)

	// Print results for manual inspection
	jsonResults, _ := json.MarshalIndent(results, "", "  ")
	fmt.Printf("Scan results:\n%s\n", string(jsonResults))
	t.Fail()
}
