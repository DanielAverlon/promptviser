package scanner

import (
	"testing"

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
