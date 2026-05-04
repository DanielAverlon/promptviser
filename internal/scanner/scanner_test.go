package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/internal/llm"
	advisersvc "github.com/effective-security/promptviser/server/service/adviser"
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

func Test_ScanAndMatchRules(t *testing.T) {
	// A representative subset of rules — static-only and meta-only rules that
	// fire deterministically regardless of LLM scores.
	rules := []*adviserdb.Rule{
		{
			RuleID:         "SEC-001",
			Domain:         "Security & Injection Resistance",
			Name:           "User input not structurally delimited",
			Severity:       "High",
			TriggerType:    "static",
			StaticTriggers: []string{"MISSING_DELIMITER"},
		},
		{
			RuleID:         "SEC-003",
			Domain:         "Security & Injection Resistance",
			Name:           "Excessive tool agency without confirmation gate",
			Severity:       "High",
			TriggerType:    "combined",
			StaticTriggers: []string{"EXCESSIVE_TOOL_AGENCY"},
		},
		{
			RuleID:        "SEC-006",
			Domain:        "Security & Injection Resistance",
			Name:          "No rate limiting or abuse signal in agent prompt",
			Severity:      "Low",
			TriggerType:   "meta",
			MetadataFlags: []string{"no_timeout", "loop_or_batch_context"},
		},
	}

	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{Provider: "stub"})
	require.NoError(t, err)

	fileResults, err := Scan(ctx, "./testdata/fake-project", provider)
	require.NoError(t, err)
	require.NotEmpty(t, fileResults)

	// Match each file result against the rule set.
	type fileFindings struct {
		fileName string
		ruleIDs  []string
	}
	var got []fileFindings
	for _, fr := range fileResults {
		pf := advisersvc.FindingsForFile(fr, rules)
		if len(pf.Findings) == 0 {
			continue
		}
		ids := make([]string, 0, len(pf.Findings))
		for _, f := range pf.Findings {
			ids = append(ids, f.RuleID)
		}
		got = append(got, fileFindings{fileName: pf.FileName, ruleIDs: ids})
	}

	// Every file containing {{.UserInput}} should trigger SEC-001.
	findRuleIDs := func(fileName string) []string {
		for _, ff := range got {
			if ff.fileName == fileName {
				return ff.ruleIDs
			}
		}
		return nil
	}

	assert.Contains(t, findRuleIDs("testdata/fake-project/prompts/patient-intake.yaml"), "SEC-001")
	assert.Contains(t, findRuleIDs("testdata/fake-project/prompts/crisis-support.yaml"), "SEC-001")

	// agent-executor has irreversible tools → SEC-003 and SEC-006.
	// Note: it uses {{.UserTask}} not {{.UserInput}}, so SEC-001 does not fire.
	agentIDs := findRuleIDs("testdata/fake-project/prompts/more/agent-executor.yaml")
	assert.NotContains(t, agentIDs, "SEC-001")
	assert.Contains(t, agentIDs, "SEC-003")
	assert.Contains(t, agentIDs, "SEC-006")
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
