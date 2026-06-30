package scanner

// integration_test.go runs the full scan pipeline against every prompt file in
// testdata/fake-project/ and diffs the resulting rule findings against a curated
// expected/ JSON fixture for each file.
//
// Design constraints:
//   - Uses the stub LLM provider (no API keys required).
//   - Because the stub returns 0.5 for all scores, only rules whose
//     score_triggers are empty ({}) fire deterministically.  Score-dependent
//     rules (PRIV-001, REL-003, REL-005, ACC-003, …) are intentionally absent
//     from must_contain — they are tested with a real LLM in Test_ScanReal.
//   - Expected fixtures live in testdata/fake-project/expected/<stem>.json and
//     carry two keys: "must_contain" and "must_not_contain".

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/internal/llm"
	advisersvc "github.com/effective-security/promptviser/server/service/adviser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deterministicRules is the subset of the production rule catalogue whose
// score_triggers are empty, meaning they fire purely on static regex signals
// and/or YAML metadata flags — fully deterministic with any LLM provider.
var deterministicRules = []*adviserdb.Rule{
	// Data Privacy & Confidentiality
	{
		RuleID: "PRIV-003", Domain: "Data Privacy & Confidentiality",
		Name: "Hardcoded secret or credential in prompt", Severity: "High",
		TriggerType: "static", StaticTriggers: []string{"HARDCODED_SECRET"},
	},
	{
		RuleID: "PRIV-004", Domain: "Data Privacy & Confidentiality",
		Name: "System prompt leakage risk", Severity: "High",
		TriggerType: "combined", StaticTriggers: []string{"CONFIDENTIALITY_INSTRUCTION"},
	},
	// Security & Injection Resistance
	{
		RuleID: "SEC-001", Domain: "Security & Injection Resistance",
		Name: "User input not structurally delimited", Severity: "High",
		TriggerType: "static", StaticTriggers: []string{"MISSING_DELIMITER"},
	},
	{
		RuleID: "SEC-002", Domain: "Security & Injection Resistance",
		Name: "External content ingestion without trust boundary", Severity: "High",
		TriggerType: "combined", StaticTriggers: []string{"EXTERNAL_CONTENT_INGESTION"},
	},
	{
		RuleID: "SEC-003", Domain: "Security & Injection Resistance",
		Name: "Excessive tool agency without confirmation gate", Severity: "High",
		TriggerType: "combined", StaticTriggers: []string{"EXCESSIVE_TOOL_AGENCY"},
	},
	{
		RuleID: "SEC-004", Domain: "Security & Injection Resistance",
		Name: "Unsanitized output destination", Severity: "High",
		TriggerType: "combined", StaticTriggers: []string{"UNSANITIZED_OUTPUT"},
	},
	{
		RuleID: "SEC-005", Domain: "Security & Injection Resistance",
		Name: "Multi-agent trust boundary not declared", Severity: "High",
		TriggerType: "combined", StaticTriggers: []string{"MULTI_AGENT_REFERENCE"},
	},
	{
		RuleID: "SEC-006", Domain: "Security & Injection Resistance",
		Name: "No rate limiting or abuse signal in agent prompt", Severity: "Low",
		TriggerType: "meta", MetadataFlags: []string{"no_timeout", "loop_or_batch_context"},
	},
	// Reliability & Safety
	{
		RuleID: "REL-002", Domain: "Reliability & Safety",
		Name: "RAG prompt without citation requirement", Severity: "High",
		TriggerType: "static", StaticTriggers: []string{"RAG_WITHOUT_CITATION"},
	},
	{
		RuleID: "REL-006", Domain: "Reliability & Safety",
		Name: "Agentic loop with no termination condition", Severity: "Medium",
		TriggerType: "combined", StaticTriggers: []string{"AGENTIC_LOOP_NO_TERMINATION"},
	},
	// Accountability & Transparency
	{
		RuleID: "ACC-001", Domain: "Accountability & Transparency",
		Name: "User-facing AI without self-identification", Severity: "High",
		TriggerType:    "combined",
		StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
		MetadataFlags:  []string{"is_user_facing"},
	},
	{
		RuleID: "ACC-002", Domain: "Accountability & Transparency",
		Name: "No version or model traceability metadata", Severity: "Low",
		TriggerType: "meta", MetadataFlags: []string{"missing_model_id"},
	},
	{
		RuleID: "ACC-005", Domain: "Accountability & Transparency",
		Name: "Deepfake or synthetic media generation without disclosure", Severity: "High",
		TriggerType: "static", StaticTriggers: []string{"SYNTHETIC_MEDIA_GENERATION"},
	},
	// Prompt Engineering
	{
		RuleID: "PE-001", Domain: "Prompt Engineering",
		Name: "No persona or role definition", Severity: "Low",
		TriggerType: "static", StaticTriggers: []string{"MISSING_PERSONA"},
	},
	{
		RuleID: "PE-005", Domain: "Prompt Engineering",
		Name: "Prompt relies entirely on negative directives", Severity: "Medium",
		TriggerType: "static", StaticTriggers: []string{"NEGATIVE_ONLY_INSTRUCTION"},
	},
	{
		RuleID: "PE-006", Domain: "Prompt Engineering",
		Name: "Prompt exceeds recommended token budget", Severity: "Low",
		TriggerType: "static", StaticTriggers: []string{"TOKEN_HEAVY_PROMPT"},
	},
	{
		RuleID: "PE-007", Domain: "Prompt Engineering",
		Name: "Conflicting instructions detected", Severity: "Low",
		TriggerType: "combined", StaticTriggers: []string{"CONFLICTING_INSTRUCTIONS"},
	},
}

// expectedFindings is the on-disk format for each fixture file.
type expectedFindings struct {
	MustContain    []string `json:"must_contain"`
	MustNotContain []string `json:"must_not_contain"`
}

func TestIntegration_FakeProject(t *testing.T) {
	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{Provider: "stub"})
	require.NoError(t, err)

	// Scan every prompt file in fake-project.
	fileResults, err := Scan(ctx, "./testdata/fake-project", provider)
	require.NoError(t, err)
	require.NotEmpty(t, fileResults)

	// Build a lookup: normalised filename stem → rule IDs that fired.
	firedByFile := make(map[string][]string, len(fileResults))
	for _, fr := range fileResults {
		pf := advisersvc.FindingsForFile(fr, deterministicRules)
		ids := make([]string, 0, len(pf.Findings))
		for _, f := range pf.Findings {
			ids = append(ids, f.RuleID)
		}
		// Key on the base filename without directory prefix for easy lookup.
		stem := strings.TrimSuffix(filepath.Base(fr.FileName), ".yaml")
		firedByFile[stem] = ids
	}

	// Walk expected/ and assert each fixture.
	expectedDir := "./testdata/fake-project/expected"
	entries, err := os.ReadDir(expectedDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries, "expected/ directory should contain fixture files")

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		stem := strings.TrimSuffix(entry.Name(), ".json")

		t.Run(stem, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(expectedDir, entry.Name()))
			require.NoError(t, err)

			var exp expectedFindings
			require.NoError(t, json.Unmarshal(raw, &exp))

			fired := firedByFile[stem]

			for _, want := range exp.MustContain {
				assert.Contains(t, fired, want,
					"file %s: expected rule %s to fire but it did not (fired: %v)", stem, want, fired)
			}
			for _, unwanted := range exp.MustNotContain {
				assert.NotContains(t, fired, unwanted,
					"file %s: rule %s fired but should not have (fired: %v)", stem, unwanted, fired)
			}
		})
	}
}
