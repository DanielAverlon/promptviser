package adviser_test

import (
	"context"
	"testing"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/mocks/mockadviserdb"
	"github.com/effective-security/promptviser/server/service/adviser"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// newService creates an adviser.Service with a mock DB, bypassing the dig
// container so tests can run without a live gRPC server or database.
func newService(t *testing.T) (*adviser.Service, *mockadviserdb.MockAdviserDb) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockDB := mockadviserdb.NewMockAdviserDb(ctrl)
	svc := adviser.NewServiceForTest(mockDB)
	return svc, mockDB
}

// ----- sample rules used across tests ----------------------------------------

var sampleRules = []*adviserdb.Rule{
	{
		RuleID:         "REL-003",
		Domain:         "Reliability & Safety",
		Name:           "High-stakes output with no human oversight clause",
		Severity:       "High",
		TriggerType:    "score",
		ScoreTriggers:  map[string]float64{"output_consequence_gt": 0.75, "human_oversight_lt": 0.3},
		StaticTriggers: nil,
		MetadataFlags:  nil,
		Remediation:    "Add a human oversight clause.",
		Standards:      []string{"AIUC-1 E1", "EU AI Act Art.14"},
	},
	{
		RuleID:         "PRIV-001",
		Domain:         "Data Privacy & Confidentiality",
		Name:           "PII variable sent to an external model",
		Severity:       "High",
		TriggerType:    "combined",
		ScoreTriggers:  map[string]float64{"pii_exposure_gt": 0.7},
		StaticTriggers: []string{"PII_VARIABLE"},
		MetadataFlags:  nil,
		Remediation:    "Use redacted placeholders.",
		Standards:      []string{"OWASP LLM02", "GDPR Art.25"},
	},
	{
		RuleID:         "SEC-001",
		Domain:         "Security & Injection Resistance",
		Name:           "User input not structurally delimited",
		Severity:       "High",
		TriggerType:    "static",
		ScoreTriggers:  nil,
		StaticTriggers: []string{"MISSING_DELIMITER"},
		MetadataFlags:  nil,
		Remediation:    "Wrap user input with structural delimiters.",
		Standards:      []string{"OWASP LLM01"},
	},
	{
		RuleID:         "ACC-001",
		Domain:         "Accountability & Transparency",
		Name:           "User-facing AI without self-identification",
		Severity:       "High",
		TriggerType:    "combined",
		ScoreTriggers:  nil,
		StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
		MetadataFlags:  []string{"is_user_facing"},
		Remediation:    "Add AI self-identification.",
		Standards:      []string{"EU AI Act Art.50"},
	},
}

// ----- MatchRules tests -------------------------------------------------------

func TestMatchRules_HighConsequenceLowOversight_ReturnsREL003(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName: "prompts/agent.yaml",
				Scores: []*pb.DimensionScore{
					{Dimension: "output_consequence", Score: 0.9},
					{Dimension: "human_oversight", Score: 0.1},
				},
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)
	require.Equal(t, "prompts/agent.yaml", resp.Findings[0].FileName)

	ruleIDs := ruleIDsForFile(resp.Findings, "prompts/agent.yaml")
	require.Contains(t, ruleIDs, "REL-003")
}

func TestMatchRules_StaticTrigger_ReturnsSEC001(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName:       "prompts/chat.yaml",
				StaticTriggers: []string{"MISSING_DELIMITER"},
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)
	require.Equal(t, "prompts/chat.yaml", resp.Findings[0].FileName)

	ruleIDs := ruleIDsForFile(resp.Findings, "prompts/chat.yaml")
	require.Contains(t, ruleIDs, "SEC-001")
	require.NotContains(t, ruleIDs, "REL-003") // score thresholds not met
}

func TestMatchRules_CombinedRule_RequiresBothStaticAndMeta(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName:       "prompts/ui.yaml",
				StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
				MetadataFlags:  []string{"is_user_facing"},
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)

	ruleIDs := ruleIDsForFile(resp.Findings, "prompts/ui.yaml")
	require.Contains(t, ruleIDs, "ACC-001")
}

func TestMatchRules_CombinedRule_MissingMetaFlag_NoMatch(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName:       "prompts/internal.yaml",
				StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
				// is_user_facing flag absent — ACC-001 should not fire
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	// No rules matched — Findings slice should be empty (files with no hits are omitted)
	require.Empty(t, resp.Findings)
}

func TestMatchRules_NilRequest_ReturnsError(t *testing.T) {
	svc, _ := newService(t)

	_, err := svc.MatchRules(context.Background(), nil)
	require.Error(t, err)
}

// ----- helpers ----------------------------------------------------------------

// ruleIDsForFile extracts all matched rule IDs for the first PromptFindings
// entry whose FileName matches. Panics if not found — tests should call
// require.Len(t, resp.Findings, ...) first if needed.
func ruleIDsForFile(findings []*pb.PromptFindings, fileName string) []string {
	for _, pf := range findings {
		if pf.FileName == fileName {
			ids := make([]string, 0, len(pf.Findings))
			for _, f := range pf.Findings {
				ids = append(ids, f.RuleID)
			}
			return ids
		}
	}
	return nil
}
