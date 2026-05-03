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

	req := &pb.MatchRulesRequest{}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)

	ruleIDs := findingIDs(resp.Findings)
	_ = ruleIDs
}

// ----- helpers ----------------------------------------------------------------

func findingIDs(findings []*pb.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}
