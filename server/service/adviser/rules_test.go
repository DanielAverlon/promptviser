package adviser_test

import (
	"context"
	"testing"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/mocks/mockadviserdb"
	"github.com/effective-security/promptviser/server/service/adviser"
	"github.com/stretchr/testify/assert"
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
		Scores: []*pb.DimensionScore{
			{Dimension: "output_consequence", Score: 0.85},
			{Dimension: "human_oversight", Score: 0.12},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)

	ruleIDs := findingIDs(resp.Findings)
	assert.Contains(t, ruleIDs, "REL-003", "expected REL-003 to fire on high consequence + low oversight")
	assert.NotContains(t, ruleIDs, "PRIV-001", "PRIV-001 requires PII_VARIABLE static trigger")
	assert.NotContains(t, ruleIDs, "SEC-001", "SEC-001 requires MISSING_DELIMITER static trigger")
}

func TestMatchRules_PIIExposureWithStaticTrigger_ReturnsPRIV001(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		Scores: []*pb.DimensionScore{
			{Dimension: "pii_exposure", Score: 0.85},
		},
		StaticTriggers: []string{"PII_VARIABLE"},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)

	ruleIDs := findingIDs(resp.Findings)
	assert.Contains(t, ruleIDs, "PRIV-001")
	assert.NotContains(t, ruleIDs, "REL-003", "REL-003 requires both score thresholds to be met")
}

func TestMatchRules_MissingDelimiter_ReturnsSEC001(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		StaticTriggers: []string{"MISSING_DELIMITER"},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)

	ruleIDs := findingIDs(resp.Findings)
	assert.Contains(t, ruleIDs, "SEC-001")
}

func TestMatchRules_UserFacingMetaFlag_ReturnsACC001(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
		MetadataFlags:  []string{"is_user_facing"},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)

	ruleIDs := findingIDs(resp.Findings)
	assert.Contains(t, ruleIDs, "ACC-001")
}

func TestMatchRules_MultipleTriggersAtOnce(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	// Simulate a worst-case prompt: PII variable + missing delimiter
	// + high consequence + low oversight + user-facing + AI disclosure missing.
	req := &pb.MatchRulesRequest{
		Scores: []*pb.DimensionScore{
			{Dimension: "pii_exposure", Score: 0.85},
			{Dimension: "output_consequence", Score: 0.90},
			{Dimension: "human_oversight", Score: 0.10},
		},
		StaticTriggers: []string{"PII_VARIABLE", "MISSING_DELIMITER", "MISSING_AI_DISCLOSURE"},
		MetadataFlags:  []string{"is_user_facing"},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)

	ruleIDs := findingIDs(resp.Findings)
	assert.Contains(t, ruleIDs, "PRIV-001")
	assert.Contains(t, ruleIDs, "SEC-001")
	assert.Contains(t, ruleIDs, "REL-003")
	assert.Contains(t, ruleIDs, "ACC-001")
}

func TestMatchRules_NilRequest_ReturnsError(t *testing.T) {
	svc, _ := newService(t)

	_, err := svc.MatchRules(context.Background(), nil)
	require.Error(t, err)
}

func TestMatchRules_ScoreBelowThreshold_NoMatch(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	// consequence is below the 0.75 threshold for REL-003
	req := &pb.MatchRulesRequest{
		Scores: []*pb.DimensionScore{
			{Dimension: "output_consequence", Score: 0.5},
			{Dimension: "human_oversight", Score: 0.1},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	assert.NotContains(t, findingIDs(resp.Findings), "REL-003")
}

// ----- GetRules tests ---------------------------------------------------------

func TestGetRules_NoFilter_ReturnsAll(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	resp, err := svc.GetRules(context.Background(), &pb.GetRulesRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.Rules, len(sampleRules))
}

func TestGetRules_DomainFilter(t *testing.T) {
	svc, mockDB := newService(t)

	filtered := []*adviserdb.Rule{sampleRules[1]} // PRIV-001 only
	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "Data Privacy & Confidentiality", "").
		Return(filtered, nil)

	resp, err := svc.GetRules(context.Background(), &pb.GetRulesRequest{
		Domain: "Data Privacy & Confidentiality",
	})
	require.NoError(t, err)
	require.Len(t, resp.Rules, 1)
	assert.Equal(t, "PRIV-001", resp.Rules[0].RuleID)
}

func TestGetRules_NilRequest_ReturnsError(t *testing.T) {
	svc, _ := newService(t)

	_, err := svc.GetRules(context.Background(), nil)
	require.Error(t, err)
}

// ----- helpers ----------------------------------------------------------------

func findingIDs(findings []*pb.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}
