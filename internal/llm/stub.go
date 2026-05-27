package llm

import (
	"context"

	pb "github.com/effective-security/promptviser/api/pb"
)

type stubProvider struct{}

func (s *stubProvider) Score(_ context.Context, _ []byte) ([]*pb.DimensionScore, error) {
	return []*pb.DimensionScore{
		{Dimension: "bias_risk", Score: 0.5},
		{Dimension: "data_persistence", Score: 0.5},
		{Dimension: "human_oversight", Score: 0.5},
		{Dimension: "output_consequence", Score: 0.5},
		{Dimension: "pii_exposure", Score: 0.5},
		{Dimension: "refusal_instructions", Score: 0.5},
	}, nil
}

func (s *stubProvider) Remediate(_ context.Context, _ []byte) (*RemediationResult, error) {
	return &RemediationResult{Remediations: []RemediationEdit{
		{RuleID: "SEC-001", Severity: "High", Original: "Contains potentially biased language", Replacement: "Consider rephrasing to be more neutral", Reason: "The prompt may lead to biased outputs. Rephrasing can help mitigate this risk."},
		{RuleID: "SEC-002", Severity: "Medium", Original: "Includes user-specific information", Replacement: "Avoid including user-specific information", Reason: "Storing user-specific information can lead to data persistence issues."},
		{RuleID: "SEC-003", Severity: "Low", Original: "No human oversight", Replacement: "Add a disclaimer that the response is AI-generated", Reason: "Human oversight is important to ensure the accuracy and appropriateness of AI-generated content."},
		{RuleID: "SEC-004", Severity: "Medium", Original: "Unclear consequences", Replacement: "Clarify that the response is for informational purposes only", Reason: "Users should understand the limitations and potential consequences of AI-generated content."},
		{RuleID: "SEC-005", Severity: "High", Original: "Contains PII", Replacement: "Remove or obfuscate any personally identifiable information (PII)", Reason: "Exposing PII can lead to privacy violations and legal issues."},
		{RuleID: "SEC-006", Severity: "Low", Original: "No refusal instructions", Replacement: "Include instructions for the model to refuse generating content if it detects sensitive topics", Reason: "Refusal instructions help prevent the model from generating inappropriate or harmful content."},
	}}, nil
}
