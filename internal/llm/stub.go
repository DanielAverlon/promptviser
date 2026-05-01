package llm

import (
	"context"

	pb "github.com/effective-security/promptviser/api/pb"
)

type stubProvider struct{}

func (s *stubProvider) Score(_ context.Context, _ []byte) ([]*pb.DimensionScore, error) {
	return []*pb.DimensionScore{
		{Dimension: "pii_exposure", Score: 0.5},
		{Dimension: "output_consequence", Score: 0.5},
		{Dimension: "human_oversight", Score: 0.5},
		{Dimension: "data_persistence", Score: 0.5},
		{Dimension: "refusal_instructions", Score: 0.5},
		{Dimension: "bias_risk", Score: 0.5},
	}, nil
}
