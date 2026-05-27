package adviser

import (
	"context"

	pb "github.com/effective-security/promptviser/api/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetStats returns aggregated rule-violation counts across all recorded scans.
func (s *Service) GetStats(ctx context.Context, req *pb.GetStatsRequest) (*pb.GetStatsResponse, error) {
	limit := 10
	if req != nil && req.Limit > 0 {
		limit = int(req.Limit)
	}

	entries, err := s.db.GetRuleStats(ctx, limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch stats: %v", err)
	}

	violations := make([]*pb.RuleViolationCount, 0, len(entries))
	for _, e := range entries {
		violations = append(violations, &pb.RuleViolationCount{
			RuleID:    e.RuleID,
			Title:     e.Name,
			Severity:  e.Severity,
			Domain:    e.Domain,
			Standards: e.Standards,
			Count:     e.Count,
		})
	}

	return &pb.GetStatsResponse{TopViolations: violations}, nil
}
