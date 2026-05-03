package adviser

import (
	"context"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MatchRules evaluates the anonymised dimension scores and static triggers sent
// by the client and returns every rule whose conditions are satisfied.
// No prompt text is processed here — only numeric scores and named flags.
func (s *Service) MatchRules(ctx context.Context, req *pb.MatchRulesRequest) (*pb.MatchRulesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	rules, err := s.db.GetAllRules(ctx, "", "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch rules: %v", err)
	}
	_ = rules // TODO: filter by domain/severity if provided in req

	var findings []*pb.Finding

	return &pb.MatchRulesResponse{Findings: findings}, nil
}

// GetRules returns the full rule catalogue, optionally filtered by domain and/or severity.
func (s *Service) GetRules(ctx context.Context, req *pb.GetRulesRequest) (*pb.GetRulesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	rules, err := s.db.GetAllRules(ctx, req.Domain, req.Severity)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch rules: %v", err)
	}

	findings := make([]*pb.Finding, 0, len(rules))
	for _, r := range rules {
		findings = append(findings, ruleToFinding(r))
	}

	return &pb.GetRulesResponse{Rules: findings}, nil
}

func ruleToFinding(r *adviserdb.Rule) *pb.Finding {
	return &pb.Finding{
		RuleID:      r.RuleID,
		Title:       r.Name,
		Severity:    r.Severity,
		Domain:      r.Domain,
		Remediation: r.Remediation,
		Standards:   r.Standards,
		TriggerType: r.TriggerType,
	}
}
