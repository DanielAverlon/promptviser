package adviser

import (
	"context"
	"strings"

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

	scoreMap := buildScoreMap(req.Scores)
	staticSet := buildStringSet(req.StaticTriggers)
	metaSet := buildStringSet(req.MetadataFlags)

	var findings []*pb.Finding
	for _, r := range rules {
		if ruleMatches(r, scoreMap, staticSet, metaSet) {
			findings = append(findings, ruleToFinding(r))
		}
	}

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

// ruleMatches returns true when the rule's trigger conditions are satisfied by
// the provided inputs.
func ruleMatches(
	r *adviserdb.Rule,
	scoreMap map[string]float32,
	staticSet map[string]struct{},
	metaSet map[string]struct{},
) bool {
	// Static triggers: at least one must appear in staticSet.
	if len(r.StaticTriggers) > 0 {
		if !anyInSet(r.StaticTriggers, staticSet) {
			return false
		}
	}

	// Metadata flags: all required flags must be present.
	if len(r.MetadataFlags) > 0 {
		if !anyInSet(r.MetadataFlags, metaSet) {
			return false
		}
	}

	// Score triggers: every threshold condition must be satisfied.
	for key, threshold := range r.ScoreTriggers {
		if strings.HasSuffix(key, "_gt") {
			dim := strings.TrimSuffix(key, "_gt")
			if score, ok := scoreMap[dim]; !ok || score <= float32(threshold) {
				return false
			}
		} else if strings.HasSuffix(key, "_lt") {
			dim := strings.TrimSuffix(key, "_lt")
			if score, ok := scoreMap[dim]; !ok || score >= float32(threshold) {
				return false
			}
		}
	}

	// A rule with no triggers of any kind is informational and always fires.
	return true
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

func buildScoreMap(scores []*pb.DimensionScore) map[string]float32 {
	m := make(map[string]float32, len(scores))
	for _, s := range scores {
		if s != nil {
			m[s.Dimension] = s.Score
		}
	}
	return m
}

func buildStringSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, item := range items {
		m[item] = struct{}{}
	}
	return m
}

func anyInSet(items []string, set map[string]struct{}) bool {
	for _, item := range items {
		if _, ok := set[item]; ok {
			return true
		}
	}
	return false
}
