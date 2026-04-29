package scanner

import (
	"os"
	"path/filepath"
	"strings"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/scanner/pass1"
	"github.com/effective-security/promptviser/internal/scanner/pass2"
	"github.com/effective-security/promptviser/internal/scanner/pass3"
)

// promptExtensions lists the file extensions treated as prompt files.
var promptExtensions = map[string]bool{
	".yaml": true,
	".yml":  true,
	".txt":  true,
	".md":   true,
}

// Result holds the combined output of all three passes across all scanned files.
type Result struct {
	StaticTriggers []string
	MetadataFlags  []string
	Scores         []*pb.DimensionScore
}

// ToMatchRulesRequest converts the scan result into a gRPC request for the server.
// No prompt text is included — only derived signals.
func (r *Result) ToMatchRulesRequest() *pb.MatchRulesRequest {
	return &pb.MatchRulesRequest{
		Scores:         r.Scores,
		MetadataFlags:  dedup(r.MetadataFlags),
		StaticTriggers: dedup(r.StaticTriggers),
	}
}

// Scan walks dir, runs all three passes over every prompt file found, and
// returns the combined Result. Prompt text never leaves this function.
func Scan(dir string) (*Result, error) {
	files, err := collectPromptFiles(dir)
	if err != nil {
		return nil, err
	}

	result := &Result{}

	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		// Pass 1 — regex patterns (no network, no LLM)
		triggers := pass1.Check(content)
		result.StaticTriggers = append(result.StaticTriggers, triggers...)

		// Pass 2 — YAML/AST analysis (no network, no LLM)
		flags := pass2.Analyze(content)
		result.MetadataFlags = append(result.MetadataFlags, flags...)

		// Pass 3 — LLM scoring (calls LLM API locally, no prompt text to server)
		scores, err := pass3.Score(content)
		if err != nil {
			return nil, err
		}
		result.Scores = mergeScores(result.Scores, scores)
	}

	return result, nil
}

// collectPromptFiles returns all prompt files under dir recursively.
func collectPromptFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// skip hidden dirs like .git
			if strings.HasPrefix(d.Name(), ".") && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if promptExtensions[strings.ToLower(filepath.Ext(path))] {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// mergeScores averages duplicate dimensions across files so the server
// receives one score per dimension regardless of how many files were scanned.
func mergeScores(existing, incoming []*pb.DimensionScore) []*pb.DimensionScore {
	index := make(map[string]int, len(existing))
	counts := make(map[string]int, len(existing))
	out := make([]*pb.DimensionScore, len(existing))
	copy(out, existing)

	for i, s := range out {
		index[s.Dimension] = i
		counts[s.Dimension] = 1
	}

	for _, s := range incoming {
		if i, ok := index[s.Dimension]; ok {
			n := float32(counts[s.Dimension])
			out[i].Score = (out[i].Score*n + s.Score) / (n + 1)
			counts[s.Dimension]++
		} else {
			index[s.Dimension] = len(out)
			counts[s.Dimension] = 1
			out = append(out, &pb.DimensionScore{
				Dimension: s.Dimension,
				Score:     s.Score,
			})
		}
	}
	return out
}

func dedup(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}
