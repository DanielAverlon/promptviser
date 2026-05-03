package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/llm"
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

// Result holds the combined output of all three passes for a scanned file.
type Result struct {
	FileName       string
	StaticTriggers []string
	MetadataFlags  []string
	Scores         []*pb.DimensionScore
}

// TODO: add a ScanConfig to configure what triggers get ignored
// type ScanConfig struct {
//     Extensions      []string            // default: .yaml,.yml,.txt,.md
//     ExcludeRules    map[string][]string // filename → rule IDs to suppress
// }
// TODO: reasoning along dimension scores
// TODO: later add compliance to other yaml config frameworks

// Scan walks dir, runs all three passes over every prompt file found, and
// returns the combined Result. Prompt text never leaves this function.
func Scan(ctx context.Context, dir string, provider llm.Provider) ([]*pb.FileScanResult, error) {
	files, err := collectPromptFiles(dir)
	if err != nil {
		return nil, err
	}

	results := []*pb.FileScanResult{}

	for _, path := range files {
		fileResult := &pb.FileScanResult{
			FileName: path,
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		// Pass 1 — regex patterns
		triggers := pass1.Check(content)
		fileResult.StaticTriggers = append(fileResult.StaticTriggers, triggers...)

		// Pass 2 — YAML/AST analysis
		flags := pass2.Analyze(content)
		fileResult.MetadataFlags = append(fileResult.MetadataFlags, flags...)

		// Pass 3 — LLM scoring
		scores, err := pass3.Score(ctx, content, provider)
		if err != nil {
			return nil, err
		}
		fileResult.Scores = mergeScores(fileResult.Scores, scores)

		results = append(results, fileResult)
	}

	return results, nil
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
