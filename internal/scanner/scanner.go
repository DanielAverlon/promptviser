package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
// TODO: later add compliance to other yaml config frameworks

// Scan walks dir, runs all three passes over every prompt file found, and
// returns the combined Result. Prompt text never leaves this function.
func Scan(ctx context.Context, dir string, provider llm.Provider) ([]*pb.FileScanResult, error) {
	files, err := collectPromptFiles(dir)
	if err != nil {
		return nil, err
	}

	type result struct {
		index  int
		result *pb.FileScanResult
		err    error
	}
	resultsCh := make(chan result, len(files))
	var wg sync.WaitGroup

	for idx, path := range files {
		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()
			fileResult := &pb.FileScanResult{
				FileName: path,
			}
			content, err := os.ReadFile(path)
			if err != nil {
				resultsCh <- result{index: idx, result: fileResult, err: err}
				return
			}

			fileResult.StaticTriggers = pass1.Check(content)
			fileResult.MetadataFlags = pass2.Analyze(content)
			scores, err := pass3.Score(ctx, content, fileResult.StaticTriggers, fileResult.MetadataFlags, provider)
			if err != nil {
				scores = []*pb.DimensionScore{{Dimension: "error: " + err.Error(), Score: 1}}
			}
			fileResult.Scores = mergeScores(fileResult.Scores, scores)

			resultsCh <- result{index: idx, result: fileResult, err: err}
		}(idx, path)
	}

	// Close channel once all goroutines finish
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	results := make([]*pb.FileScanResult, len(files))
	for res := range resultsCh {
		if res.err != nil {
			return nil, res.err
		}
		results[res.index] = res.result
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
