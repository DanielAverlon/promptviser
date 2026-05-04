package llm

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/effective-security/promptviser/api/pb"
)

// TODO: add agents

// Provider is the interface pass3 calls to score a prompt.
type Provider interface {
	Score(ctx context.Context, promptContent []byte) ([]*pb.DimensionScore, error)
}

type LLMConfig struct {
	Provider   string `yaml:"provider"`    // "openai" | "azure" | "anthropic" | "ollama" | "stub"
	Model      string `yaml:"model"`       // e.g. "gpt-4o", "llama3"
	BaseURL    string `yaml:"base_url"`    // for ollama or Azure endpoint
	APIKey     string `yaml:"api_key"`     // env var name or literal value
	APIVersion string `yaml:"api_version"` // Azure only, e.g. "2024-06-01"
}

func New(cfg LLMConfig) (Provider, error) {
	switch cfg.Provider {
	case "openai":
		return newOpenAI(cfg)
	case "azure":
		return newAzureOpenAI(cfg)
	case "anthropic":
		return newAnthropic(cfg)
	case "ollama":
		return newOllama(cfg)
	case "stub", "":
		return &stubProvider{}, nil
	default:
		return nil, fmt.Errorf("unknown LLM provider: %q", cfg.Provider)
	}
}

// metaPrompt is the system prompt used by all providers to score a prompt file.
//
//go:embed score_prompt.md
var metaPrompt string

// parseScores extracts dimension scores from a raw LLM response string.
// It strips markdown code fences if the model wraps its output in them.
func parseScores(raw string) ([]*pb.DimensionScore, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "```") {
		first := strings.Index(raw, "\n")
		last := strings.LastIndex(raw, "```")
		if first != -1 && last > first {
			raw = strings.TrimSpace(raw[first:last])
		}
	}

	var scores map[string]float32
	if err := json.Unmarshal([]byte(raw), &scores); err != nil {
		return nil, fmt.Errorf("failed to parse scores from LLM response: %w\nraw: %s", err, raw)
	}

	result := make([]*pb.DimensionScore, 0, len(scores))
	for dim, score := range scores {
		result = append(result, &pb.DimensionScore{Dimension: dim, Score: score})
	}
	return result, nil
}
