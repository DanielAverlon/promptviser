package llm

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/effective-security/promptviser/api/pb"
	"gopkg.in/yaml.v3"
)

// Provider is the interface pass3 calls to score a prompt and optionally
// generate remediation suggestions.
type Provider interface {
	Score(ctx context.Context, promptContent []byte) ([]*pb.DimensionScore, error)
	Remediate(ctx context.Context, content []byte) (*RemediationResult, error)
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
	case "gemini":
		return newGemini(cfg)
	case "ollama":
		return newOllama(cfg)
	case "stub", "":
		return &stubProvider{}, nil
	default:
		return nil, fmt.Errorf("unknown LLM provider: %q", cfg.Provider)
	}
}

// scorePromptYAML is the raw YAML file that carries version metadata and the system prompt.
//
//go:embed score_prompt.yaml
var scorePromptYAML string

// remediationPromptYAML is the raw YAML file for the remediation prompt.
//
//go:embed remediation_prompt.yaml
var remediationPromptYAML string

// metaPrompt is the system prompt used by all providers to score a prompt file.
// It is extracted from score_prompt.yaml at init time.
var metaPrompt string

// UserMessageTemplate is the Go text/template for the user-turn message.
// It is extracted from score_prompt.yaml at init time.
var UserMessageTemplate string

func init() {
	var cfg struct {
		SystemPrompt        string `yaml:"system_prompt"`
		UserMessageTemplate string `yaml:"prompt"`
	}
	if err := yaml.Unmarshal([]byte(scorePromptYAML), &cfg); err != nil {
		panic("score_prompt.yaml: " + err.Error())
	}
	metaPrompt = cfg.SystemPrompt
	UserMessageTemplate = cfg.UserMessageTemplate
}

// parseScores extracts dimension scores from a raw LLM response string.
// It accepts both the two-key format {"reasoning":{…},"scores":{…}} produced
// by the current prompt and the legacy flat format {"dim":0.5,…}.
// Markdown code fences are stripped if present.
func parseScores(raw string) ([]*pb.DimensionScore, error) {
	fmt.Printf("LLM raw response:\n%s\n", raw) // for debugging
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "```") {
		first := strings.Index(raw, "\n")
		last := strings.LastIndex(raw, "```")
		if first != -1 && last > first {
			raw = strings.TrimSpace(raw[first:last])
		}
	}

	// Try two-key format first.
	var twoKey struct {
		Scores map[string]float32 `json:"scores"`
	}
	if err := json.Unmarshal([]byte(raw), &twoKey); err == nil && len(twoKey.Scores) > 0 {
		result := make([]*pb.DimensionScore, 0, len(twoKey.Scores))
		for dim, score := range twoKey.Scores {
			result = append(result, &pb.DimensionScore{Dimension: dim, Score: score})
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Dimension < result[j].Dimension })
		return result, nil
	}

	// Fall back to legacy flat format.
	var flat map[string]float32
	if err := json.Unmarshal([]byte(raw), &flat); err != nil {
		return nil, fmt.Errorf("failed to parse scores from LLM response: %w\nraw: %s", err, raw)
	}
	result := make([]*pb.DimensionScore, 0, len(flat))
	for dim, score := range flat {
		result = append(result, &pb.DimensionScore{Dimension: dim, Score: score})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Dimension < result[j].Dimension })
	return result, nil
}
