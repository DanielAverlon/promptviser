package llm

import (
	"context"
	"fmt"

	"github.com/effective-security/promptviser/api/pb"
)

// TODO: add agents

// Provider is the interface pass3 calls to score a prompt.
type Provider interface {
	Score(ctx context.Context, promptContent []byte) ([]*pb.DimensionScore, error)
}

type LLMConfig struct {
	Provider string `yaml:"provider"` // "openai", "anthropic", "ollama"
	Model    string `yaml:"model"`    // e.g. "gpt-4o", "llama3"
	BaseURL  string `yaml:"base_url"` // for ollama or custom endpoints
	APIKey   string `yaml:"api_key"`  // env var name or literal
}

func New(cfg LLMConfig) (Provider, error) {
	switch cfg.Provider {
	case "openai":
		return newOpenAI(cfg)
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
