package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/effective-security/promptviser/api/pb"
)

type anthropicProvider struct {
	client *anthropic.Client
	model  string
}

func newAnthropic(cfg LLMConfig) (Provider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	} else if v := os.Getenv(apiKey); v != "" {
		apiKey = v // treat as env var name
	}
	if apiKey == "" {
		return nil, fmt.Errorf("llm/anthropic: no API key provided")
	}

	model := cfg.Model
	if model == "" {
		model = "claude-2"
	}

	client := anthropic.NewClient(option.WithAPIKey(apiKey))

	return &anthropicProvider{client: &client, model: model}, nil
}

func (p *anthropicProvider) Score(ctx context.Context, content []byte) ([]*pb.DimensionScore, error) {
	resp, err := p.client.Completions.New(ctx, anthropic.CompletionNewParams{
		Model:  p.model,
		Prompt: metaPrompt + "\n\n" + string(content),
	})
	if err != nil {
		return nil, fmt.Errorf("llm/anthropic: %w", err)
	}

	var scores map[string]float32
	if err := json.Unmarshal([]byte(resp.Completion), &scores); err != nil {
		return nil, fmt.Errorf("llm/anthropic: failed to parse scores: %w", err)
	}

	out := make([]*pb.DimensionScore, 0, len(scores))
	for dim, score := range scores {
		out = append(out, &pb.DimensionScore{Dimension: dim, Score: score})
	}
	return out, nil
}
