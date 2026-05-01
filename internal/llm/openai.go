package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

type openaiProvider struct {
	client *openai.Client
	model  string
}

func newOpenAI(cfg LLMConfig) (Provider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	} else if v := os.Getenv(apiKey); v != "" {
		apiKey = v // treat as env var name
	}
	if apiKey == "" {
		return nil, fmt.Errorf("llm/openai: no API key provided")
	}

	opts := []option.RequestOption{option.WithAPIKey(apiKey)}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}

	model := cfg.Model
	if model == "" {
		model = "gpt-4o"
	}

	client := openai.NewClient(opts...)
	return &openaiProvider{client: &client, model: model}, nil
}

// TODO: make seperate MD prompt to use

// metaPrompt is the system prompt sent to the LLM to score a user prompt.
const metaPrompt = `You are a prompt safety auditor. Score the following prompt on each dimension from 0.0 (low risk) to 1.0 (high risk). 
Reply ONLY with a JSON object like: {"pii_exposure":0.2,"output_consequence":0.1,"human_oversight":0.8,"data_persistence":0.0,"refusal_instructions":0.3,"bias_risk":0.1}`

func (p *openaiProvider) Score(ctx context.Context, content []byte) ([]*pb.DimensionScore, error) {
	resp, err := p.client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model: openai.ChatModel(p.model),
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(metaPrompt),
			openai.UserMessage(string(content)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("llm/openai: %w", err)
	}

	var scores map[string]float32
	if err := json.Unmarshal([]byte(resp.Choices[0].Message.Content), &scores); err != nil {
		return nil, fmt.Errorf("llm/openai: failed to parse scores: %w", err)
	}

	result := make([]*pb.DimensionScore, 0, len(scores))
	for dim, score := range scores {
		result = append(result, &pb.DimensionScore{Dimension: dim, Score: score})
	}
	return result, nil
}
