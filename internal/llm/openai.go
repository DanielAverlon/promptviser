package llm

import (
	"context"
	"fmt"
	"os"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/azure"
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

func newAzureOpenAI(cfg LLMConfig) (Provider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("AZURE_OPENAI_API_KEY")
	} else if v := os.Getenv(apiKey); v != "" {
		apiKey = v
	}
	if apiKey == "" {
		return nil, fmt.Errorf("llm/azure: no API key provided")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("llm/azure: base_url must be set to your Azure OpenAI endpoint (e.g. https://<resource>.openai.azure.com)")
	}
	apiVersion := cfg.APIVersion
	if apiVersion == "" {
		apiVersion = "2024-06-01"
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4o"
	}
	client := openai.NewClient(
		azure.WithEndpoint(cfg.BaseURL, apiVersion),
		azure.WithAPIKey(apiKey),
	)
	return &openaiProvider{client: &client, model: model}, nil
}

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

	return parseScores(resp.Choices[0].Message.Content)
}
