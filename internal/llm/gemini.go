package llm

import (
	"context"
	"fmt"
	"os"

	pb "github.com/effective-security/promptviser/api/pb"
	"google.golang.org/genai"
)

type geminiProvider struct {
	model  string
	apiKey string
}

func newGemini(cfg LLMConfig) (Provider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	} else if v := os.Getenv(apiKey); v != "" {
		apiKey = v // treat as env var name
	}
	if apiKey == "" {
		return nil, fmt.Errorf("llm/gemini: no API key provided (set GEMINI_API_KEY or api_key in config)")
	}

	model := cfg.Model
	if model == "" {
		model = "gemini-2.5-flash"
	}

	return &geminiProvider{model: model, apiKey: apiKey}, nil
}

func (p *geminiProvider) Score(ctx context.Context, content []byte) ([]*pb.DimensionScore, error) {
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  p.apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("llm/gemini: failed to create client: %w", err)
	}

	prompt := metaPrompt + "\n\n" + string(content)
	resp, err := client.Models.GenerateContent(ctx, p.model, genai.Text(prompt), nil)
	if err != nil {
		return nil, fmt.Errorf("llm/gemini: %w", err)
	}

	if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("llm/gemini: empty response")
	}

	return parseScores(resp.Candidates[0].Content.Parts[0].Text)
}

func (p *geminiProvider) Remediate(ctx context.Context, content []byte) (*RemediationResult, error) {
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  p.apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("llm/gemini: failed to create client: %w", err)
	}

	prompt := remediationSystemPrompt + "\n\n" + string(content)
	resp, err := client.Models.GenerateContent(ctx, p.model, genai.Text(prompt), nil)
	if err != nil {
		return nil, fmt.Errorf("llm/gemini: %w", err)
	}

	if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("llm/gemini: empty response")
	}
	return parseRemediations(resp.Candidates[0].Content.Parts[0].Text)
}
