package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	pb "github.com/effective-security/promptviser/api/pb"
)

type ollamaProvider struct {
	baseURL string
	model   string
}

func newOllama(cfg LLMConfig) (Provider, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	model := cfg.Model
	if model == "" {
		model = "llama3"
	}

	return &ollamaProvider{baseURL: baseURL, model: model}, nil
}

func (p *ollamaProvider) Score(ctx context.Context, content []byte) ([]*pb.DimensionScore, error) {
	body, _ := json.Marshal(map[string]any{
		"model":  p.model,
		"prompt": metaPrompt + "\n\n" + string(content),
		"stream": false,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/api/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm/ollama: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("llm/ollama: failed to decode response: %w", err)
	}

	var scores map[string]float32
	if err := json.Unmarshal([]byte(result.Response), &scores); err != nil {
		return nil, fmt.Errorf("llm/ollama: failed to parse scores: %w", err)
	}

	out := make([]*pb.DimensionScore, 0, len(scores))
	for dim, score := range scores {
		out = append(out, &pb.DimensionScore{Dimension: dim, Score: score})
	}
	return out, nil
}
