package pass3

import pb "github.com/effective-security/promptviser/api/pb"

// Score calls the LLM API with the prompt content and returns dimension scores.
// The prompt text is sent to the LLM (running locally or via a direct API call
// the user configures) — it is NOT forwarded to the promptviser server.
//
// TODO: implement real LLM scoring.
// Options:
//   - Call OpenAI/Anthropic with a meta-evaluation prompt asking the LLM to
//     score the given prompt on each dimension (0-1 float).
//   - Use a local model (ollama, llama.cpp) for air-gapped environments.
//
// For now this returns a neutral score of 0.5 for every dimension so the
// pipeline is runnable end-to-end before the LLM integration is built.
func Score(_ []byte) ([]*pb.DimensionScore, error) {
	return []*pb.DimensionScore{
		{Dimension: "pii_exposure", Score: 0.5},
		{Dimension: "output_consequence", Score: 0.5},
		{Dimension: "human_oversight", Score: 0.5},
		{Dimension: "data_persistence", Score: 0.5},
		{Dimension: "refusal_instructions", Score: 0.5},
		{Dimension: "bias_risk", Score: 0.5},
	}, nil
}
