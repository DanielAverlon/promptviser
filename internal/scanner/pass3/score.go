package pass3

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/llm"
)

// Score calls the LLM provider with the prompt content and pre-computed signals
// from pass1 and pass2, returning dimension scores in [0, 1].
// The prompt text is sent to the LLM configured by the user — it is NOT
// forwarded to the promptviser server.
func Score(ctx context.Context, content []byte, staticTriggers, metadataFlags []string, provider llm.Provider) ([]*pb.DimensionScore, error) {
	userMsg := buildUserMessage(content, staticTriggers, metadataFlags)
	return provider.Score(ctx, []byte(userMsg))
}

// buildUserMessage composes the user-turn message sent to the LLM.
// It includes the prompt text plus any pre-computed signals from pass1/pass2
// so the model has concrete evidence to anchor its scores.
func buildUserMessage(content []byte, staticTriggers, metadataFlags []string) string {
	var b strings.Builder

	b.WriteString("## Prompt under review\n\n")
	b.Write(content)

	if len(staticTriggers) > 0 || len(metadataFlags) > 0 {
		b.WriteString("\n\n## Pre-computed signals (static analysis)\n")
		if len(staticTriggers) > 0 {
			b.WriteString(fmt.Sprintf("Static triggers: %s\n", strings.Join(staticTriggers, ", ")))
		}
		if len(metadataFlags) > 0 {
			b.WriteString(fmt.Sprintf("Metadata flags:  %s\n", strings.Join(metadataFlags, ", ")))
		}
	}

	return b.String()
}
