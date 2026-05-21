package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// RemediationViolation is a single finding passed to the remediation LLM.
type RemediationViolation struct {
	RuleID      string
	RuleName    string
	Severity    string
	TriggerType string
	Remediation string
}

// RemediationEdit is one targeted fix returned by the LLM — modelled so that
// applying strings.Replace(original, edit.Original, edit.Replacement, 1)
// produces a valid improved prompt.
type RemediationEdit struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Original    string `json:"original"`    // exact verbatim snippet; "" = pure addition
	Replacement string `json:"replacement"` // drop-in substitute or text to add
	Reason      string `json:"reason"`      // one-sentence description of the problem
}

// RemediationResult is the top-level JSON object returned by the LLM.
type RemediationResult struct {
	Remediations []RemediationEdit `json:"remediations"`
}

// remediationSystemPrompt is extracted from remediation_prompt.yaml at init.
var remediationSystemPrompt string

// remediationTmpl is the compiled user-turn template from remediation_prompt.yaml.
var remediationTmpl *template.Template

func init() {
	var cfg struct {
		SystemPrompt string `yaml:"system_prompt"`
		Prompt       string `yaml:"prompt"`
	}
	if err := yaml.Unmarshal([]byte(remediationPromptYAML), &cfg); err != nil {
		panic("remediation_prompt.yaml: " + err.Error())
	}
	remediationSystemPrompt = cfg.SystemPrompt
	remediationTmpl = template.Must(template.New("remediation_msg").Parse(cfg.Prompt))
}

// RenderRemediationMessage renders the user-turn template with the prompt text
// and its list of violations. The result is passed to Provider.Remediate.
func RenderRemediationMessage(promptText string, violations []RemediationViolation) (string, error) {
	var buf bytes.Buffer
	err := remediationTmpl.Execute(&buf, struct {
		UserPrompt string
		Violations []RemediationViolation
	}{
		UserPrompt: promptText,
		Violations: violations,
	})
	if err != nil {
		return "", fmt.Errorf("llm: failed to render remediation message: %w", err)
	}
	return buf.String(), nil
}

// parseRemediations extracts a RemediationResult from the raw LLM response.
// Markdown code fences are stripped if present.
func parseRemediations(raw string) (*RemediationResult, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "```") {
		first := strings.Index(raw, "\n")
		last := strings.LastIndex(raw, "```")
		if first != -1 && last > first {
			raw = strings.TrimSpace(raw[first:last])
		}
	}
	var result RemediationResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("llm: failed to parse remediation response: %w\nraw: %s", err, raw)
	}
	return &result, nil
}
