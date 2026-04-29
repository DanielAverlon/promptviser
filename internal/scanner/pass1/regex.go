package pass1

import "regexp"

// TODO: change everything

// pattern holds a compiled regex and the trigger name it fires.
type pattern struct {
	re      *regexp.Regexp
	trigger string
}

// patterns is the list of all Pass 1 regex rules.
// Each entry maps to a StaticTrigger name that the server rules reference.
var patterns = []pattern{
	// SEC-001: user input variable present without structural delimiter
	// Fires when a Go template variable for user input exists in the file.
	// The absence of surrounding ### / """ / XML tags is checked separately.
	{regexp.MustCompile(`\{\{\.(?:UserInput|UserMessage|Query|Prompt)\}\}`), "MISSING_DELIMITER"},

	// PRIV-001 / PRIV-002: PII template variables
	{regexp.MustCompile(`\{\{\.(?:SSN|DOB|Email|Phone|MedicalRecord|DateOfBirth|SocialSecurity)\}\}`), "PII_VARIABLE"},

	// PRIV-003: hardcoded secrets / credentials
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{32,}`), "HARDCODED_SECRET"},           // OpenAI key
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "HARDCODED_SECRET"},              // AWS access key
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "HARDCODED_SECRET"},           // GitHub PAT
	{regexp.MustCompile(`Bearer\s+[A-Za-z0-9._\-]{20,}`), "HARDCODED_SECRET"}, // Bearer token

	// PRIV-004: confidentiality instruction + literal secret present
	{regexp.MustCompile(`(?i)keep\s+this\s+confidential|do\s+not\s+reveal`), "CONFIDENTIALITY_INSTRUCTION"},

	// PRIV-005: cross-session memory references
	{regexp.MustCompile(`(?i)\b(?:remember|last\s+time|your\s+history|previous\s+conversation)\b`), "MEMORY_REFERENCE"},

	// SEC-002: indirect injection / external content ingestion
	{regexp.MustCompile(`(?i)\b(?:browse|fetch|read\s+url|search\s+web|retrieved\s+documents|from\s+the\s+following\s+webpage)\b`), "EXTERNAL_CONTENT_INGESTION"},

	// SEC-003: excessive tool agency keywords
	{regexp.MustCompile(`(?i)\b(?:db_write|file_delete|send_email|execute_code|git_push)\b`), "EXCESSIVE_TOOL_AGENCY"},

	// SEC-004: unsanitized output destination keywords
	{regexp.MustCompile(`(?i)\b(?:ResponseWriter|template\.HTML)\b`), "UNSANITIZED_OUTPUT"},

	// SEC-005: multi-agent references without trust declaration
	{regexp.MustCompile(`(?i)\b(?:other\s+agent|sub-agent|orchestrator|tool\s+output|agent\s+result)\b`), "MULTI_AGENT_REFERENCE"},

	// REL-001: missing uncertainty clause in fact-retrieval prompts
	// This fires when there is no hedge phrase (will be checked inverted by the scorer).
	// Here we detect fact-retrieval prompts that lack any uncertainty language.
	// NOTE: absence-based rules are hard to do in pure regex — this flags the
	// presence of a positive assertion without the hedge. The LLM pass refines this.
	{regexp.MustCompile(`(?i)\b(?:the\s+answer\s+is|the\s+fact\s+is|definitively)\b`), "MISSING_UNCERTAINTY_CLAUSE"},

	// REL-002: RAG context block without citation instruction
	{regexp.MustCompile(`(?i)^(?:context|retrieved|documents|search\s+results)\s*:`), "RAG_WITHOUT_CITATION"},

	// REL-004: missing refusal instruction
	{regexp.MustCompile(`(?i)\b(?:outside\s+my\s+scope|I\s+cannot\s+help\s+with|not\s+designed\s+to)\b`), "MISSING_REFUSAL_INSTRUCTION"},

	// REL-005: crisis-adjacent keywords without escalation path
	{regexp.MustCompile(`(?i)\b(?:self.harm|suicide|crisis\s+line|988|emergency\s+services)\b`), "MISSING_CRISIS_ESCALATION"},

	// REL-006: agentic loop without termination
	{regexp.MustCompile(`(?i)\b(?:repeat\s+until|loop\s+until|keep\s+trying|retry\s+indefinitely)\b`), "AGENTIC_LOOP_NO_TERMINATION"},

	// ACC-001: missing AI self-identification in user-facing prompt
	{regexp.MustCompile(`(?i)\b(?:I\s+am\s+an\s+AI|AI\s+assistant|language\s+model|automated\s+system)\b`), "MISSING_AI_DISCLOSURE"},

	// ACC-005: synthetic media generation
	{regexp.MustCompile(`(?i)\b(?:generate\s+image\s+of|create\s+a\s+photo|make\s+a\s+voice|synthesize\s+audio|impersonate|write\s+as\s+if\s+you\s+are)\b`), "SYNTHETIC_MEDIA_GENERATION"},

	// PE-001: no role or persona definition
	{regexp.MustCompile(`(?i)\b(?:You\s+are|Your\s+role\s+is|Act\s+as\s+a|As\s+a\s+\w+\s+assistant)\b`), "MISSING_PERSONA"},

	// PE-005: negative-only instructions
	{regexp.MustCompile(`(?i)\b(?:do\s+not|never|avoid)\b`), "NEGATIVE_ONLY_INSTRUCTION"},

	// PE-006: token-heavy prompt (rough heuristic: file > 3000 bytes)
	// Handled separately in Check() below.

	// PE-007: conflicting instructions
	{regexp.MustCompile(`(?i)\bbe\s+concise\b`), "CONFLICTING_INSTRUCTIONS"},
	{regexp.MustCompile(`(?i)\bprovide\s+comprehensive\b`), "CONFLICTING_INSTRUCTIONS"},

	// ACC-004: output going to DB or file
	{regexp.MustCompile(`(?i)\b(?:db\.Exec|file\.Write|os\.WriteFile|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b`), "OUTPUT_TO_DB_OR_FILE"},

	// ACC-003: missing bias guardrail
	{regexp.MustCompile(`(?i)\b(?:do\s+not\s+consider|ignore\s+protected|race|gender|age|religion)\b`), "MISSING_BIAS_GUARDRAIL"},
}

// tokenHeavyThreshold is the byte size above which PE-006 fires.
const tokenHeavyThreshold = 3000

// Check runs all Pass 1 regex patterns against content and returns the list
// of unique StaticTrigger names that fired. Duplicates are collapsed.
func Check(content []byte) []string {
	triggered := make(map[string]struct{})

	for _, p := range patterns {
		if p.re.Match(content) {
			triggered[p.trigger] = struct{}{}
		}
	}

	// PE-006: token-heavy heuristic
	if len(content) > tokenHeavyThreshold {
		triggered["TOKEN_HEAVY_PROMPT"] = struct{}{}
	}

	result := make([]string, 0, len(triggered))
	for name := range triggered {
		result = append(result, name)
	}
	return result
}
