package pb

// GetStatsRequest carries optional parameters for the GetStats RPC.
type GetStatsRequest struct {
	// Limit is the maximum number of top violations to return. Defaults to 10.
	Limit int32 `json:"Limit,omitempty"`
}

// RuleViolationCount represents one rule's aggregated violation total.
type RuleViolationCount struct {
	// RuleID is the stable rule identifier, e.g. "PRIV-001".
	RuleID string `json:"RuleID,omitempty"`
	// Title is the human-readable rule name.
	Title string `json:"Title,omitempty"`
	// Severity is one of: Critical, High, Medium, Low.
	Severity string `json:"Severity,omitempty"`
	// Domain is the rule category, e.g. "Data Privacy & Confidentiality".
	Domain string `json:"Domain,omitempty"`
	// Standards lists applicable compliance references, e.g. "OWASP LLM01".
	Standards []string `json:"Standards,omitempty"`
	// Count is the total number of times this rule has been violated.
	Count int64 `json:"Count,omitempty"`
}

// GetStatsResponse returns aggregated violation statistics.
type GetStatsResponse struct {
	// TopViolations lists the most-violated rules, sorted by count descending.
	TopViolations []*RuleViolationCount `json:"TopViolations,omitempty"`
	// TotalScans is the total number of distinct scan IDs recorded.
	TotalScans int64 `json:"TotalScans,omitempty"`
}
