package model

// Rule represents a single row from the rules table.
type Rule struct {
	RuleID         string
	Domain         string
	Name           string
	Severity       string
	TriggerType    string
	ScoreTriggers  map[string]float64 // decoded from JSONB
	StaticTriggers []string
	MetadataFlags  []string
	Remediation    string
	Standards      []string
}
