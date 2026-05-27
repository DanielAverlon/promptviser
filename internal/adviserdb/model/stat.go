package model

// FindingRecord is a single rule violation to persist.
type FindingRecord struct {
	RuleID   string
	FileName string
}

// RuleStatEntry holds aggregated violation counts joined with rule metadata.
type RuleStatEntry struct {
	RuleID    string
	Name      string
	Severity  string
	Domain    string
	Standards []string
	Count     int64
}
