package pass2

import "gopkg.in/yaml.v3"

// TODO: change everything

// promptMetadata mirrors the expected top-level YAML fields in a prompt file.
// Fields are optional; missing fields produce no flags.
type promptMetadata struct {
	IsUserFacing bool     `yaml:"is_user_facing"`
	Domain       string   `yaml:"domain"`
	ModelID      string   `yaml:"model_id"`
	Version      string   `yaml:"version"`
	Tools        []string `yaml:"tools"`
}

// highRiskDomains maps domain values to the metadata flag the server expects.
var highRiskDomains = map[string]string{
	"medical":          "domain:medical",
	"healthcare":       "domain:medical",
	"legal":            "domain:legal",
	"financial":        "domain:financial",
	"hiring":           "domain:hiring",
	"lending":          "domain:lending",
	"admissions":       "domain:admissions",
	"benefits":         "domain:benefits",
	"criminal_justice": "domain:criminal_justice",
	"mental_health":    "domain:mental_health",
	"crisis":           "domain:crisis",
	"self_harm":        "domain:self_harm",
	"emergency":        "domain:emergency",
}

// irreversibleTools are tool names that SEC-003 considers high-agency.
var irreversibleTools = map[string]bool{
	"db_write":     true,
	"file_delete":  true,
	"send_email":   true,
	"execute_code": true,
	"git_push":     true,
}

// Analyze parses the YAML front-matter of a prompt file and returns the list
// of metadata flags the server rules use for matching.
func Analyze(content []byte) []string {
	var meta promptMetadata
	// Best-effort parse — ignore errors so non-YAML files are silently skipped.
	_ = yaml.Unmarshal(content, &meta)

	var flags []string

	// ACC-001: is_user_facing: true
	if meta.IsUserFacing {
		flags = append(flags, "is_user_facing")
	}

	// Domain-based flags (REL-005, ACC-003, etc.)
	if flag, ok := highRiskDomains[meta.Domain]; ok {
		flags = append(flags, flag)
	}

	// ACC-002: missing model_id
	if meta.ModelID == "" {
		flags = append(flags, "missing_model_id")
	}

	// SEC-003: tool list contains irreversible actions
	for _, tool := range meta.Tools {
		if irreversibleTools[tool] {
			flags = append(flags, "no_timeout")
			break
		}
	}

	// SEC-006: more than 3 tools = potential excessive agency
	if len(meta.Tools) > 3 {
		flags = append(flags, "loop_or_batch_context")
	}

	return flags
}
