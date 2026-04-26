package pgsql

import (
	"context"
	"encoding/json"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/promptviser/internal/adviserdb/model"
	"github.com/lib/pq"
)

// GetAllRules returns all rules from the database, optionally filtered by
// domain and/or severity. Empty strings mean "no filter".
func (p *Provider) GetAllRules(ctx context.Context, domain, severity string) ([]*model.Rule, error) {
	query := `
SELECT rule_id, domain, name, severity, trigger_type,
       score_triggers, static_triggers, metadata_flags,
       remediation, standards
FROM rules
WHERE ($1 = '' OR domain = $1)
  AND ($2 = '' OR severity = $2)
ORDER BY rule_id`

	rows, err := p.sql.QueryContext(ctx, query, domain, severity)
	if err != nil {
		return nil, errors.Wrap(err, "GetAllRules: query failed")
	}
	defer rows.Close()

	var rules []*model.Rule
	for rows.Next() {
		var r model.Rule
		var scoreTriggersJSON []byte
		var staticTriggers pq.StringArray
		var metadataFlags pq.StringArray
		var standards pq.StringArray

		if err := rows.Scan(
			&r.RuleID,
			&r.Domain,
			&r.Name,
			&r.Severity,
			&r.TriggerType,
			&scoreTriggersJSON,
			&staticTriggers,
			&metadataFlags,
			&r.Remediation,
			&standards,
		); err != nil {
			return nil, errors.Wrap(err, "GetAllRules: scan failed")
		}

		r.StaticTriggers = []string(staticTriggers)
		r.MetadataFlags = []string(metadataFlags)
		r.Standards = []string(standards)

		if err := json.Unmarshal(scoreTriggersJSON, &r.ScoreTriggers); err != nil {
			return nil, errors.Wrap(err, "GetAllRules: failed to decode score_triggers JSON")
		}

		rules = append(rules, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "GetAllRules: row iteration error")
	}

	return rules, nil
}
