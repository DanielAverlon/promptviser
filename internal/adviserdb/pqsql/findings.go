package pgsql

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/promptviser/internal/adviserdb/model"
	"github.com/lib/pq"
)

// RecordFindings inserts one row per rule violation into the findings table.
func (p *Provider) RecordFindings(ctx context.Context, scanID string, records []model.FindingRecord) error {
	if len(records) == 0 {
		return nil
	}

	const q = `INSERT INTO findings (scan_id, rule_id, file_name) VALUES ($1, $2, $3)`
	for _, r := range records {
		if _, err := p.ExecContext(ctx, q, scanID, r.RuleID, r.FileName); err != nil {
			return errors.Wrap(err, "RecordFindings: insert failed")
		}
	}
	return nil
}

// GetRuleStats returns the top-N most frequently violated rules, joined with
// their name, severity, domain, and standards from the rules table.
func (p *Provider) GetRuleStats(ctx context.Context, limit int) ([]*model.RuleStatEntry, error) {
	if limit <= 0 {
		limit = 10
	}

	const query = `
SELECT r.rule_id, r.name, r.severity, r.domain, r.standards, COUNT(f.id) AS cnt
FROM findings f
JOIN rules r ON r.rule_id = f.rule_id
GROUP BY r.rule_id, r.name, r.severity, r.domain, r.standards
ORDER BY cnt DESC
LIMIT $1`

	rows, err := p.sql.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, errors.Wrap(err, "GetRuleStats: query failed")
	}
	defer rows.Close()

	var entries []*model.RuleStatEntry
	for rows.Next() {
		var e model.RuleStatEntry
		var standards pq.StringArray
		if err := rows.Scan(&e.RuleID, &e.Name, &e.Severity, &e.Domain, &standards, &e.Count); err != nil {
			return nil, errors.Wrap(err, "GetRuleStats: scan failed")
		}
		e.Standards = []string(standards)
		entries = append(entries, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "GetRuleStats: row iteration error")
	}
	return entries, nil
}
