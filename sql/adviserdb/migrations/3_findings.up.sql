BEGIN;

-- findings records every rule violation surfaced by MatchRules.
-- This allows the server to aggregate stats across all submitted scans.
CREATE TABLE IF NOT EXISTS findings (
    id          BIGSERIAL    PRIMARY KEY,
    scan_id     TEXT         NOT NULL,
    rule_id     TEXT         NOT NULL REFERENCES rules(rule_id),
    file_name   TEXT         NOT NULL,
    created_at  TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_rule_id    ON findings (rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id    ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings (created_at);

COMMIT;
