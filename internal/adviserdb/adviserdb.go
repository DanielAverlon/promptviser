package adviserdb

import (
	"context"

	"github.com/effective-security/promptviser/internal/adviserdb/model"
	pgsql "github.com/effective-security/promptviser/internal/adviserdb/pqsql"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xdb/pkg/flake"

	// register Postgres driver
	_ "github.com/lib/pq"
	// register file driver for migration
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

//go:generate mockgen -source=adviserdb.go -destination=../../mocks/mockadviserdb/adviserdb_mock.gen.go -package mockadviserdb

// Rule is re-exported from the model package for convenience.
type Rule = model.Rule

// AdviserReadonlyDb defines an interface for Read operations on Certs
type AdviserReadonlyDb interface {
	xdb.IDGenerator

	// GetAllRules returns all rules, optionally filtered by domain and/or severity.
	// An empty string for domain or severity means "no filter".
	GetAllRules(ctx context.Context, domain, severity string) ([]*model.Rule, error)

	// GetRuleStats returns the top-N most-violated rules aggregated from the
	// findings table.  If limit <= 0 it defaults to 10.
	GetRuleStats(ctx context.Context, limit int) ([]*model.RuleStatEntry, error)
}

// AdviserDb defines an interface for CRUD operations on Adviser
type AdviserDb interface {
	AdviserReadonlyDb

	// RecordFindings persists every rule violation from a single MatchRules
	// call so they can be aggregated by GetRuleStats.
	RecordFindings(ctx context.Context, scanID string, records []model.FindingRecord) error
}

// Provider provides complete DB access
type Provider interface {
	xdb.Provider

	AdviserDb
}

// New creates a Provider instance
func New(dataSourceName, migrationsDir string, forceVersion, migrateVersion int, idGen flake.IDGenerator) (Provider, error) {
	var migrateCfg *xdb.MigrationConfig
	if migrationsDir != "" {
		migrateCfg = &xdb.MigrationConfig{
			ForceVersion:   forceVersion,
			MigrateVersion: migrateVersion,
			Source:         migrationsDir,
		}
	}

	p, err := xdb.NewProvider(dataSourceName, "", idGen, migrateCfg)
	if err != nil {
		return nil, err
	}

	return pgsql.New(p)
}
