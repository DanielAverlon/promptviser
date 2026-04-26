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
}

// AdviserDb defines an interface for CRUD operations on Adviser
type AdviserDb interface {
	AdviserReadonlyDb
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
