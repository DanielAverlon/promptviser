package pgsql_test

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/promptviser/internal/adviserdb"
	pgsql "github.com/effective-security/promptviser/internal/adviserdb/pqsql"
	"github.com/effective-security/promptviser/tests/testutils"
	"github.com/effective-security/x/flake"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	provider adviserdb.Provider
	ctx      = context.Background()
)

func TestMain(m *testing.M) {
	xlog.SetGlobalLogLevel(xlog.TRACE)

	// var err error
	// grunner, err = dbrunner.New(nil)
	// if err != nil {
	// 	panic(err)
	// }
	// provider = grunner.Provider

	cfg, err := testutils.LoadConfig("UNIT_TEST")
	if err != nil {
		panic(err)
	}

	provider, err = adviserdb.New(
		cfg.SQL.DataSource,
		cfg.SQL.MigrationsDir,
		0, 0,
		flake.DefaultIDGenerator,
	)
	if err != nil {
		panic(err)
	}

	// Run the tests
	rc := m.Run()

	// // NOTE: os.Exit does not respect defer
	// grunner.Close()
	_ = provider.Close()

	os.Exit(rc)
}

func TestCheckErrIDConflict(t *testing.T) {
	tw := bytes.Buffer{}
	writer := bufio.NewWriter(&tw)
	xlog.SetFormatter(xlog.NewStringFormatter(writer))

	p := provider.(*pgsql.Provider)
	id := p.NextID()
	p.CheckErrIDConflict(context.Background(), errors.New("duplicate key value violates unique constraint \"users_pkey\""), id.UInt64())

	writer.Flush()
	log := tw.String()
	assert.Contains(t, log, `func=CheckErrIDConflict reason="duplicate_key"`)
	assert.Contains(t, log, `caller="TestCheckErrIDConflict [provider_test.go:`)
}

func Test_ListTables(t *testing.T) {
	expectedTables := []string{
		"rules",
		"schema_migrations",
	}
	require.NotNil(t, provider)
	require.NotNil(t, provider.DB())
	res, err := provider.QueryContext(ctx, `
	SELECT
		tablename
	FROM
		pg_catalog.pg_tables
	;`)
	require.NoError(t, err)
	defer res.Close()

	var tables []string
	var table string
	for res.Next() {
		err = res.Scan(&table)
		require.NoError(t, err)
		if !strings.HasPrefix(table, "sql_") && !strings.HasPrefix(table, "pg_") {
			tables = append(tables, table)
		}
	}
	sort.Strings(tables)
	assert.Equal(t, expectedTables, tables)
}

func slowMethod() {
	defer pgsql.DbMeasureSince(time.Now())
	time.Sleep(time.Millisecond * time.Duration(pgsql.DbSlowMethodMilliseconds+1))
}

func Test_DbMeasureSince(t *testing.T) {
	var b bytes.Buffer
	writer := bufio.NewWriter(&b)
	xlog.SetPackageLogLevel("github.com/effective-security/promptviser/internal/adviserdb", "pgsql", xlog.DEBUG)
	xlog.SetFormatter(xlog.NewStringFormatter(writer).Options(xlog.FormatSkipTime))

	slowMethod()

	pgsql.DbMeasureQuerySince("GetXXX_1_2", time.Now())
	pgsql.DbMeasureQuerySince("ListYYY", time.Now())

	writer.Flush()
	assert.Contains(t, b.String(), "level=D pkg=pgsql func=DbMeasureQuerySince reason=\"slow\" db=\"adviserdb\" query=\"slowMethod\" ms=")
}
