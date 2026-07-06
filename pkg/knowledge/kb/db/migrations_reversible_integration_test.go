//go:build integration

package db_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// migrationsSourceURL locates the on-disk migrations directory relative to
// this test file. go:embed copies file content verbatim, so the file://
// source below is byte-identical to the embedded iofs source that
// db.Migrate/db.Open drive in production — this test lives in the
// external db_test package (to reuse dbtest.StartPostgres without an
// import cycle: dbtest already imports db) and so cannot reach db's
// unexported embed.FS directly. Reading the same directory from disk
// exercises the exact same migration SQL files.
func migrationsSourceURL(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("migrationsSourceURL: runtime.Caller failed")
	}
	dir := filepath.Join(filepath.Dir(thisFile), "migrations")
	return "file://" + filepath.ToSlash(dir)
}

// TestMigrationsReversible proves every embedded migration cleanly
// reverses: up to head (done implicitly by dbtest.StartPostgres, which
// calls kbdb.Open -> Migrate), all the way down to an empty schema via
// Down(), then back up to head via Up() again — asserting no error and no
// dirty state at any step. This is the regression guard for a .down.sql
// silently drifting out of sync with its .up.sql counterpart: if any
// migration's down script were broken, Down() would fail or leave the
// schema in a state Up() can't cleanly rebuild from.
func TestMigrationsReversible(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)

	driver, err := migratepg.WithInstance(conn, &migratepg.Config{})
	if err != nil {
		t.Fatalf("postgres driver: %v", err)
	}
	m, err := migrate.NewWithDatabaseInstance(migrationsSourceURL(t), "postgres", driver)
	if err != nil {
		t.Fatalf("migrate new: %v", err)
	}

	headVersion, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("initial Version: %v", err)
	}
	if dirty {
		t.Fatalf("initial state is dirty at version %d", headVersion)
	}
	assertTablePresent(t, conn, "modules")

	// DOWN: reverse every migration back to an empty schema.
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("Down: %v", err)
	}
	if _, downDirty, verErr := m.Version(); verErr != nil {
		if !errors.Is(verErr, migrate.ErrNilVersion) {
			t.Fatalf("Version after Down: %v", verErr)
		}
	} else if downDirty {
		t.Fatalf("dirty after Down")
	}
	assertTableAbsent(t, conn, "modules")

	// UP: reapply every migration from empty back to head.
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("Up (second pass): %v", err)
	}
	gotVersion, upDirty, err := m.Version()
	if err != nil {
		t.Fatalf("final Version: %v", err)
	}
	if upDirty {
		t.Fatalf("dirty after final Up at version %d", gotVersion)
	}
	if gotVersion != headVersion {
		t.Fatalf("Up->Down->Up landed on version %d, want head %d", gotVersion, headVersion)
	}
	assertTablePresent(t, conn, "modules")
}

func assertTableAbsent(t *testing.T, conn *sql.DB, name string) {
	t.Helper()
	var rel sql.NullString
	if err := conn.QueryRow(`SELECT to_regclass($1)::text`, "public."+name).Scan(&rel); err != nil {
		t.Fatalf("to_regclass %s: %v", name, err)
	}
	if rel.Valid {
		t.Fatalf("table %s still exists after Down", name)
	}
}

func assertTablePresent(t *testing.T, conn *sql.DB, name string) {
	t.Helper()
	var rel sql.NullString
	if err := conn.QueryRow(`SELECT to_regclass($1)::text`, "public."+name).Scan(&rel); err != nil {
		t.Fatalf("to_regclass %s: %v", name, err)
	}
	if !rel.Valid {
		t.Fatalf("table %s missing after re-Up", name)
	}
}
