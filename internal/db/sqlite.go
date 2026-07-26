package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err) // codecov:ignore -- database/sql.Open validates only that the driver name is registered; it never dials the DSN (that happens lazily on first use, exercised by the "configure sqlite" PRAGMA Exec just below). "sqlite" is always registered via the blank modernc.org/sqlite import, so this can only fail on a broken build, not any runtime path input. Cannot occur in practice.
	}

	database.SetConnMaxLifetime(30 * time.Minute)
	database.SetMaxIdleConns(1)
	database.SetMaxOpenConns(1)

	if _, err := database.Exec(`
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
`); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}

	return &Store{db: database}, nil
}

func (s *Store) Close() error {
	// PRAGMA wal_checkpoint(TRUNCATE) returns one row (busy, log,
	// checkpointed) rather than signalling failure the way a normal
	// statement does: busy != 0 means another connection's open read or
	// write transaction blocked the truncate, so the -wal sidecar still
	// holds data the main file does not. That must be read with QueryRow,
	// not Exec, or a blocked checkpoint is silently indistinguishable from
	// a clean one — and the backup runbook's "a clean shutdown checkpoints
	// the WAL" assumption (docs/backup-restore.md) would go unverified.
	var checkpointErr error
	if s.db != nil {
		var busy, walPages, checkpointedPages int
		if err := s.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE);`).Scan(&busy, &walPages, &checkpointedPages); err != nil {
			checkpointErr = fmt.Errorf("wal checkpoint: %w", err)
		} else if busy != 0 {
			checkpointErr = fmt.Errorf("wal checkpoint blocked by a concurrent reader/writer (busy=%d log=%d checkpointed=%d): the closed database file may not be self-contained", busy, walPages, checkpointedPages)
		}
	}
	return errors.Join(checkpointErr, s.db.Close())
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) ApplyMigrations(ctx context.Context) error {
	return applyMigrations(ctx, s.db)
}

func (s *Store) SchemaReady(ctx context.Context) (bool, error) {
	return schemaReady(ctx, s.db)
}
