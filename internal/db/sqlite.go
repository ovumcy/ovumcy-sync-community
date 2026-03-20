package db

import (
	"context"
	"database/sql"
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
		return nil, fmt.Errorf("open sqlite: %w", err)
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
	return s.db.Close()
}

func (s *Store) ApplyMigrations(ctx context.Context) error {
	return applyMigrations(ctx, s.db)
}
