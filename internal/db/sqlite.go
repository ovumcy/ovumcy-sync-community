package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB

	// ready caches CheckReady's last answer; see readinessCacheTTL.
	ready struct {
		mu        sync.Mutex
		checkedAt time.Time
		err       error
		// inflight is closed when the one running check has stored its answer.
		inflight chan struct{}
		// epoch moves on forgetReadiness, so a check started before it cannot
		// store a stale answer after it.
		epoch uint64
		// check replaces checkReadyUncached in tests.
		check func(context.Context) error
	}
}

// readinessCacheTTL is how long one CheckReady answer is reused. /readyz is
// public and exempt from rate limits, and the pool holds one connection, so
// without it a flood of probes queues every request behind schema queries.
// One second is far below any healthcheck interval.
const readinessCacheTTL = time.Second

// readinessCheckTimeout bounds the one shared check, which runs detached from
// the caller that started it: a caller giving up must not void the answer
// the others wait for. A check that runs out of time is a not-ready answer.
const readinessCheckTimeout = 5 * time.Second

func Open(path string) (*Store, error) {
	if err := refuseTxLockOverride(path); err != nil {
		return nil, err
	}
	inMemory := isInMemoryPath(path)
	if !inMemory {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
		if err := createPlainDBFileOwnerOnly(path); err != nil {
			return nil, err
		}
	}

	database, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err) // codecov:ignore -- database/sql.Open validates only that the driver name is registered; it never dials the DSN (that happens lazily on first use, exercised by the "configure sqlite" Ping just below). "sqlite" is always registered via the blank modernc.org/sqlite import, so this can only fail on a broken build, not any runtime path input. Cannot occur in practice.
	}

	// An in-memory database lives and dies with its one connection: retiring
	// it would silently start over on an empty, unmigrated database.
	if !inMemory {
		database.SetConnMaxLifetime(30 * time.Minute)
	}
	database.SetMaxIdleConns(1)
	database.SetMaxOpenConns(1)

	// The driver runs the DSN pragmas when it dials a connection, so dialing
	// one here surfaces a bad DSN at startup instead of on the first request.
	if err := database.Ping(); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}

	return &Store{db: database}, nil
}

func isInMemoryPath(path string) bool {
	if strings.HasPrefix(path, ":memory:") || strings.HasPrefix(path, "file::memory:") {
		return true
	}
	_, query, hasQuery := strings.Cut(path, "?")
	return hasQuery && strings.Contains("&"+query+"&", "&mode=memory&")
}

// createPlainDBFileOwnerOnly creates a missing database file as 0600 before
// SQLite opens it: SQLite would create it under the process umask (commonly
// 0644), and it gives the -wal and -shm files the main file's mode. URI and
// query paths are left to SQLite. An existing file keeps its mode.
func createPlainDBFileOwnerOnly(path string) error {
	if strings.HasPrefix(path, "file:") || strings.Contains(path, "?") {
		return nil
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- DB_PATH is operator config
	if err != nil {
		return fmt.Errorf("create db file: %w", err)
	}
	return file.Close()
}

// connectionPragmas run on every connection the pool dials. They live in the
// DSN, not in a one-off Exec, because foreign_keys and busy_timeout are
// per-connection settings and SetConnMaxLifetime replaces the connection such
// an Exec configured: from then on writes would run with foreign keys off and
// no busy wait. secure_delete zeroes freed pages, so a deleted account's
// ciphertext and hashes do not linger in a copied database file.
//
// _txlock=immediate makes every BeginTx a BEGIN IMMEDIATE: the write lock is
// taken (or waited for, under busy_timeout) at begin. A deferred transaction
// that reads, and then writes after another process (`migrate`,
// `purge-lapsed-accounts`, a backup) committed, fails with SQLITE_BUSY_SNAPSHOT,
// which busy_timeout cannot wait out.
const connectionPragmas = "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=secure_delete(1)&_txlock=immediate"

// sqliteDSN appends connectionPragmas to the configured path. modernc.org/sqlite
// splits the DSN at the first '?' and opens everything before it as a plain
// filename, so spaces, '%', '#' and Windows drive paths need no escaping; a
// path that already carries a query keeps it and gains the pragmas after it.
func sqliteDSN(path string) string {
	if strings.Contains(path, "?") {
		return path + "&" + connectionPragmas
	}
	return path + "?" + connectionPragmas
}

// refuseTxLockOverride rejects a path whose own query sets _txlock: the driver
// reads the first _txlock in the DSN, so the path's value would win over
// connectionPragmas' immediate and bring back SQLITE_BUSY_SNAPSHOT.
func refuseTxLockOverride(path string) error {
	_, query, found := strings.Cut(path, "?")
	if !found {
		return nil
	}
	// A query the driver cannot parse fails its own "configure sqlite" check.
	values, err := url.ParseQuery(query)
	if err == nil && values.Has("_txlock") {
		return errors.New("database path must not set _txlock: every transaction takes the write lock at begin")
	}
	return nil
}

func (s *Store) Close() error {
	defer s.forgetReadiness()
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

// CheckReady reports whether the store can serve traffic right now: the
// database still answers, and the schema it holds is exactly the one this
// build embeds. It backs the /readyz probe, so it stays at the two small
// statements schemaReady already runs — a sqlite_master lookup and the
// schema_migrations name set, a handful of short TEXT rows — cheap enough to
// poll on the container healthcheck's interval.
//
// It is schema-aware on purpose. A liveness answer proves only that the HTTP
// loop is running, and the boot-time schema gate proves nothing after boot: a
// newer image running `migrate` against the same volume moves the schema out
// from under this still-running process, which would then keep serving
// traffic on a schema no code in this build understands. The same name-set
// comparison that refuses such a database at startup refuses it here, so the
// process reports unready instead of healthy.
//
// Callers within readinessCacheTTL of a completed check share its answer, and
// concurrent callers wait for the one check in flight instead of each queuing
// its own statements. Each caller waits only as long as its own context
// allows; the check itself runs to its answer, which is cached for the rest.
func (s *Store) CheckReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for {
		s.ready.mu.Lock()
		if !s.ready.checkedAt.IsZero() && time.Since(s.ready.checkedAt) < readinessCacheTTL {
			err := s.ready.err
			s.ready.mu.Unlock()
			return err
		}
		done := s.ready.inflight
		if done == nil {
			done = make(chan struct{})
			s.ready.inflight = done
			check := s.ready.check
			if check == nil {
				check = s.checkReadyUncached
			}
			go s.runReadinessCheck(context.WithoutCancel(ctx), check, s.ready.epoch, done)
		}
		s.ready.mu.Unlock()

		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Store) runReadinessCheck(ctx context.Context, check func(context.Context) error, epoch uint64, done chan struct{}) {
	ctx, cancel := context.WithTimeout(ctx, readinessCheckTimeout)
	defer cancel()
	err := check(ctx)

	s.ready.mu.Lock()
	if s.ready.epoch == epoch {
		s.ready.checkedAt = time.Now()
		s.ready.err = err
	}
	if s.ready.inflight == done {
		s.ready.inflight = nil
	}
	s.ready.mu.Unlock()
	close(done)
}

func (s *Store) forgetReadiness() {
	s.ready.mu.Lock()
	s.ready.epoch++
	s.ready.checkedAt = time.Time{}
	s.ready.err = nil
	s.ready.inflight = nil
	s.ready.mu.Unlock()
}

func (s *Store) checkReadyUncached(ctx context.Context) error {
	ready, err := schemaReady(ctx, s.db)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("database schema is not initialized for this build; run `ovumcy-sync-community migrate`")
	}

	return nil
}
