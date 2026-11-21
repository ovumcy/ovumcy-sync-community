package db

import (
	"context"
	"slices"
	"testing"
	"time"
)

// accountErase is one live path that erases a whole account; every one of
// them must clear accountChildTables in full.
type accountErase struct {
	name   string
	mode   string
	lapsed bool
	erase  func(ctx context.Context, store *Store, accountID string) error
}

var accountErases = []accountErase{
	{
		name: "session-authenticated delete",
		mode: "self_hosted",
		erase: func(ctx context.Context, store *Store, accountID string) error {
			return store.DeleteAccountForSession(ctx, accountID, "hash", false, accountID+"-token-hash")
		},
	},
	{
		name: "bridge purge",
		mode: "managed",
		erase: func(ctx context.Context, store *Store, accountID string) error {
			return store.DeleteManagedAccount(ctx, accountID)
		},
	},
	{
		name:   "lapsed-account sweep",
		mode:   "managed",
		lapsed: true,
		erase: func(ctx context.Context, store *Store, accountID string) error {
			return store.DeleteLapsedManagedAccount(ctx, accountID, time.Now().UTC().Add(-time.Hour))
		},
	},
}

func countAccountRows(t *testing.T, store *Store, table string, accountID string) int {
	t.Helper()
	var rows int
	if err := store.db.QueryRowContext(
		context.Background(),
		`SELECT COUNT(*) FROM `+table+` WHERE account_id = ?`, // #nosec G202 -- table ranges only over the fixed accountChildTables allowlist
		accountID,
	).Scan(&rows); err != nil {
		t.Fatalf("count %s rows: %v", table, err)
	}
	return rows
}

// TestAccountChildTablesCoverEveryAccountKeyedTable reads the migrated schema
// for every table with an account_id column or a foreign key to accounts: a
// new per-account table that is not added to accountChildTables would survive
// every account erase.
func TestAccountChildTablesCoverEveryAccountKeyedTable(t *testing.T) {
	store := openTestStore(t)

	rows, err := store.db.QueryContext(
		context.Background(),
		`SELECT m.name FROM sqlite_master AS m, pragma_table_info(m.name) AS c
		 WHERE m.type = 'table' AND c.name = 'account_id'
		 UNION
		 SELECT m.name FROM sqlite_master AS m, pragma_foreign_key_list(m.name) AS f
		 WHERE m.type = 'table' AND f."table" = 'accounts'
		 ORDER BY 1`,
	)
	if err != nil {
		t.Fatalf("list account-keyed tables: %v", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var keyed []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		keyed = append(keyed, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("account-keyed tables rows: %v", err)
	}

	listed := slices.Sorted(slices.Values(accountChildTables[:]))
	if !slices.Equal(keyed, listed) {
		t.Fatalf("tables keyed by account_id %v, accountChildTables %v: every account-keyed table must be erased with the account", keyed, listed)
	}
}
