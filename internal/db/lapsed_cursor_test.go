package db

import (
	"context"
	"testing"
	"time"
)

// TestListLapsedManagedAccountIDsPagesByLapseThenID pins the keyset the sweep
// drains with: rows come in (lapse instant, id) order, a tie on the instant is
// broken by id, and a page that starts after a candidate never returns it or
// anything before it. Two rows store the same instant in different text
// (Z and +00:00), so the tie is decided on julianday(), not on the text.
func TestListLapsedManagedAccountIDsPagesByLapseThenID(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	tie := now.Add(-80 * 24 * time.Hour).Truncate(time.Second)

	for _, id := range []string{"lapsed-a", "lapsed-b", "lapsed-c", "lapsed-d"} {
		createLapseTestAccount(t, store, id, "managed")
	}
	if err := store.SetAccountLapsed(ctx, "lapsed-a", now.Add(-90*24*time.Hour)); err != nil {
		t.Fatalf("lapse a: %v", err)
	}
	for _, id := range []string{"lapsed-c", "lapsed-b"} {
		if err := store.SetAccountLapsed(ctx, id, tie); err != nil {
			t.Fatalf("lapse %s: %v", id, err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE accounts SET lapsed_at = ? WHERE id = 'lapsed-c'`, tie.Format("2006-01-02T15:04:05+00:00")); err != nil {
		t.Fatalf("restamp c: %v", err)
	}
	if err := store.SetAccountLapsed(ctx, "lapsed-d", now.Add(-70*24*time.Hour)); err != nil {
		t.Fatalf("lapse d: %v", err)
	}

	cutoff := now.Add(-60 * 24 * time.Hour)
	var got []string
	var after LapsedCandidate
	for pages := 0; ; pages++ {
		if pages > 4 {
			t.Fatalf("the cursor did not advance; got %v so far", got)
		}
		page, err := store.ListLapsedManagedAccountIDs(ctx, cutoff, after, 1)
		if err != nil {
			t.Fatalf("list page %d: %v", pages, err)
		}
		if len(page) == 0 {
			break
		}
		got = append(got, page[0].ID)
		after = page[0]
	}

	want := []string{"lapsed-a", "lapsed-b", "lapsed-c", "lapsed-d"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}

	rest, err := store.ListLapsedManagedAccountIDs(ctx, cutoff, LapsedCandidate{ID: "lapsed-b", LapsedAt: tie.Format(time.RFC3339Nano)}, 10)
	if err != nil {
		t.Fatalf("list after b: %v", err)
	}
	if len(rest) != 2 || rest[0].ID != "lapsed-c" || rest[1].ID != "lapsed-d" {
		t.Fatalf("expected [lapsed-c lapsed-d] after b, got %#v", rest)
	}
}
