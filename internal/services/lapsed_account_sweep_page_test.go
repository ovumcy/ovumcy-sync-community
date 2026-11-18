package services

import "testing"

// TestLapsedAccountSweepPageSizeFloor pins SYNC-24 B16: every listing page is
// a full accounts scan, so an operator page size below
// MinLapsedAccountSweepPage is raised to it, while 0 still means the store
// default and larger sizes pass through.
func TestLapsedAccountSweepPageSizeFloor(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{-3, 0},
		{0, 0},
		{1, MinLapsedAccountSweepPage},
		{MinLapsedAccountSweepPage - 1, MinLapsedAccountSweepPage},
		{MinLapsedAccountSweepPage, MinLapsedAccountSweepPage},
		{500, 500},
	} {
		if got := LapsedAccountSweepPageSize(tc.in); got != tc.want {
			t.Fatalf("LapsedAccountSweepPageSize(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
