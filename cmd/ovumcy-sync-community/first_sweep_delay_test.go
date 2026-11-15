package main

import (
	"testing"
	"time"
)

// A daily restart must not postpone the first sweep past the restart: the
// wait is capped well below the 24h default interval.
func TestFirstSweepDelay(t *testing.T) {
	for _, tc := range []struct {
		interval time.Duration
		want     time.Duration
	}{
		{24 * time.Hour, maxFirstSweepDelay},
		{maxFirstSweepDelay, maxFirstSweepDelay},
		{time.Minute, time.Minute},
	} {
		if got := firstSweepDelay(tc.interval); got != tc.want {
			t.Fatalf("firstSweepDelay(%s) = %s, want %s", tc.interval, got, tc.want)
		}
	}
}
