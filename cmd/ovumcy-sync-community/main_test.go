package main

import "testing"

func TestShutdownSignalReturnsChannel(t *testing.T) {
	if shutdownSignal() == nil {
		t.Fatal("expected shutdown signal channel")
	}
}
