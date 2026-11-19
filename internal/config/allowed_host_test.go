package config

import "testing"

func TestParseAllowedHostNormalizes(t *testing.T) {
	for input, want := range map[string]string{
		"sync.example.com":    "sync.example.com",
		" Sync.Example.COM. ": "sync.example.com",
		"ovumcy_sync":         "ovumcy_sync",
		"localhost":           "localhost",
	} {
		got, err := ParseAllowedHost(input)
		if err != nil || got != want {
			t.Fatalf("ParseAllowedHost(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestParseAllowedHostRejectsNonNames(t *testing.T) {
	for _, input := range []string{
		"",
		".",
		"https://sync.example.com",
		"sync.example.com:8443",
		"sync.example.com/path",
		"*.example.com",
		"sync..example.com",
		".example.com",
		"user@sync.example.com",
		"sync example.com",
		"Kexample.com", // KELVIN SIGN lowercases to an ASCII 'k'
		"xn--bcher-kva.example.com ",
	} {
		if got, err := ParseAllowedHost(input); err == nil {
			t.Fatalf("ParseAllowedHost(%q) = %q, want an error", input, got)
		}
	}
}

func TestLoadRejectsInvalidAllowedHost(t *testing.T) {
	clearLoadEnv(t)
	t.Setenv("ALLOWED_HOSTS", "sync.example.com, https://sync.example.com")

	if _, err := Load(); err == nil {
		t.Fatal("expected Load to reject an ALLOWED_HOSTS entry with a scheme")
	}
}

func TestLoadReadsAllowedHosts(t *testing.T) {
	clearLoadEnv(t)
	t.Setenv("ALLOWED_HOSTS", "sync.example.com, sync.example.net")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.AllowedHosts) != 2 || cfg.AllowedHosts[0] != "sync.example.com" || cfg.AllowedHosts[1] != "sync.example.net" {
		t.Fatalf("AllowedHosts = %#v", cfg.AllowedHosts)
	}
}
