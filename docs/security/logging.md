# Logging

The server logs with the standard library `log` package to stderr. There are no request or access
logs and no structured logging. Every log call is in `cmd/ovumcy-sync-community/main.go` or
`internal/api/server.go`. Related: [threat-model.md](threat-model.md),
[data-handling.md](data-handling.md).

## What is logged

| Event | Content | Source |
| --- | --- | --- |
| Startup | Database path, "applied database migrations", listen address | `main.go` |
| Database close failure | The close error | `main.go` |
| Fatal startup error | The configuration or startup error | `main.go` |
| Lapsed-account sweep | Counts examined and deleted; one `account_id=<id>` line per deleted account; the sweep error, if any; a notice when the in-process sweep is disabled | `main.go` |
| Expired-rows sweep | Counts of deleted sessions, password reset tokens and TOTP challenges; the sweep error, if any; a notice when disabled | `main.go` |
| Recovered handler panic | Method, path, panic type and length, stack trace | `serveWithPanicRecovery`, `internal/api/server.go` |

Account ids are random identifiers, not logins. Sweep entries report counts and ids, never row
contents.

## Request-value sanitizer

The only request-derived values that reach a log call are the HTTP method and URL path in the panic
line, and both pass through `sanitizeLogValue` (`internal/api/server.go`). It removes:

- C0 control characters below 0x20, which includes CR and LF, and DEL (0x7F);
- the C1 range 0x80-0x9F, because a percent-decoded path can carry U+009B, a single-character CSI
  that a UTF-8 terminal executes like an escape sequence;
- the Unicode format category (Cf), which includes bidirectional overrides that reorder how a line
  is displayed.

This closes log forging by line breaks (CWE-117) and terminal-escape injection. Printable runes,
including non-ASCII text, are kept. The query string is not logged.

## Panic-recovery shape

A handler panic is converted to a 500 `internal_error` response when the response has not started
(`recoveryWriter`), and one entry is logged:

```
recovered panic serving <METHOD> <PATH>: panic_type=<Go type> panic_len=<n>
<stack trace>
```

The panic value itself is never rendered, only its dynamic type and the length of its rendering,
because a panic value can carry request-derived text such as a login or header content. The stack
trace comes from the binary's symbol table and carries no request text. The body, headers and query
are never included.

## What is never logged

- passwords, recovery codes, password reset tokens;
- session bearer tokens and the `Authorization` header, including the managed-bridge and metrics
  tokens;
- login identifiers (the login is never passed to a log call);
- TOTP secrets, TOTP codes and challenge ids;
- `FIELD_ENCRYPTION_KEY`, `MANAGED_BRIDGE_TOKEN`, `METRICS_BEARER_TOKEN`;
- blob contents or recovery-key package fields;
- client IP addresses, user agents, request bodies and query strings.

Errors from services are logged only in the sweep paths; they wrap store and driver errors, which
carry SQL or driver text but not request fields. Treat that as a property to re-check when adding a
log call, not as a guarantee about third-party error text.

## Operator guidance

- Logs contain account ids, paths and counts. They are low sensitivity but still metadata: a deleted
  account id remains in historical logs.
- Retain logs only as long as you need them for operations. A short fixed window (for example 7 to
  30 days) is enough; the application writes nothing that must be kept for audit.
- Your reverse proxy is outside this document and normally logs client addresses, paths and
  timing. Apply the same retention to it, and keep `Authorization` headers and request bodies out of
  its logs.
- Rotate logs with your container runtime or service manager; the process does not rotate its own.
- If a log excerpt is shared for a bug report, remove account ids first.
