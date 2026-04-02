---
name: commit
description: Prepare a clean commit for ovumcy-sync-community with scoped backend changes and explicit verification notes.
---

## Workflow

1. Review changed files and keep the commit narrowly scoped.
2. Check for security-sensitive regressions, migration drift, and local-only runtime artifacts.
3. Summarize relevant backend verification.
4. Propose a concise imperative commit message with the why.
5. Only run `git commit` or `git push` when the user explicitly asks.

