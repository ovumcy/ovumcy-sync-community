---
name: feature-change
description: Plan and implement an ovumcy-sync-community change using the repository's backend-only zero-knowledge sync boundaries.
---

## Workflow

1. Read `AGENTS.md`, `AI_CONTEXT.md`, and local context first.
2. Keep the repository layered:
   - `api`
   - `services`
   - `db`
   - `models`
   - `security`
3. Treat auth, sessions, capability policy, blob flows, and deployment honesty as security-sensitive.
4. Keep zero-knowledge boundaries explicit and do not let plaintext product data leak into this repo.
5. Run focused backend verification after non-trivial changes.

