---
name: security-check
description: Audit ovumcy-sync-community for auth, capability, blob-flow, deployment, and zero-knowledge boundary risks without applying fixes automatically.
---

## Workflow

1. Review:
   - auth/session routes
   - capability policy
   - device and blob flows
   - logging and secret handling
   - migration and deployment surfaces
   - zero-knowledge contract boundaries
2. Run focused baseline verification where useful.
3. Report findings first, then residual risks and clean remediation order.
4. Do not apply fixes automatically.

