# Ovumcy Sync Community AI Context: Security

## Security Model

- `ovumcy-sync-community` is a privacy-sensitive zero-knowledge sync backend.
- The server stores only account/session/device metadata and ciphertext blobs.
- Decrypted health payloads, recovery phrases, and client master keys are forbidden on the server.

## Auth and Session Rules

- Passwords must be hashed with a strong password hash before persistence.
- Session tokens must be opaque and only stored as hashes in the database.
- Auth failures must use enumeration-safe, generic user-facing error keys.
- Auth/session logs must not include passwords, tokens, login identifiers, or raw authorization headers.

## Blob Handling Rules

- Sync blobs must be accepted only as ciphertext plus metadata.
- Blob writes must validate:
  - positive schema version,
  - positive generation,
  - non-empty ciphertext,
  - checksum format,
  - checksum match,
  - stale generation rejection,
  - max blob size.
- Do not add plaintext-side inspection of sync snapshots to this repository.

## HTTP and Runtime Hardening

- Default responses should include baseline browser hardening headers and `Cache-Control: no-store`.
- Do not enable global CORS unless the product gains an explicit cross-origin sync client contract.
- Rate limiting must apply to public auth surfaces at minimum.
