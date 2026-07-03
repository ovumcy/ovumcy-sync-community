#!/usr/bin/env bash
set -euo pipefail

# Some hosts (Windows + Git Bash) have `python3` resolve to the Microsoft Store
# stub which exits non-zero without running. Prefer an explicit PYTHON override,
# otherwise pick the first interpreter that actually executes a one-liner.
if [[ -z "${PYTHON:-}" ]]; then
  for candidate in python3 python; do
    if "${candidate}" -c 'import sys; sys.exit(0)' >/dev/null 2>&1; then
      PYTHON="${candidate}"
      break
    fi
  done
fi
: "${PYTHON:?could not find a working python interpreter (set PYTHON=/path/to/python)}"

IMAGE="${IMAGE:?IMAGE is required}"
CONTAINER_NAME="${CONTAINER_NAME:-ovumcy-sync-community-runtime-smoke}"
HOST_PORT="${HOST_PORT:-18080}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${HOST_PORT}}"
VOLUME_NAME="${CONTAINER_NAME}-data-$(date +%s)"
LOGIN="selftest-$(date +%s)@example.com"
PASSWORD="correct horse battery staple"
METRICS_ENABLED="${METRICS_ENABLED:-true}"
METRICS_BEARER_TOKEN="${METRICS_BEARER_TOKEN:-runtime-smoke-metrics-token}"
# Field-encryption key gates the TOTP 2FA surface. Set it so the smoke exercises
# /auth/totp/* instead of the key-absent 503 path; this also guards against the
# "2FA silently unavailable because the key never reached the container" deploy
# drift. Ephemeral test value only — never a real key.
FIELD_ENCRYPTION_KEY="${FIELD_ENCRYPTION_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  docker volume rm -f "${VOLUME_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "${VOLUME_NAME}" >/dev/null
docker run --rm -v "${VOLUME_NAME}:/data" "${IMAGE}" migrate
docker run -d --rm --name "${CONTAINER_NAME}" \
  -e "METRICS_ENABLED=${METRICS_ENABLED}" \
  -e "METRICS_BEARER_TOKEN=${METRICS_BEARER_TOKEN}" \
  -e "FIELD_ENCRYPTION_KEY=${FIELD_ENCRYPTION_KEY}" \
  -p "${HOST_PORT}:8080" \
  -v "${VOLUME_NAME}:/data" \
  "${IMAGE}" serve >/dev/null

for _ in $(seq 1 30); do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null; then
    break
  fi
  sleep 1
done

curl -fsS "${BASE_URL}/healthz" >/dev/null

metrics_status="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/metrics")"
if [[ "${metrics_status}" != "401" ]]; then
  echo "expected unauthenticated metrics request to return 401, got ${metrics_status}" >&2
  exit 1
fi

curl -fsS "${BASE_URL}/metrics" \
  -H "Authorization: Bearer ${METRICS_BEARER_TOKEN}" >/dev/null

register_response="$(curl -fsS -X POST "${BASE_URL}/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"password\":\"${PASSWORD}\"}")"

session_token="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${register_response}")"
if [[ -z "${session_token}" ]]; then
  echo "missing session token from register response" >&2
  exit 1
fi

recovery_code="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["recovery_code"])' <<<"${register_response}")"
if [[ -z "${recovery_code}" ]]; then
  echo "missing recovery_code from register response" >&2
  exit 1
fi

curl -fsS "${BASE_URL}/sync/capabilities" \
  -H "Authorization: Bearer ${session_token}" >/dev/null

curl -fsS -X POST "${BASE_URL}/sync/devices" \
  -H "Authorization: Bearer ${session_token}" \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"device-12345","device_label":"CI smoke"}' >/dev/null

curl -fsS -X PUT "${BASE_URL}/sync/recovery-key" \
  -H "Authorization: Bearer ${session_token}" \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"xchacha20poly1305","kdf":"bip39_seed_hkdf_sha256","mnemonic_word_count":12,"wrap_nonce_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wrapped_master_key_hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","phrase_fingerprint_hex":"cccccccccccccccc"}' >/dev/null

curl -fsS "${BASE_URL}/sync/recovery-key" \
  -H "Authorization: Bearer ${session_token}" >/dev/null

blob_payload="$("${PYTHON}" - <<'PY'
import base64, hashlib, json
ciphertext = b"runtime-smoke-ciphertext"
print(json.dumps({
    "schema_version": 1,
    "generation": 1,
    "checksum_sha256": hashlib.sha256(ciphertext).hexdigest(),
    "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
}))
PY
)"

curl -fsS -X PUT "${BASE_URL}/sync/blob" \
  -H "Authorization: Bearer ${session_token}" \
  -H 'Content-Type: application/json' \
  -d "${blob_payload}" >/dev/null

curl -fsS "${BASE_URL}/sync/blob" \
  -H "Authorization: Bearer ${session_token}" >/dev/null

login_response="$(curl -fsS -X POST "${BASE_URL}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"password\":\"${PASSWORD}\"}")"
login_session_token="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${login_response}")"
if [[ -z "${login_session_token}" ]]; then
  echo "missing session token from login response" >&2
  exit 1
fi

curl -fsS -X DELETE "${BASE_URL}/auth/session" \
  -H "Authorization: Bearer ${login_session_token}" >/dev/null

logout_status="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/sync/capabilities" \
  -H "Authorization: Bearer ${login_session_token}")"
if [[ "${logout_status}" != "401" ]]; then
  echo "expected revoked token to return 401, got ${logout_status}" >&2
  exit 1
fi

# === Phase 1: change-password revokes other sessions ===

device1_response="$(curl -fsS -X POST "${BASE_URL}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"password\":\"${PASSWORD}\"}")"
device1_token="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${device1_response}")"

device2_response="$(curl -fsS -X POST "${BASE_URL}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"password\":\"${PASSWORD}\"}")"
device2_token="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${device2_response}")"

if [[ "${device1_token}" == "${device2_token}" ]]; then
  echo "expected distinct session tokens for the two logins" >&2
  exit 1
fi

NEW_PASSWORD="updated runtime smoke password"
curl -fsS -X POST "${BASE_URL}/auth/change-password" \
  -H "Authorization: Bearer ${device1_token}" \
  -H 'Content-Type: application/json' \
  -d "{\"current_password\":\"${PASSWORD}\",\"new_password\":\"${NEW_PASSWORD}\"}" >/dev/null

curl -fsS "${BASE_URL}/sync/capabilities" \
  -H "Authorization: Bearer ${device1_token}" >/dev/null

revoked_status="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/sync/capabilities" \
  -H "Authorization: Bearer ${device2_token}")"
if [[ "${revoked_status}" != "401" ]]; then
  echo "expected change-password to revoke other sessions, got ${revoked_status}" >&2
  exit 1
fi

old_login_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"password\":\"${PASSWORD}\"}")"
if [[ "${old_login_status}" != "401" ]]; then
  echo "expected old password to fail login after change-password, got ${old_login_status}" >&2
  exit 1
fi

# === Phase 2: forgot-password / reset-password / regenerate recovery code ===

forgot_response="$(curl -fsS -X POST "${BASE_URL}/auth/forgot-password" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"recovery_code\":\"${recovery_code}\"}")"
reset_token="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["reset_token"])' <<<"${forgot_response}")"
if [[ -z "${reset_token}" ]]; then
  echo "missing reset_token from forgot-password response" >&2
  exit 1
fi

RESET_PASSWORD="post reset runtime smoke password"
reset_response="$(curl -fsS -X POST "${BASE_URL}/auth/reset-password" \
  -H 'Content-Type: application/json' \
  -d "{\"reset_token\":\"${reset_token}\",\"new_password\":\"${RESET_PASSWORD}\"}")"
rotated_recovery_code="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["recovery_code"])' <<<"${reset_response}")"
if [[ -z "${rotated_recovery_code}" ]] || [[ "${rotated_recovery_code}" == "${recovery_code}" ]]; then
  echo "expected reset-password to rotate the recovery code" >&2
  exit 1
fi

post_reset_status="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/sync/capabilities" \
  -H "Authorization: Bearer ${device1_token}")"
if [[ "${post_reset_status}" != "401" ]]; then
  echo "expected reset-password to revoke all sessions, got ${post_reset_status}" >&2
  exit 1
fi

old_recovery_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/forgot-password" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"recovery_code\":\"${recovery_code}\"}")"
if [[ "${old_recovery_status}" != "401" ]]; then
  echo "expected old recovery code to fail after rotation, got ${old_recovery_status}" >&2
  exit 1
fi

post_reset_login_response="$(curl -fsS -X POST "${BASE_URL}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"password\":\"${RESET_PASSWORD}\"}")"
post_reset_session_token="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${post_reset_login_response}")"
if [[ -z "${post_reset_session_token}" ]]; then
  echo "missing session token from post-reset login response" >&2
  exit 1
fi

regenerate_wrong_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/recovery-code/regenerate" \
  -H "Authorization: Bearer ${post_reset_session_token}" \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"wrong password value 12345"}')"
if [[ "${regenerate_wrong_status}" != "401" ]]; then
  echo "expected regenerate with wrong password to return 401, got ${regenerate_wrong_status}" >&2
  exit 1
fi

regenerate_response="$(curl -fsS -X POST "${BASE_URL}/auth/recovery-code/regenerate" \
  -H "Authorization: Bearer ${post_reset_session_token}" \
  -H 'Content-Type: application/json' \
  -d "{\"current_password\":\"${RESET_PASSWORD}\"}")"
regenerated_recovery_code="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["recovery_code"])' <<<"${regenerate_response}")"
if [[ -z "${regenerated_recovery_code}" ]] || [[ "${regenerated_recovery_code}" == "${rotated_recovery_code}" ]]; then
  echo "expected regenerate to issue a new recovery code" >&2
  exit 1
fi

prev_recovery_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/forgot-password" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"recovery_code\":\"${rotated_recovery_code}\"}")"
if [[ "${prev_recovery_status}" != "401" ]]; then
  echo "expected reset-issued recovery code to fail after regenerate, got ${prev_recovery_status}" >&2
  exit 1
fi

curl -fsS -X POST "${BASE_URL}/auth/forgot-password" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"recovery_code\":\"${regenerated_recovery_code}\"}" >/dev/null

# === Phase 3: TOTP 2FA enroll / verify / login challenge ===
# Uses a fresh account so it is independent of the password rotation above. This
# phase doubles as a deploy-wiring guard: if FIELD_ENCRYPTION_KEY had not reached
# the container, enrollment would return 503 here instead of a secret.

totp_code() {
  "${PYTHON}" - "$1" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1].upper()
key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
counter = int(time.time()) // 30
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
print("%06d" % (binary % 1000000))
PY
}

TOTP_LOGIN="totp-selftest-$(date +%s)@example.com"
TOTP_PASSWORD="totp runtime smoke password"

totp_register_response="$(curl -fsS -X POST "${BASE_URL}/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${TOTP_LOGIN}\",\"password\":\"${TOTP_PASSWORD}\"}")"
totp_session_token="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${totp_register_response}")"
if [[ -z "${totp_session_token}" ]]; then
  echo "missing session token from totp account register response" >&2
  exit 1
fi

# Enrollment requires the current password.
enroll_wrong_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/totp/enroll" \
  -H "Authorization: Bearer ${totp_session_token}" \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"wrong password value 12345"}')"
if [[ "${enroll_wrong_status}" != "401" ]]; then
  echo "expected totp enroll with wrong password to return 401, got ${enroll_wrong_status}" >&2
  exit 1
fi

enroll_response="$(curl -fsS -X POST "${BASE_URL}/auth/totp/enroll" \
  -H "Authorization: Bearer ${totp_session_token}" \
  -H 'Content-Type: application/json' \
  -d "{\"current_password\":\"${TOTP_PASSWORD}\"}")"
totp_secret="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["secret_base32"])' <<<"${enroll_response}")"
if [[ -z "${totp_secret}" ]]; then
  echo "missing secret_base32 from totp enroll (is FIELD_ENCRYPTION_KEY configured?)" >&2
  exit 1
fi

# A wrong code must not complete enrollment.
verify_wrong_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/totp/verify" \
  -H "Authorization: Bearer ${totp_session_token}" \
  -H 'Content-Type: application/json' \
  -d '{"code":"000000"}')"
if [[ "${verify_wrong_status}" == "200" ]]; then
  echo "expected totp verify with a wrong code to fail, got 200" >&2
  exit 1
fi

curl -fsS -X POST "${BASE_URL}/auth/totp/verify" \
  -H "Authorization: Bearer ${totp_session_token}" \
  -H 'Content-Type: application/json' \
  -d "{\"code\":\"$(totp_code "${totp_secret}")\"}" >/dev/null

# With TOTP enabled, login must return a challenge and withhold the session.
totp_login_response="$(curl -fsS -X POST "${BASE_URL}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${TOTP_LOGIN}\",\"password\":\"${TOTP_PASSWORD}\"}")"
totp_challenge_id="$("${PYTHON}" -c 'import json,sys; print((json.load(sys.stdin).get("totp_challenge") or {}).get("challenge_id",""))' <<<"${totp_login_response}")"
totp_login_session="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin).get("session_token") or "")' <<<"${totp_login_response}")"
if [[ -z "${totp_challenge_id}" ]]; then
  echo "expected login of a TOTP-enabled account to return a challenge id" >&2
  exit 1
fi
if [[ -n "${totp_login_session}" ]]; then
  echo "expected login of a TOTP-enabled account to withhold the session token until the challenge is met" >&2
  exit 1
fi

# The step CAS rejects reusing the step enrollment just claimed; wait for the
# next 30s window so the challenge code maps to a fresh, higher step.
sleep "$(( 31 - $(date +%s) % 30 ))"

totp_challenge_response="$(curl -fsS -X POST "${BASE_URL}/auth/totp/challenge" \
  -H 'Content-Type: application/json' \
  -d "{\"challenge_id\":\"${totp_challenge_id}\",\"code\":\"$(totp_code "${totp_secret}")\"}")"
totp_challenge_session="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${totp_challenge_response}")"
if [[ -z "${totp_challenge_session}" ]]; then
  echo "missing session token from totp challenge response" >&2
  exit 1
fi

curl -fsS "${BASE_URL}/sync/capabilities" \
  -H "Authorization: Bearer ${totp_challenge_session}" >/dev/null

# === Phase 4: DELETE /account erases the account and everything it owns ===

delete_unauth_status="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "${BASE_URL}/account")"
if [[ "${delete_unauth_status}" != "401" ]]; then
  echo "expected unauthenticated DELETE /account to return 401, got ${delete_unauth_status}" >&2
  exit 1
fi

DELETE_LOGIN="delete-selftest-$(date +%s)@example.com"
DELETE_PASSWORD="correct horse battery staple delete"

delete_register_response="$(curl -fsS -X POST "${BASE_URL}/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${DELETE_LOGIN}\",\"password\":\"${DELETE_PASSWORD}\"}")"
delete_session_token="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${delete_register_response}")"
if [[ -z "${delete_session_token}" ]]; then
  echo "missing session token from delete-account register response" >&2
  exit 1
fi

curl -fsS -X POST "${BASE_URL}/sync/devices" \
  -H "Authorization: Bearer ${delete_session_token}" \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"device-delete-1","device_label":"CI delete smoke"}' >/dev/null

delete_blob_payload="$("${PYTHON}" - <<'PY'
import base64, hashlib, json
ciphertext = b"delete-account-smoke-ciphertext"
print(json.dumps({
    "schema_version": 1,
    "generation": 1,
    "checksum_sha256": hashlib.sha256(ciphertext).hexdigest(),
    "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
}))
PY
)"
curl -fsS -X PUT "${BASE_URL}/sync/blob" \
  -H "Authorization: Bearer ${delete_session_token}" \
  -H 'Content-Type: application/json' \
  -d "${delete_blob_payload}" >/dev/null

delete_response="$(curl -fsS -X DELETE "${BASE_URL}/account" \
  -H "Authorization: Bearer ${delete_session_token}")"
delete_status_field="$("${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"${delete_response}")"
if [[ "${delete_status_field}" != "account_deleted" ]]; then
  echo "expected account_deleted status from DELETE /account, got: ${delete_response}" >&2
  exit 1
fi

post_delete_status="$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/sync/capabilities" \
  -H "Authorization: Bearer ${delete_session_token}")"
if [[ "${post_delete_status}" != "401" ]]; then
  echo "expected the deleted account's own session to stop authenticating, got ${post_delete_status}" >&2
  exit 1
fi

post_delete_login_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${DELETE_LOGIN}\",\"password\":\"${DELETE_PASSWORD}\"}")"
if [[ "${post_delete_login_status}" != "401" ]]; then
  echo "expected login to fail for a deleted account, got ${post_delete_login_status}" >&2
  exit 1
fi

# Repeat DELETE /account with the same (now-revoked) bearer token: the
# account's data is gone either way, and since the session died with the
# account, the caller sees 401 rather than a second 200 or a 500 -- that is
# the idempotent outcome at the HTTP layer (see docs/self-hosting.md #
# "Account Deletion" for why the repeat surfaces as unauthenticated instead
# of a second success).
repeat_delete_status="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "${BASE_URL}/account" \
  -H "Authorization: Bearer ${delete_session_token}")"
if [[ "${repeat_delete_status}" != "401" ]]; then
  echo "expected repeat DELETE /account with a revoked token to return 401, got ${repeat_delete_status}" >&2
  exit 1
fi
