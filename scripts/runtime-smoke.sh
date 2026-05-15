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
