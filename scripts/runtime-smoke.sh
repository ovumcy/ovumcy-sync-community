#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:?IMAGE is required}"
CONTAINER_NAME="${CONTAINER_NAME:-ovumcy-sync-community-runtime-smoke}"
HOST_PORT="${HOST_PORT:-18080}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${HOST_PORT}}"
VOLUME_NAME="${CONTAINER_NAME}-data-$(date +%s)"
LOGIN="selftest-$(date +%s)@example.com"
PASSWORD="correct horse battery staple"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  docker volume rm -f "${VOLUME_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "${VOLUME_NAME}" >/dev/null
docker run --rm -v "${VOLUME_NAME}:/data" "${IMAGE}" migrate
docker run -d --rm --name "${CONTAINER_NAME}" -p "${HOST_PORT}:8080" -v "${VOLUME_NAME}:/data" "${IMAGE}" serve >/dev/null

for _ in $(seq 1 30); do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null; then
    break
  fi
  sleep 1
done

curl -fsS "${BASE_URL}/healthz" >/dev/null

register_response="$(curl -fsS -X POST "${BASE_URL}/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"${LOGIN}\",\"password\":\"${PASSWORD}\"}")"

session_token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${register_response}")"
if [[ -z "${session_token}" ]]; then
  echo "missing session token from register response" >&2
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

blob_payload="$(python3 - <<'PY'
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
login_session_token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<<"${login_response}")"
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
