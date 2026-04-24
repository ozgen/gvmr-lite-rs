#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8084}"
SECRET="${GVMR_JWT_SECRET:-supersecret_shared_between_services}"
ISSUER="${GVMR_JWT_ISSUER:-gvmd-lite}"
AUDIENCE="${GVMR_JWT_AUDIENCE:-gvmr-lite}"

echo "Testing JWT auth against: ${BASE_URL}"

make_token() {
  local scope="$1"

  python3 - <<PY
import time
import jwt

secret = "${SECRET}"
now = int(time.time())

payload = {
    "sub": "test-user",
    "iss": "${ISSUER}",
    "aud": "${AUDIENCE}",
    "iat": now,
    "exp": now + 3600,
    "scope": "${scope}",
}

print(jwt.encode(payload, secret, algorithm="HS256"))
PY
}

echo
echo "1 - Missing token should return 401"
curl -i "${BASE_URL}/api/v1/ping"

echo
echo
echo "2 - Valid token should return 200 on /api/v1/ping"
TOKEN="$(make_token "render sync")"

curl -i \
  -H "Authorization: Bearer ${TOKEN}" \
  "${BASE_URL}/api/v1/ping"

echo
echo
echo "3 - Token without sync scope should return 403 on /api/v1/sync-ping"
TOKEN_NO_SYNC="$(make_token "render")"

curl -i \
  -H "Authorization: Bearer ${TOKEN_NO_SYNC}" \
  "${BASE_URL}/api/v1/sync-ping"

echo
echo
echo "4 - Token with sync scope should return 200 on /api/v1/sync-ping"
TOKEN_WITH_SYNC="$(make_token "render sync")"

curl -i \
  -H "Authorization: Bearer ${TOKEN_WITH_SYNC}" \
  "${BASE_URL}/api/v1/sync-ping"

echo
echo
echo "Done"