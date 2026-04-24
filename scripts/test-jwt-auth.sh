#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8084}"
SECRET="${GVMR_JWT_SECRET:-supersecret_shared_between_services}"
ISSUER="${GVMR_JWT_ISSUER:-gvmd-lite}"
AUDIENCE="${GVMR_JWT_AUDIENCE:-gvmr-lite}"

echo "Testing JWT auth against: ${BASE_URL}"

echo
echo "1 - Missing token should return 401"
curl -i "${BASE_URL}/api/v1/ping"

echo
echo
echo "2 - Generating JWT token"
TOKEN="$(python3 - <<PY
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
    "scope": "render sync",
}

print(jwt.encode(payload, secret, algorithm="HS256"))
PY
)"

echo "Token generated"

echo
echo "3 - Valid token should return 200"
curl -i \
  -H "Authorization: Bearer ${TOKEN}" \
  "${BASE_URL}/api/v1/ping"

echo
echo
echo "Done"