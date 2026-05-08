#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8084}"
FORMAT_ID="${FORMAT_ID:-c402cc3e-b531-11e1-9163-406186ea4fc5}"
REPORT_XML_FILE="${REPORT_XML_FILE:-report.xml}"
OUTPUT_FILE="${OUTPUT_FILE:-rendered-report.pdf}"
HEADERS_FILE="${HEADERS_FILE:-rendered-report-headers.txt}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-300}"
OUTPUT_NAME="${OUTPUT_NAME:-report.xml}"

API_KEY="${API_KEY:-}"
API_KEY_HEADER="${API_KEY_HEADER:-X-API-Key}"
JWT_TOKEN="${JWT_TOKEN:-}"

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed."
  exit 1
fi

if [[ -z "$FORMAT_ID" ]]; then
  echo "Error: FORMAT_ID is required."
  echo
  echo "Example:"
  echo "  FORMAT_ID=fmt-1 REPORT_XML_FILE=report.xml ./scripts/render-xml.sh"
  exit 1
fi

if [[ ! -f "$REPORT_XML_FILE" ]]; then
  echo "Error: report XML file not found: $REPORT_XML_FILE"
  exit 1
fi

AUTH_HEADERS=()

if [[ -n "$API_KEY" ]]; then
  AUTH_HEADERS+=(-H "${API_KEY_HEADER}: ${API_KEY}")
fi

if [[ -n "$JWT_TOKEN" ]]; then
  AUTH_HEADERS+=(-H "Authorization: Bearer ${JWT_TOKEN}")
fi

BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

jq -n \
  --rawfile report_xml "$REPORT_XML_FILE" \
  --arg format_id "$FORMAT_ID" \
  --arg output_name "$OUTPUT_NAME" \
  --argjson timeout_seconds "$TIMEOUT_SECONDS" \
  '{
    format_id: $format_id,
    report_xml: $report_xml,
    params: {},
    output_name: $output_name,
    timeout_seconds: $timeout_seconds
  }' > "$BODY_FILE"

echo "Rendering XML report..."
echo "  URL: ${BASE_URL}/api/v1/render/xml"
echo "  Format ID: ${FORMAT_ID}"
echo "  Input: ${REPORT_XML_FILE}"
echo "  Output: ${OUTPUT_FILE}"
echo "  Request body: ${BODY_FILE}"

curl -sS \
  -X POST "${BASE_URL}/api/v1/render/xml" \
  -H "Content-Type: application/json" \
  "${AUTH_HEADERS[@]}" \
  --data-binary @"$BODY_FILE" \
  -D "$HEADERS_FILE" \
  -o "$OUTPUT_FILE"

STATUS_CODE="$(awk 'BEGIN { code="" } /^HTTP\// { code=$2 } END { print code }' "$HEADERS_FILE")"

echo
echo "HTTP status: ${STATUS_CODE}"
echo "Headers saved to: ${HEADERS_FILE}"
echo "Response saved to: ${OUTPUT_FILE}"

if [[ "$STATUS_CODE" != "200" ]]; then
  echo
  echo "Request failed. Response body:"
  cat "$OUTPUT_FILE"
  echo
  exit 1
fi

echo
echo "Success."