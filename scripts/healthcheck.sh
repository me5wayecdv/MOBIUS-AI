#!/bin/sh
# Wait for a locally running MOBIUS API to report healthy, then print the status.
# Usage: scripts/healthcheck.sh [base-url] [timeout-seconds]
set -eu
BASE="${1:-http://127.0.0.1:8000}"
LIMIT="${2:-60}"
n=0
until curl -fsS -m 5 "$BASE/api/v1/health" 2>/dev/null; do
  n=$((n + 1))
  if [ "$n" -ge "$LIMIT" ]; then
    echo "MOBIUS did not become healthy within ${LIMIT}s at $BASE" >&2
    exit 1
  fi
  sleep 1
done
echo
