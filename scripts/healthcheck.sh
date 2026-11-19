#!/bin/sh
# Wait for a locally running MOBIUS API to report healthy, then print the status.
# Usage: scripts/healthcheck.sh [base-url] [deadline-seconds]
set -eu
BASE="${1:-http://127.0.0.1:8000}"
DEADLINE="${2:-60}"
end=$(( $(date +%s) + DEADLINE ))
until curl -fsS -m 2 "$BASE/api/v1/health" 2>/dev/null; do
  if [ "$(date +%s)" -ge "$end" ]; then
    echo "MOBIUS did not become healthy within ${DEADLINE}s at $BASE" >&2
    exit 1
  fi
  sleep 1
done
echo
