#!/bin/sh
# Single Railway service: uvicorn (API) + consumer.py (SQS). Both use db.py → DATABASE_URL (Postgres on Railway).

set -e
PORT="${PORT:-8000}"

uvicorn api:app --host 0.0.0.0 --port "$PORT" &
UV_PID=$!

cleanup() {
  kill "$UV_PID" 2>/dev/null || true
}
trap cleanup INT TERM

python -u consumer.py
STATUS=$?
cleanup
wait "$UV_PID" 2>/dev/null || true
exit "$STATUS"
