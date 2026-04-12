#!/bin/sh
# Single Railway service: API (uvicorn) + SQS consumer share one process tree and the same SQLite file
# under /app/transactions.db (enable Postgres with DATABASE_URL instead for durable data).

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
