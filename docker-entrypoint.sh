#!/bin/sh
# Single Railway service: uvicorn (API) + consumer.py (SQS). Both use db.py → DATABASE_URL (Postgres on Railway).
# Keep API alive even if the SQS consumer exits, so Railway /health can pass.

PORT="${PORT:-8000}"

uvicorn api:app --host 0.0.0.0 --port "$PORT" &
UV_PID=$!

cleanup() {
  kill "$UV_PID" 2>/dev/null || true
}
trap cleanup INT TERM

# Wait until API answers /health (max ~60s) before starting consumer.
i=0
while [ "$i" -lt 60 ]; do
  if ! kill -0 "$UV_PID" 2>/dev/null; then
    echo "uvicorn exited before ready" >&2
    exit 1
  fi
  if python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/health', timeout=1).read()" 2>/dev/null; then
    echo "API health OK on :${PORT}"
    break
  fi
  i=$((i + 1))
  sleep 1
done

while true; do
  python -u consumer.py
  echo "consumer exited; restarting in 5s" >&2
  sleep 5
done
