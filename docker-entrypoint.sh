#!/bin/sh
set -e
# Railway: duplicate this repo as a second service and set SERVICE_ROLE=api for Lovable HTTP API.
# Default (unset or "worker") runs the SQS consumer.
if [ "${SERVICE_ROLE:-worker}" = "api" ]; then
  exec uvicorn api:app --host 0.0.0.0 --port "${PORT:-8000}"
fi
exec python -u consumer.py
