#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${FLAG_2:-}" ]]; then
  echo "ERROR: FLAG_2 is not set"
  exit 1
fi

if [[ -z "${SECRET_KEY:-}" ]]; then
  echo "ERROR: SECRET_KEY is not set"
  exit 1
fi

# --- Render /app/flag (symlinked to /tmp/flag) from its template ---
if [[ -f "/app/flag.template" ]]; then
  sed "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_2}/g" /app/flag.template > /tmp/flag
  chmod 0600 /tmp/flag
else
  echo "WARNING: /app/flag.template not found, skipping"
fi

# --- Start the server ---
echo "Starting server..."
exec gunicorn -b 0.0.0.0:8000 server:app
