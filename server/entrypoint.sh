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

# --- Replace placeholder in /app/flag ---
if [[ -f "/app/flag" ]]; then
  if grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/tmp/flag"; then
    sed -i "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_2}/g" /tmp/flag
    chmod 400 /tmp/flag
  fi
else
  echo "WARNING: /app/flag not found, skipping"
fi

unset FLAG_2

# --- Start the server ---
echo "Starting server..."
exec gunicorn -b 0.0.0.0:8000 server:app
