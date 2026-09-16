# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# git is only needed to fetch the pinned rmap commit, so remove it after
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && pip install --no-cache-dir -e . \
 && apt-get purge -y git \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# Copy sources after dependencies installation
COPY src /app/src
COPY flag /app/flag.template
COPY entrypoint.sh /app/entrypoint.sh

#    - Create a dedicated non-root system user & group with no login shell
#    - Lock down entrypoint to read+execute only (0555) so it cannot be tampered with
#    - Restrict flag permissions strictly to owner-only (0400)
#    - Create writable storage directory for user documents
RUN addgroup --system --gid 1001 appuser \
 && adduser --system --uid 1001 --ingroup appuser --no-create-home appuser \
 && mkdir -p /app/storage \
 && ln -s /tmp/flag /app/flag \
 && chown -R appuser:appuser /app/storage \
 && chown appuser:appuser /app/flag.template \
 && chmod 0400 /app/flag.template \
 && chmod 0555 /app/entrypoint.sh

USER appuser

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]
