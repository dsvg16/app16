# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy project description and sources, then install once everything is present
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src

COPY flag /app/flag.template
COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e . \
 && addgroup --system tatou \
 && adduser --system --ingroup tatou tatou \
 && mkdir -p /app/storage \
 && ln -s /tmp/flag /app/flag \
 && chown -R tatou:tatou /app/flag.template /app/entrypoint.sh /app/storage \
 && chmod 0555 /app/entrypoint.sh \
 && chmod 0600 /app/flag.template

USER tatou

EXPOSE 8000

# Default command runs the web server
CMD ["./entrypoint.sh"]
