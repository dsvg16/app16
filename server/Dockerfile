# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e . \
 && addgroup --system tatou \
 && adduser --system --ingroup tatou tatou \
 && mkdir -p /app/storage \
 && chown -R tatou:tatou /app/flag /app/entrypoint.sh /app/storage \
 && chmod 0555 /app/entrypoint.sh \
 && chmod 0600 /app/flag

USER tatou

EXPOSE 8000

# Default command runs the web server
CMD ["./entrypoint.sh"]
