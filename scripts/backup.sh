#!/bin/sh
set -eu

BACKUP_DIR="/backups"
INTERVAL="${BACKUP_INTERVAL:-21600}"
KEEP="${BACKUP_KEEP:-7}"

mkdir -p "$BACKUP_DIR"

while true; do
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  TARGET="${BACKUP_DIR}/${TIMESTAMP}"
  mkdir -p "$TARGET"

  echo "Backup [$(date)] "

  # Dump database
  mariadb-dump -h db -u root -p"$MARIADB_ROOT_PASSWORD" --single-transaction --quick tatou > "${TARGET}/tatou.sql"

  # Archive user files
  tar -czf "${TARGET}/storage.tar.gz" -C /storage .

  # Clean older snapshots
  ls -dt "${BACKUP_DIR}"/* 2>/dev/null | tail -n +$((KEEP + 1)) | xargs rm -rf 2>/dev/null || true

  echo "[+] [$(date)] Backup completed at ./backups/${TIMESTAMP}"
  sleep "$INTERVAL"
done
