#!/bin/bash
# scripts/backup_before_migration.sh

set -e

# Validate required environment variable
if [ -z "${DB_PASSWORD}" ]; then
    echo "Error: DB_PASSWORD environment variable must be set"
    exit 1
fi

BACKUP_DIR="backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/before_permission_migration_${TIMESTAMP}.sql"

mkdir -p "${BACKUP_DIR}"

echo "Creating database backup..."

# Create temporary MySQL config file (secure method)
TEMP_CNF=$(mktemp)
cat > "${TEMP_CNF}" <<EOF
[client]
user=${DB_USER:-root}
password=${DB_PASSWORD}
EOF
chmod 600 "${TEMP_CNF}"

# Perform backup with transaction consistency
mysqldump --defaults-extra-file="${TEMP_CNF}" \
    --single-transaction \
    --routines \
    --triggers \
    --events \
    "${DB_NAME:-paigram}" > "${BACKUP_FILE}"

# Clean up temp file
rm -f "${TEMP_CNF}"

echo "Backup created: ${BACKUP_FILE}"
echo "File size: $(du -h "${BACKUP_FILE}" | cut -f1)"

# Verify backup is valid
if [ -s "${BACKUP_FILE}" ] && grep -q "Dump completed" "${BACKUP_FILE}"; then
    echo "Backup verification: SUCCESS"
else
    echo "Backup verification: FAILED - File is empty or incomplete!"
    exit 1
fi