#!/bin/bash
# Database backup script before migrations
# Creates a full database backup with timestamp

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups/zumodra}"
DB_CONTAINER="${DB_CONTAINER:-zumodra_postgres}"
DB_USER="${DB_USER:-zumodra_user}"
DB_NAME="${DB_NAME:-zumodra_db}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Generate backup filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/zumodra_backup_$TIMESTAMP.dump"
BACKUP_LOG="$BACKUP_DIR/zumodra_backup_$TIMESTAMP.log"

echo "=== Zumodra Database Backup ===" | tee -a "$BACKUP_LOG"
echo "Started: $(date)" | tee -a "$BACKUP_LOG"
echo "Backup file: $BACKUP_FILE" | tee -a "$BACKUP_LOG"
echo "" | tee -a "$BACKUP_LOG"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker not found" | tee -a "$BACKUP_LOG"
    exit 1
fi

# Check if database container is running
if ! docker ps | grep -q "$DB_CONTAINER"; then
    echo "ERROR: Database container '$DB_CONTAINER' is not running" | tee -a "$BACKUP_LOG"
    exit 1
fi

# Get database size
echo "[1/5] Checking database size..." | tee -a "$BACKUP_LOG"
DB_SIZE=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c "
SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" 2>&1 | xargs)
echo "Database size: $DB_SIZE" | tee -a "$BACKUP_LOG"
echo "" | tee -a "$BACKUP_LOG"

# Check available disk space
echo "[2/5] Checking available disk space..." | tee -a "$BACKUP_LOG"
AVAILABLE_SPACE=$(df -h "$BACKUP_DIR" | awk 'NR==2 {print $4}')
echo "Available space: $AVAILABLE_SPACE" | tee -a "$BACKUP_LOG"
echo "" | tee -a "$BACKUP_LOG"

# Create backup
echo "[3/5] Creating backup..." | tee -a "$BACKUP_LOG"
START_TIME=$(date +%s)

if docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc > "$BACKUP_FILE" 2>> "$BACKUP_LOG"; then
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    echo "✓ Backup created successfully" | tee -a "$BACKUP_LOG"
    echo "Duration: ${DURATION}s" | tee -a "$BACKUP_LOG"

    # Get backup file size
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "Backup size: $BACKUP_SIZE" | tee -a "$BACKUP_LOG"
else
    echo "✗ Backup failed!" | tee -a "$BACKUP_LOG"
    exit 1
fi
echo "" | tee -a "$BACKUP_LOG"

# Verify backup
echo "[4/5] Verifying backup..." | tee -a "$BACKUP_LOG"
if docker exec "$DB_CONTAINER" pg_restore --list "$BACKUP_FILE" > /dev/null 2>&1; then
    echo "✓ Backup file is valid" | tee -a "$BACKUP_LOG"
else
    echo "⚠ WARNING: Backup verification failed" | tee -a "$BACKUP_LOG"
fi
echo "" | tee -a "$BACKUP_LOG"

# Cleanup old backups
echo "[5/5] Cleaning up old backups (keeping last $RETENTION_DAYS days)..." | tee -a "$BACKUP_LOG"
OLD_BACKUPS=$(find "$BACKUP_DIR" -name "zumodra_backup_*.dump" -mtime +$RETENTION_DAYS 2>/dev/null)

if [ -n "$OLD_BACKUPS" ]; then
    echo "$OLD_BACKUPS" | while read -r old_backup; do
        echo "Deleting: $old_backup" | tee -a "$BACKUP_LOG"
        rm -f "$old_backup"
    done
    # Also delete old log files
    find "$BACKUP_DIR" -name "zumodra_backup_*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
else
    echo "No old backups to delete" | tee -a "$BACKUP_LOG"
fi
echo "" | tee -a "$BACKUP_LOG"

# Summary
echo "=== Backup Complete ===" | tee -a "$BACKUP_LOG"
echo "Backup file: $BACKUP_FILE" | tee -a "$BACKUP_LOG"
echo "Backup size: $BACKUP_SIZE" | tee -a "$BACKUP_LOG"
echo "Log file: $BACKUP_LOG" | tee -a "$BACKUP_LOG"
echo "Finished: $(date)" | tee -a "$BACKUP_LOG"

# Optional: Compress backup
if command -v gzip &> /dev/null; then
    echo "" | tee -a "$BACKUP_LOG"
    echo "Compressing backup..." | tee -a "$BACKUP_LOG"
    gzip "$BACKUP_FILE"
    COMPRESSED_SIZE=$(du -h "${BACKUP_FILE}.gz" | cut -f1)
    echo "✓ Backup compressed: ${BACKUP_FILE}.gz" | tee -a "$BACKUP_LOG"
    echo "Compressed size: $COMPRESSED_SIZE" | tee -a "$BACKUP_LOG"
    BACKUP_FILE="${BACKUP_FILE}.gz"
fi

echo ""
echo "Backup location: $BACKUP_FILE"

# Return backup filename for use by other scripts
echo "$BACKUP_FILE"

exit 0
