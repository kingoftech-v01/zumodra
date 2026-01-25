#!/bin/bash
# Automated tenant migration monitoring and self-healing
# Run via cron every 15 minutes: */15 * * * * /app/scripts/monitor_tenant_migrations.sh

set -e

# Configuration
LOG_FILE="/var/log/zumodra/migration_monitor.log"
JSON_OUTPUT="/tmp/migration_status_$(date +%Y%m%d_%H%M%S).json"

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Check if running in Docker environment
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    DOCKER_EXEC="docker exec zumodra_web"
else
    DOCKER_EXEC=""
fi

echo "[$(date)] Starting migration check..." >> "$LOG_FILE"

# Check migration status with JSON output
if $DOCKER_EXEC python manage.py verify_tenant_migrations --json > "$JSON_OUTPUT" 2>&1; then
    echo "[$(date)] Migration check command executed successfully" >> "$LOG_FILE"
else
    echo "[$(date)] Migration check command failed with exit code $?" >> "$LOG_FILE"
fi

# Parse JSON to check for issues
if [ -f "$JSON_OUTPUT" ] && command -v python3 &> /dev/null; then
    TENANTS_WITH_ISSUES=$(python3 -c "import sys, json; data=json.load(open('$JSON_OUTPUT')); print(data.get('tenants_with_issues', 0))" 2>/dev/null || echo "0")
else
    echo "[$(date)] Could not parse JSON output" >> "$LOG_FILE"
    TENANTS_WITH_ISSUES=0
fi

if [ "$TENANTS_WITH_ISSUES" -gt 0 ]; then
    echo "[$(date)] WARNING: Found $TENANTS_WITH_ISSUES tenant(s) with migration issues" >> "$LOG_FILE"
    cat "$JSON_OUTPUT" >> "$LOG_FILE"

    # Attempt automatic fix
    echo "[$(date)] Attempting automatic fix..." >> "$LOG_FILE"
    if $DOCKER_EXEC python manage.py verify_tenant_migrations --fix --json >> "$LOG_FILE" 2>&1; then
        echo "[$(date)] Auto-fix successful!" >> "$LOG_FILE"

        # Send success notification (optional - integrate with your notification system)
        # Uncomment and configure based on your notification system
        # SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        # curl -X POST "$SLACK_WEBHOOK" -H 'Content-Type: application/json' \
        #      -d '{"text":"✅ Zumodra: Migration issue auto-fixed on production"}' >> "$LOG_FILE" 2>&1
    else
        echo "[$(date)] Auto-fix failed! Manual intervention required." >> "$LOG_FILE"

        # Send alert (integrate with your notification system)
        # Uncomment and configure based on your notification system
        # SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        # curl -X POST "$SLACK_WEBHOOK" -H 'Content-Type: application/json' \
        #      -d '{"text":"🚨 ALERT: Zumodra migration issue requires manual fix"}' >> "$LOG_FILE" 2>&1

        # Alternative: Send email
        # echo "Migration issue detected. Check $LOG_FILE for details." | mail -s "Zumodra Alert" ops@example.com
    fi
else
    echo "[$(date)] All tenant migrations OK (checked $TENANTS_WITH_ISSUES tenants)" >> "$LOG_FILE"
fi

# Cleanup old JSON files (keep last 7 days)
find /tmp -name "migration_status_*.json" -mtime +7 -delete 2>/dev/null || true

echo "[$(date)] Migration check complete" >> "$LOG_FILE"

# Exit successfully
exit 0
