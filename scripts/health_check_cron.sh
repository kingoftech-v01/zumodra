#!/bin/bash
# Automated comprehensive health check
# Run via cron every 5 minutes: */5 * * * * /app/scripts/health_check_cron.sh

# Configuration
HEALTH_LOG="/var/log/zumodra/health_check.log"
HEALTH_JSON="/tmp/health_status.json"

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$HEALTH_LOG")"

# Check if running in Docker environment
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    DOCKER_EXEC="docker exec zumodra_web"
else
    DOCKER_EXEC=""
fi

# Run full health check
if $DOCKER_EXEC python manage.py health_check --full --json > "$HEALTH_JSON" 2>&1; then
    # Health check ran successfully, parse results
    if command -v python3 &> /dev/null && [ -f "$HEALTH_JSON" ]; then
        OVERALL_STATUS=$(python3 -c "import sys, json; data=json.load(open('$HEALTH_JSON')); print(data.get('status', 'unknown'))" 2>/dev/null || echo "unknown")
    else
        OVERALL_STATUS="unknown"
    fi
else
    echo "[$(date)] Health check command failed" >> "$HEALTH_LOG"
    OVERALL_STATUS="error"
fi

echo "[$(date)] Health Status: $OVERALL_STATUS" >> "$HEALTH_LOG"

if [ "$OVERALL_STATUS" != "healthy" ]; then
    echo "[$(date)] UNHEALTHY - Details:" >> "$HEALTH_LOG"
    if [ -f "$HEALTH_JSON" ]; then
        cat "$HEALTH_JSON" >> "$HEALTH_LOG"
    fi

    # Send alert (configure based on your notification system)
    # Uncomment and configure based on your setup:

    # Slack:
    # SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    # curl -X POST "$SLACK_WEBHOOK" -H 'Content-Type: application/json' \
    #      -d "{\"text\":\"🚨 ALERT: Zumodra health check failed: $OVERALL_STATUS\"}" >> "$HEALTH_LOG" 2>&1

    # Email:
    # echo "Zumodra health check failed. Status: $OVERALL_STATUS. See $HEALTH_LOG for details." | \
    #      mail -s "Zumodra Health Alert" ops@example.com

    # PagerDuty:
    # PAGERDUTY_TOKEN="your_token_here"
    # curl -X POST https://api.pagerduty.com/incidents \
    #      -H "Authorization: Token token=$PAGERDUTY_TOKEN" \
    #      -H "Content-Type: application/json" \
    #      -d '{"incident":{"type":"incident","title":"Zumodra Health Check Failed"}}' >> "$HEALTH_LOG" 2>&1
fi

# Cleanup old health status files (keep last 24 hours)
find /tmp -name "health_status*.json" -mmin +1440 -delete 2>/dev/null || true

# Exit successfully (don't fail cron job)
exit 0
