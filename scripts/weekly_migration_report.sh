#!/bin/bash
# Weekly migration status report
# Run via cron: 0 9 * * 1 /app/scripts/weekly_migration_report.sh
# Sends comprehensive report every Monday at 9 AM

set -e

# Configuration
REPORT_FILE="/tmp/migration_report_$(date +%Y%m%d).txt"
JSON_FILE="/tmp/migration_report_$(date +%Y%m%d).json"
WEEK_START=$(date -d "7 days ago" +%Y-%m-%d)
WEEK_END=$(date +%Y-%m-%d)

# Check if running in Docker environment
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    DOCKER_EXEC="docker exec zumodra_web"
else
    DOCKER_EXEC=""
fi

# Generate report
echo "=== Zumodra Weekly Migration Report ===" > "$REPORT_FILE"
echo "Report Period: $WEEK_START to $WEEK_END" >> "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 1. Current Migration Status
echo "## 1. Current Migration Status" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

$DOCKER_EXEC python manage.py verify_tenant_migrations --json > "$JSON_FILE" 2>&1 || true

if [ -f "$JSON_FILE" ]; then
    TOTAL_TENANTS=$(python3 -c "import sys, json; print(json.load(open('$JSON_FILE')).get('total_tenants', 0))" 2>/dev/null || echo "0")
    TENANTS_OK=$(python3 -c "import sys, json; print(json.load(open('$JSON_FILE')).get('tenants_ok', 0))" 2>/dev/null || echo "0")
    TENANTS_ISSUES=$(python3 -c "import sys, json; print(json.load(open('$JSON_FILE')).get('tenants_with_issues', 0))" 2>/dev/null || echo "0")

    echo "Total Tenants: $TOTAL_TENANTS" >> "$REPORT_FILE"
    echo "Tenants OK: $TENANTS_OK" >> "$REPORT_FILE"
    echo "Tenants with Issues: $TENANTS_ISSUES" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    if [ "$TENANTS_ISSUES" -gt 0 ]; then
        echo "⚠ WARNING: $TENANTS_ISSUES tenant(s) have migration issues!" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "Details:" >> "$REPORT_FILE"
        python3 -c "
import json
data = json.load(open('$JSON_FILE'))
for tenant in data.get('tenants', []):
    if tenant.get('pending_count', 0) > 0:
        print(f\"  - {tenant['schema_name']}: {tenant['pending_count']} pending migrations\")
" >> "$REPORT_FILE" 2>/dev/null || echo "  (Unable to parse details)" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
else
    echo "Unable to retrieve migration status" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# 2. Health Check Summary
echo "## 2. Health Check Summary" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

$DOCKER_EXEC python manage.py health_check --full --json > /tmp/health_report.json 2>&1 || true

if [ -f /tmp/health_report.json ]; then
    HEALTH_STATUS=$(python3 -c "import sys, json; print(json.load(open('/tmp/health_report.json')).get('status', 'unknown'))" 2>/dev/null || echo "unknown")
    echo "Overall Status: $HEALTH_STATUS" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Tenant migrations check
    TENANT_MIG_STATUS=$(python3 -c "
import json
data = json.load(open('/tmp/health_report.json'))
check = data.get('checks', {}).get('tenant_migrations', {})
print(check.get('status', 'unknown'))
" 2>/dev/null || echo "unknown")

    echo "Tenant Migrations Check: $TENANT_MIG_STATUS" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# 3. Activity This Week
echo "## 3. Migration Activity (Past 7 Days)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

if [ -f /var/log/zumodra/migration_monitor.log ]; then
    # Count auto-fixes
    AUTO_FIXES=$(grep -c "Auto-fix successful" /var/log/zumodra/migration_monitor.log 2>/dev/null || echo "0")
    echo "Automatic Fixes Applied: $AUTO_FIXES" >> "$REPORT_FILE"

    # Count failures
    FAILURES=$(grep -c "Auto-fix failed" /var/log/zumodra/migration_monitor.log 2>/dev/null || echo "0")
    echo "Failed Fix Attempts: $FAILURES" >> "$REPORT_FILE"

    # Count warnings
    WARNINGS=$(grep -c "WARNING.*migration" /var/log/zumodra/migration_monitor.log 2>/dev/null || echo "0")
    echo "Migration Warnings: $WARNINGS" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    if [ "$FAILURES" -gt 0 ]; then
        echo "⚠ Recent Failures:" >> "$REPORT_FILE"
        grep "Auto-fix failed" /var/log/zumodra/migration_monitor.log | tail -5 >> "$REPORT_FILE" 2>/dev/null || echo "  (No details available)" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
else
    echo "No monitoring logs available" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# 4. Performance Metrics
echo "## 4. Performance Metrics" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Average verification time (estimate from logs)
if [ -f /var/log/zumodra/migration_monitor.log ]; then
    CHECKS_RUN=$(grep -c "Migration check complete" /var/log/zumodra/migration_monitor.log 2>/dev/null || echo "0")
    echo "Migration Checks Run: $CHECKS_RUN" >> "$REPORT_FILE"
    echo "Check Frequency: Every 15 minutes (expected: 672/week)" >> "$REPORT_FILE"

    # Calculate coverage
    EXPECTED=672
    if [ "$CHECKS_RUN" -gt 0 ]; then
        COVERAGE=$((CHECKS_RUN * 100 / EXPECTED))
        echo "Monitoring Coverage: ${COVERAGE}%" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
fi

# 5. Recommendations
echo "## 5. Recommendations" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

if [ "$TENANTS_ISSUES" -gt 0 ]; then
    echo "⚠ ACTION REQUIRED:" >> "$REPORT_FILE"
    echo "  1. Investigate tenants with pending migrations" >> "$REPORT_FILE"
    echo "  2. Run: python manage.py verify_tenant_migrations --fix" >> "$REPORT_FILE"
    echo "  3. Review logs: tail -100 /var/log/zumodra/migration_monitor.log" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

if [ "$FAILURES" -gt 5 ]; then
    echo "⚠ HIGH FAILURE RATE:" >> "$REPORT_FILE"
    echo "  1. Review failure patterns in logs" >> "$REPORT_FILE"
    echo "  2. Check database connectivity and permissions" >> "$REPORT_FILE"
    echo "  3. Consider manual intervention" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

if [ "$HEALTH_STATUS" != "healthy" ]; then
    echo "⚠ UNHEALTHY STATUS:" >> "$REPORT_FILE"
    echo "  1. Run full health check: python manage.py health_check --full" >> "$REPORT_FILE"
    echo "  2. Address any issues reported" >> "$REPORT_FILE"
    echo "  3. Monitor for recurring problems" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

if [ "$TENANTS_ISSUES" -eq 0 ] && [ "$FAILURES" -eq 0 ] && [ "$HEALTH_STATUS" = "healthy" ]; then
    echo "✓ ALL SYSTEMS NOMINAL" >> "$REPORT_FILE"
    echo "  - All tenants have complete migrations" >> "$REPORT_FILE"
    echo "  - No failures this week" >> "$REPORT_FILE"
    echo "  - System health is good" >> "$REPORT_FILE"
    echo "  - Continue monitoring as usual" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# 6. Trending
echo "## 6. Trends" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Compare with last week if available
LAST_REPORT=$(find /tmp -name "migration_report_*.txt" -mtime +6 -mtime -8 | head -1)
if [ -n "$LAST_REPORT" ]; then
    LAST_TENANTS_ISSUES=$(grep "Tenants with Issues:" "$LAST_REPORT" | awk '{print $NF}' || echo "0")
    LAST_FAILURES=$(grep "Failed Fix Attempts:" "$LAST_REPORT" | awk '{print $NF}' || echo "0")

    echo "Comparison with Last Week:" >> "$REPORT_FILE"
    echo "  Tenants with Issues: $LAST_TENANTS_ISSUES → $TENANTS_ISSUES" >> "$REPORT_FILE"
    echo "  Failed Fixes: $LAST_FAILURES → $FAILURES" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Trend analysis
    if [ "$TENANTS_ISSUES" -gt "$LAST_TENANTS_ISSUES" ]; then
        echo "⚠ TREND: Increasing migration issues (investigate)" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    elif [ "$TENANTS_ISSUES" -lt "$LAST_TENANTS_ISSUES" ]; then
        echo "✓ TREND: Improving migration health" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi

# 7. Action Items
echo "## 7. Action Items for Next Week" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "- [ ] Review this report" >> "$REPORT_FILE"
echo "- [ ] Address any warnings above" >> "$REPORT_FILE"
echo "- [ ] Verify monitoring is running correctly" >> "$REPORT_FILE"
echo "- [ ] Check log rotation and cleanup" >> "$REPORT_FILE"
echo "- [ ] Update runbooks if needed" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Footer
echo "---" >> "$REPORT_FILE"
echo "For detailed information, see:" >> "$REPORT_FILE"
echo "  - Migration logs: /var/log/zumodra/migration_monitor.log" >> "$REPORT_FILE"
echo "  - Health logs: /var/log/zumodra/health_check.log" >> "$REPORT_FILE"
echo "  - Runbook: docs/runbooks/tenant-migration-troubleshooting.md" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "Generated by: $0" >> "$REPORT_FILE"
echo "=== End of Report ===" >> "$REPORT_FILE"

# Display report
cat "$REPORT_FILE"

# Send report (configure based on your notification system)
# Option 1: Email
# if command -v mail &> /dev/null; then
#     cat "$REPORT_FILE" | mail -s "Zumodra Weekly Migration Report" ops@example.com
# fi

# Option 2: Slack
# if [ -n "$SLACK_WEBHOOK" ]; then
#     REPORT_SUMMARY=$(head -30 "$REPORT_FILE")
#     curl -X POST "$SLACK_WEBHOOK" -H 'Content-Type: application/json' \
#          -d "{\"text\":\"Weekly Migration Report:\\n\`\`\`$REPORT_SUMMARY\`\`\`\"}"
# fi

# Option 3: Save to shared location
# cp "$REPORT_FILE" /var/www/reports/latest_migration_report.txt

# Cleanup old reports (keep last 12 weeks)
find /tmp -name "migration_report_*.txt" -mtime +84 -delete 2>/dev/null || true
find /tmp -name "migration_report_*.json" -mtime +84 -delete 2>/dev/null || true

echo ""
echo "Report saved to: $REPORT_FILE"
exit 0
