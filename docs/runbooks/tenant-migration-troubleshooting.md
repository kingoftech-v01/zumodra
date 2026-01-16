# Tenant Migration Troubleshooting Runbook

**Version:** 1.0
**Last Updated:** 2026-01-15
**Maintainer:** DevOps Team

## Purpose

This runbook provides step-by-step procedures for diagnosing and resolving tenant migration issues in the Zumodra platform.

---

## Table of Contents

1. [Quick Diagnosis](#quick-diagnosis)
2. [Common Issues](#common-issues)
3. [Emergency Procedures](#emergency-procedures)
4. [Step-by-Step Resolution](#step-by-step-resolution)
5. [Verification](#verification)
6. [Rollback Procedures](#rollback-procedures)
7. [Post-Incident](#post-incident)

---

## Quick Diagnosis

### Symptoms

- Users seeing 500 errors on finance pages
- "relation does not exist" errors in logs
- Health check showing migration warnings
- Automated monitoring sending alerts

### Immediate Checks

```bash
# 1. Check migration status
python manage.py verify_tenant_migrations --json

# 2. Run health check
python manage.py health_check --full

# 3. Check recent logs
tail -100 /var/log/zumodra/migration_monitor.log

# 4. Check database connectivity
python manage.py dbshell -c "\dt" # List tables in current schema
```

---

## Common Issues

### Issue 1: Finance Tables Missing in Tenant Schema

**Symptoms:**
- Error: `relation "finance_usersubscription" does not exist`
- Finance pages return 500 errors

**Diagnosis:**
```bash
# Check if finance migrations are pending
python manage.py verify_tenant_migrations --app=finance --json

# Verify table exists in tenant schema
docker exec zumodra_postgres psql -U $DB_USER -d $DB_NAME -c "
SET search_path TO tenant_demo;
SELECT COUNT(*) FROM information_schema.tables
WHERE table_name LIKE 'finance_%';"
```

**Resolution:**
```bash
# Run immediate fix
./scripts/fix_production_migrations.sh

# OR manually:
python manage.py migrate_schemas --tenant --noinput
python manage.py verify_tenant_migrations --fix
```

**Prevention:**
- Ensure automated monitoring is running
- Verify deployment process includes migration step
- Check migrations in staging before production

---

### Issue 2: Migrations Partially Applied

**Symptoms:**
- Some tenants work, others don't
- Inconsistent errors across subdomains

**Diagnosis:**
```bash
# Check each tenant individually
python manage.py verify_tenant_migrations --json | \
  python -c "import sys, json; data=json.load(sys.stdin); \
  [print(f\"{t['schema_name']}: {t['pending_count']} pending\") \
  for t in data['tenants']]"
```

**Resolution:**
```bash
# Fix all tenants
python manage.py migrate_schemas --tenant --noinput

# Verify specific tenant
python manage.py verify_tenant_migrations --tenant=<schema_name>

# Force re-apply if needed
python manage.py migrate_schemas --tenant --noinput --run-syncdb
```

---

### Issue 3: Migration Locked/Hanging

**Symptoms:**
- Migration command hangs indefinitely
- Database locks visible
- Timeout errors

**Diagnosis:**
```bash
# Check for database locks
docker exec zumodra_postgres psql -U $DB_USER -d $DB_NAME -c "
SELECT pid, query, state, query_start
FROM pg_stat_activity
WHERE state != 'idle'
AND query LIKE '%django_migrations%';"
```

**Resolution:**
```bash
# 1. Identify blocking queries
docker exec zumodra_postgres psql -U $DB_USER -d $DB_NAME -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'active'
AND query LIKE '%django_migrations%'
AND query_start < NOW() - INTERVAL '5 minutes';"

# 2. Retry migration
python manage.py migrate_schemas --tenant --noinput

# 3. If still locked, restart PostgreSQL (last resort)
docker-compose restart db
# Wait 30 seconds
python manage.py migrate_schemas --tenant --noinput
```

**Prevention:**
- Monitor migration duration
- Set reasonable timeouts
- Avoid migrations during high traffic

---

### Issue 4: Automated Fix Failing

**Symptoms:**
- `monitor_tenant_migrations.sh` reporting failures
- Auto-fix attempts unsuccessful
- Repeated alerts

**Diagnosis:**
```bash
# Check monitoring logs
tail -100 /var/log/zumodra/migration_monitor.log

# Check for specific errors
grep "Auto-fix failed" /var/log/zumodra/migration_monitor.log | tail -20

# Test manual fix
python manage.py verify_tenant_migrations --fix --json
```

**Resolution:**
```bash
# 1. Review error details
cat /tmp/migration_status_*.json | python -m json.tool | less

# 2. Check database permissions
docker exec zumodra_postgres psql -U $DB_USER -d $DB_NAME -c "
SELECT has_schema_privilege('tenant_demo', 'CREATE');"

# 3. Verify migration files exist
ls -la */migrations/

# 4. Check for migration conflicts
python manage.py showmigrations

# 5. If all else fails, contact database admin
# Document error and escalate
```

---

### Issue 5: New Tenant Created Without Migrations

**Symptoms:**
- Newly created tenant has no tables
- Users can't access new tenant features

**Diagnosis:**
```bash
# Check when tenant was created
python manage.py shell -c "
from django_tenants.utils import get_tenant_model;
Tenant = get_tenant_model();
t = Tenant.objects.get(schema_name='tenant_new');
print(f'Created: {t.created_on}')
"

# Check migration status
python manage.py verify_tenant_migrations --tenant=tenant_new
```

**Resolution:**
```bash
# Apply migrations to specific tenant
python manage.py migrate_schemas --schema=tenant_new

# Verify
python manage.py verify_tenant_migrations --tenant=tenant_new
```

**Root Cause Analysis:**
- Check if `CREATE_DEMO_TENANT` triggered migrations
- Verify entrypoint.sh Step 4 executed
- Review tenant creation process

---

## Emergency Procedures

### Emergency Response Protocol

**Severity Levels:**

- **P0 (Critical):** All tenants affected, site down
- **P1 (High):** Multiple tenants affected, degraded service
- **P2 (Medium):** Single tenant affected
- **P3 (Low):** Monitoring alerts, no user impact

### P0 - Critical: All Tenants Down

```bash
# 1. IMMEDIATE: Enable maintenance mode
# Create maintenance page or return 503

# 2. Check system health
python manage.py health_check --full --json

# 3. Apply emergency fix
./scripts/fix_production_migrations.sh

# 4. If fix fails, rollback to last known good
./scripts/rollback_migrations.sh

# 5. Restore from backup if necessary
./scripts/restore_database.sh <backup_file>

# 6. Notify stakeholders
# Use incident communication channels
```

### P1 - High: Multiple Tenants Affected

```bash
# 1. Identify affected tenants
python manage.py verify_tenant_migrations --json | \
  python -c "import sys, json; data=json.load(sys.stdin); \
  print('Affected:', [t['schema_name'] for t in data['tenants'] if t['pending_count'] > 0])"

# 2. Apply targeted fix
for tenant in $(cat /tmp/affected_tenants.txt); do
    python manage.py migrate_schemas --schema=$tenant
done

# 3. Verify fix
python manage.py verify_tenant_migrations --json

# 4. Monitor for 15 minutes
watch -n 60 'python manage.py health_check --full'
```

### P2 - Medium: Single Tenant Affected

```bash
# 1. Isolate tenant
echo "Tenant: <schema_name>"

# 2. Apply fix to specific tenant
python manage.py migrate_schemas --schema=<schema_name>

# 3. Verify
python manage.py verify_tenant_migrations --tenant=<schema_name>

# 4. Inform tenant admin if needed
```

---

## Step-by-Step Resolution

### Standard Resolution Procedure

#### Phase 1: Assessment (5 minutes)

1. **Gather Information**
   ```bash
   # Capture current state
   python manage.py verify_tenant_migrations --json > /tmp/migration_state.json
   python manage.py health_check --full --json > /tmp/health_state.json

   # Check logs
   tail -200 /var/log/zumodra/migration_monitor.log > /tmp/migration_logs.txt

   # Record time
   echo "Incident start: $(date)" > /tmp/incident_log.txt
   ```

2. **Determine Severity**
   - Count affected tenants
   - Check user impact
   - Review error frequency
   - Assign P0-P3 priority

#### Phase 2: Containment (10 minutes)

1. **Prevent Further Issues**
   ```bash
   # Stop automated migrations temporarily
   sudo systemctl stop cron

   # Or disable specific jobs
   sudo mv /etc/cron.d/zumodra /etc/cron.d/zumodra.disabled
   ```

2. **Isolate Problem**
   - Identify specific app/tenant
   - Check for ongoing deployments
   - Review recent changes

#### Phase 3: Resolution (15-30 minutes)

1. **Apply Fix**
   ```bash
   # Backup first
   ./scripts/backup_database.sh

   # Apply fix
   ./scripts/fix_production_migrations.sh

   # Verify
   python manage.py verify_tenant_migrations --json
   ```

2. **Validate**
   ```bash
   # Test affected endpoints
   curl -I https://demo.zumodra.example.com/app/finance/subscription/

   # Run health check
   python manage.py health_check --full

   # Check tenant count
   python manage.py verify_tenant_migrations --json | \
     python -c "import sys, json; d=json.load(sys.stdin); \
     print(f\"OK: {d['tenants_ok']}, Issues: {d['tenants_with_issues']}\")"
   ```

#### Phase 4: Recovery (5 minutes)

1. **Re-enable Systems**
   ```bash
   # Re-enable cron
   sudo systemctl start cron

   # Or restore cron jobs
   sudo mv /etc/cron.d/zumodra.disabled /etc/cron.d/zumodra
   ```

2. **Monitor**
   ```bash
   # Watch for 15 minutes
   watch -n 60 'python manage.py health_check --full | grep -E "status|tenant"'

   # Check logs
   tail -f /var/log/zumodra/migration_monitor.log
   ```

---

## Verification

### Post-Fix Verification Checklist

- [ ] All tenant schemas have complete migrations
  ```bash
  python manage.py verify_tenant_migrations --json | \
    python -c "import sys, json; print(json.load(sys.stdin)['tenants_with_issues'] == 0)"
  ```

- [ ] Health check passes without warnings
  ```bash
  python manage.py health_check --full | grep -q "healthy"
  ```

- [ ] Finance pages load successfully
  ```bash
  curl -I https://demo.zumodra.example.com/app/finance/subscription/ | grep -q "200\|302"
  ```

- [ ] No migration errors in logs
  ```bash
  grep -i "migration.*error" /var/log/zumodra/*.log | wc -l  # Should be 0
  ```

- [ ] Automated monitoring working
  ```bash
  /app/scripts/monitor_tenant_migrations.sh
  # Check exit code
  echo $?  # Should be 0
  ```

- [ ] Database tables exist for all tenants
  ```bash
  # Test a sample tenant
  docker exec zumodra_postgres psql -U $DB_USER -d $DB_NAME -c "
  SET search_path TO tenant_demo;
  SELECT COUNT(*) FROM finance_usersubscription;" # Should not error
  ```

---

## Rollback Procedures

### When to Rollback

Rollback if:
- Fix attempts fail after 3 tries
- Data corruption suspected
- P0 incident exceeds 30 minutes
- Risk of further damage

### Rollback Steps

```bash
# 1. Use rollback script
./scripts/rollback_migrations.sh

# 2. Or manual rollback
# Restore from backup
./scripts/restore_database.sh /backups/zumodra_$(date +%Y%m%d).dump

# 3. Revert code changes
git log --oneline -10  # Find last good commit
git revert <commit-hash>
docker-compose -f docker-compose.prod.yml build --no-cache
docker-compose -f docker-compose.prod.yml up -d

# 4. Verify rollback
python manage.py verify_tenant_migrations --json
```

### Post-Rollback

1. Document what was rolled back
2. Identify root cause
3. Plan fix without rollback risk
4. Test in staging thoroughly
5. Schedule new deployment

---

## Post-Incident

### Incident Report Template

```markdown
## Incident Report: Tenant Migration Issue

**Date:** YYYY-MM-DD
**Duration:** XX minutes
**Severity:** P0/P1/P2/P3
**Affected Tenants:** X tenants

### Timeline
- HH:MM - Issue detected
- HH:MM - Investigation started
- HH:MM - Root cause identified
- HH:MM - Fix applied
- HH:MM - Verified resolved

### Root Cause
[Describe what caused the issue]

### Impact
- X tenants affected
- X users unable to access finance features
- X minutes of downtime

### Resolution
[Describe how it was fixed]

### Prevention
- [ ] Add monitoring for X
- [ ] Update deployment checklist
- [ ] Create alert for Y
- [ ] Document in runbook

### Follow-up Actions
1. [Action item 1] - Owner: [Name]
2. [Action item 2] - Owner: [Name]
```

### Continuous Improvement

After each incident:

1. **Update Runbook**
   - Add new scenarios encountered
   - Update resolution times
   - Improve diagnostic commands

2. **Enhance Monitoring**
   - Add alerts for edge cases
   - Improve detection time
   - Reduce false positives

3. **Team Training**
   - Share lessons learned
   - Update on-call procedures
   - Practice drills

4. **Automation**
   - Automate manual steps
   - Improve self-healing
   - Add safeguards

---

## Contact Information

### Escalation Path

1. **L1:** On-call Engineer (automated monitoring)
2. **L2:** DevOps Team Lead
3. **L3:** Database Administrator
4. **L4:** CTO

### External Resources

- **Monitoring:** Grafana dashboard at `/monitoring/migrations`
- **Logs:** `/var/log/zumodra/` or centralized logging
- **Runbooks:** `docs/runbooks/`
- **Code:** GitHub repository

### Support Channels

- **Slack:** #incidents, #devops
- **PagerDuty:** Migration alerts
- **Documentation:** Internal wiki

---

## Appendix

### Useful Commands Reference

```bash
# Check migration status
python manage.py verify_tenant_migrations [--tenant=X] [--app=X] [--json] [--fix]

# Health check
python manage.py health_check [--full] [--json] [--quiet]

# Apply migrations
python manage.py migrate_schemas [--shared|--tenant] [--schema=X] [--noinput]

# Show migrations
python manage.py showmigrations [--plan] [app_label]

# Database shell
python manage.py dbshell

# Tenant shell
python manage.py tenant_command shell --schema=tenant_name
```

### Log Locations

- Migration monitoring: `/var/log/zumodra/migration_monitor.log`
- Health checks: `/var/log/zumodra/health_check.log`
- Application logs: `/var/log/zumodra/app.log`
- Database logs: `/var/log/postgresql/`

### Related Documentation

- [Migration Fix Summary](../../MIGRATION_FIX_SUMMARY.md)
- [Scripts README](../../scripts/README.md)
- [Quick Start Guide](../../QUICK_START.md)

---

**Document Version Control:**
- v1.0 - 2026-01-15 - Initial creation
- Update this runbook as new scenarios are encountered
