# Tenant Migration Management - Complete Guide

**Version:** 1.0
**Last Updated:** 2026-01-15

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Management Commands](#management-commands)
4. [Automated Scripts](#automated-scripts)
5. [Monitoring & Observability](#monitoring--observability)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)
8. [FAQ](#faq)

---

## Overview

### What is Tenant Migration Management?

Zumodra uses django-tenants for multi-tenant architecture with schema-per-tenant isolation. Each tenant (customer/organization) has their own PostgreSQL schema with isolated data.

**Key Concepts:**
- **Public Schema:** Contains shared data (SHARED_APPS)
- **Tenant Schemas:** Individual customer schemas (TENANT_APPS)
- **Finance App:** Part of TENANT_APPS, must be migrated to each tenant

### Problem This Solves

**Before:** Manual migration management led to:
- Missing tables in tenant schemas
- 500 errors for users
- Manual SQL commands needed
- No visibility into migration status

**After:** Automated system provides:
- ✅ Self-healing migration system
- ✅ Proactive monitoring and alerts
- ✅ Graceful degradation when tables missing
- ✅ Complete observability
- ✅ Automated recovery

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Zumodra Platform                          │
├─────────────────────────────────────────────────────────────┤
│  Public Schema (SHARED_APPS)                                 │
│  ├─ django_tenants                                           │
│  ├─ custom_account_u                                         │
│  └─ integrations                                             │
├─────────────────────────────────────────────────────────────┤
│  Tenant Schemas (TENANT_APPS) - Per Customer                 │
│  ├─ accounts                                                 │
│  ├─ ats                                                      │
│  ├─ hr_core                                                  │
│  ├─ finance ← Focus of this system                          │
│  └─ ... (other apps)                                        │
└─────────────────────────────────────────────────────────────┘

         ↓                    ↓                    ↓

┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Monitoring  │    │ Verification │    │ Self-Healing │
│  (cron)      │───▶│  Commands    │───▶│  Scripts     │
└──────────────┘    └──────────────┘    └──────────────┘
       │                     │                     │
       └─────────────────────┴─────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   Observability │
                    │   & Metrics     │
                    └─────────────────┘
```

### Migration Flow

1. **Deployment:**
   - Code deployed
   - Docker entrypoint runs
   - Migrations applied (shared + tenant)
   - Verification step ensures completeness

2. **Continuous Monitoring (every 15 min):**
   - Check for pending migrations
   - Auto-fix if detected
   - Alert if auto-fix fails

3. **Health Checks (every 5 min):**
   - Comprehensive system health
   - Include tenant migration status
   - Alert on degraded state

4. **Weekly Reports:**
   - Summary of migration health
   - Trends and patterns
   - Action items

---

## Management Commands

### verify_tenant_migrations

**Purpose:** Check and optionally fix tenant migration status

**Syntax:**
```bash
python manage.py verify_tenant_migrations [OPTIONS]
```

**Options:**
- `--json` - Output in JSON format
- `--fix` - Automatically apply missing migrations
- `--tenant=<name>` - Check specific tenant only
- `--app=<name>` - Check specific app only
- `--quiet` - Only output errors/warnings

**Examples:**
```bash
# Check all tenants
python manage.py verify_tenant_migrations

# Check and auto-fix
python manage.py verify_tenant_migrations --fix

# Check specific app
python manage.py verify_tenant_migrations --app=finance

# JSON output for automation
python manage.py verify_tenant_migrations --json | jq .
```

**Output:**
```json
{
  "total_tenants": 5,
  "tenants_ok": 5,
  "tenants_with_issues": 0,
  "tenants": [
    {
      "schema_name": "tenant_demo",
      "domain": "demo.zumodra.com",
      "pending_count": 0,
      "pending_migrations": []
    }
  ]
}
```

---

### health_check

**Purpose:** Comprehensive system health check including migrations

**Syntax:**
```bash
python manage.py health_check [OPTIONS]
```

**Options:**
- `--full` - Include all checks (database, cache, tenant migrations, etc.)
- `--json` - JSON output
- `--quiet` - Only show failures

**Examples:**
```bash
# Full health check
python manage.py health_check --full

# JSON format
python manage.py health_check --full --json

# Check specific components
python manage.py health_check --full --json | jq '.checks.tenant_migrations'
```

---

### migration_metrics

**Purpose:** Collect migration metrics for observability

**Syntax:**
```bash
python manage.py migration_metrics [OPTIONS]
```

**Options:**
- `--json` - JSON format
- `--prometheus` - Prometheus format
- `--export=<file>` - Export to file
- `--window=<hours>` - Time window for historical metrics

**Examples:**
```bash
# Display metrics
python manage.py migration_metrics

# Prometheus format
python manage.py migration_metrics --prometheus

# Export to file
python manage.py migration_metrics --json --export=/tmp/metrics.json
```

---

## Automated Scripts

### fix_production_migrations.sh

**Purpose:** Immediate fix for production migration issues

**When to use:** On-demand when issues detected

```bash
./scripts/fix_production_migrations.sh
```

**What it does:**
1. Checks current migration state
2. Applies missing migrations
3. Verifies migrations applied
4. Runs health check

---

### monitor_tenant_migrations.sh

**Purpose:** Continuous monitoring with self-healing

**When to run:** Every 15 minutes via cron

```bash
# Manual run
./scripts/monitor_tenant_migrations.sh

# Via cron
*/15 * * * * /app/scripts/monitor_tenant_migrations.sh
```

**What it does:**
1. Checks for pending migrations
2. Attempts automatic fix
3. Logs all activity
4. Sends alerts (if configured)

---

### health_check_cron.sh

**Purpose:** Continuous health monitoring

**When to run:** Every 5 minutes via cron

```bash
# Manual run
./scripts/health_check_cron.sh

# Via cron
*/5 * * * * /app/scripts/health_check_cron.sh
```

---

### weekly_migration_report.sh

**Purpose:** Weekly summary report

**When to run:** Weekly (Mondays at 9 AM)

```bash
# Manual run
./scripts/weekly_migration_report.sh

# Via cron
0 9 * * 1 /app/scripts/weekly_migration_report.sh
```

---

### backup_database.sh

**Purpose:** Create database backup before migrations

```bash
./scripts/backup_database.sh
```

**Environment variables:**
- `BACKUP_DIR` - Backup directory (default: /backups/zumodra)
- `RETENTION_DAYS` - Days to keep backups (default: 30)

---

### rollback_migrations.sh

**Purpose:** Rollback to previous database state

```bash
./scripts/rollback_migrations.sh <backup_file> [OPTIONS]
```

**Options:**
- `--force` - Skip confirmation
- `--app=<name>` - Rollback specific app
- `--tenant=<schema>` - Rollback specific tenant

---

## Monitoring & Observability

### Metrics Available

1. **Tenant Metrics:**
   - Total tenants
   - Healthy tenants
   - Tenants with pending migrations
   - Tenants with errors

2. **Performance Metrics:**
   - Average check duration
   - Max check duration
   - Verification command availability

3. **Health Metrics:**
   - Overall health status
   - Migration system health
   - Issues detected

### Dashboards

**Grafana Integration:**
```bash
# Export metrics in Prometheus format
python manage.py migration_metrics --prometheus > /var/lib/prometheus/zumodra_migrations.prom
```

**Sample Grafana Queries:**
```promql
# Tenants with pending migrations
zumodra_tenants_with_pending

# Total pending migrations
zumodra_total_pending_migrations

# System health (0=unhealthy, 1=healthy)
zumodra_migration_health
```

### Alerts

**Recommended Alert Rules:**

1. **Critical:** Tenants with pending migrations > 0 for > 30 minutes
2. **Warning:** Auto-fix failures > 3 in 1 hour
3. **Info:** Weekly report shows increasing trend

---

## Troubleshooting

See the comprehensive [Troubleshooting Runbook](runbooks/tenant-migration-troubleshooting.md) for:

- Common issues and resolutions
- Emergency procedures
- Step-by-step diagnostic guides
- Escalation paths

**Quick Diagnosis:**
```bash
# 1. Check status
python manage.py verify_tenant_migrations --json

# 2. Check health
python manage.py health_check --full

# 3. Check logs
tail -100 /var/log/zumodra/migration_monitor.log

# 4. Run immediate fix
./scripts/fix_production_migrations.sh
```

---

## Best Practices

### Development

1. **Always test migrations locally first**
   ```bash
   python manage.py makemigrations
   python manage.py migrate_schemas --shared
   python manage.py migrate_schemas --tenant
   python manage.py verify_tenant_migrations
   ```

2. **Run tests before deploying**
   ```bash
   pytest tests/test_tenant_migrations.py
   ./scripts/ci_test_migrations.sh
   ```

3. **Use verification in local development**
   ```bash
   # Add to your workflow
   python manage.py verify_tenant_migrations --fix
   ```

### Staging

1. **Mirror production monitoring**
2. **Test auto-fix functionality**
3. **Verify backups work**
4. **Practice rollback procedures**

### Production

1. **Never skip migrations in deployment**
2. **Always backup before major changes**
3. **Monitor continuously**
4. **Review weekly reports**
5. **Keep runbooks updated**

### Code Changes

1. **Add migrations for new models immediately**
2. **Test backward compatibility**
3. **Use defensive error handling** (see finance/template_views.py)
4. **Log errors for debugging**

---

## FAQ

### Q: What happens if migrations fail during deployment?

A: The entrypoint.sh script will:
1. Log the error
2. Continue startup (with warnings)
3. Automated monitoring will detect and attempt fix
4. Alerts sent if auto-fix fails

### Q: Can I run migrations for a single tenant?

A: Yes:
```bash
python manage.py migrate_schemas --schema=tenant_name
python manage.py verify_tenant_migrations --tenant=tenant_name
```

### Q: How do I add a new tenant?

A: Use bootstrap command:
```bash
python manage.py bootstrap_demo_tenant
# OR
python manage.py setup_beta_tenant "Company" "email@example.com"
```

Migrations are applied automatically.

### Q: What if auto-fix keeps failing?

A: Follow escalation in [Troubleshooting Runbook](runbooks/tenant-migration-troubleshooting.md):
1. Check logs for specific error
2. Verify database connectivity
3. Check permissions
4. Manual intervention may be needed
5. Contact database admin if persistent

### Q: How do I disable automated monitoring temporarily?

A:
```bash
# Disable cron
sudo systemctl stop cron

# OR remove cron file
sudo mv /etc/cron.d/zumodra /etc/cron.d/zumodra.disabled
```

Remember to re-enable:
```bash
sudo systemctl start cron
# OR
sudo mv /etc/cron.d/zumodra.disabled /etc/cron.d/zumodra
```

### Q: Can I customize alert notifications?

A: Yes, edit the monitoring scripts:
- `scripts/monitor_tenant_migrations.sh`
- `scripts/health_check_cron.sh`

Uncomment and configure Slack/Email/PagerDuty sections.

### Q: How much disk space do backups need?

A: Estimate:
- Database size: Check with `du -h /var/lib/postgresql/data`
- Backup ~= Database size (compressed: ~30-50% smaller)
- Keep 30 days: `Database size * 30 * 0.5`

---

## Related Documentation

- [Migration Fix Summary](../MIGRATION_FIX_SUMMARY.md) - Implementation overview
- [Quick Start Guide](../QUICK_START.md) - Get started quickly
- [Scripts README](../scripts/README.md) - Detailed script documentation
- [Troubleshooting Runbook](runbooks/tenant-migration-troubleshooting.md) - Operational procedures

---

## Version History

- **v1.0** (2026-01-15) - Initial release
  - Verification command
  - Automated monitoring
  - Self-healing system
  - Comprehensive documentation

---

## Support

**Questions?**
- Check [FAQ](#faq)
- Review [Troubleshooting Runbook](runbooks/tenant-migration-troubleshooting.md)
- Contact DevOps team

**Found a bug?**
- Create issue in repository
- Include logs and error messages
- Describe steps to reproduce
