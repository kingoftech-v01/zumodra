# Quick Start Guide - Fix Production Finance Migrations

## Immediate Fix (Run Now)

### Step 1: Apply Missing Migrations (10-15 minutes)

```bash
# Make the script executable
chmod +x scripts/fix_production_migrations.sh

# Run the automated fix
./scripts/fix_production_migrations.sh
```

This will:
1. Check current migration state
2. Apply missing migrations to all tenant schemas
3. Verify migrations were applied
4. Run health check

### Step 2: Verify Fix

```bash
# Test the finance subscription page
curl -I https://demo.zumodra.rhematek-solutions.com/fr/app/finance/subscription/
# Should return 200 or 302, not 500

# Run health check
docker exec zumodra_web python manage.py health_check --full
```

---

## Set Up Automated Monitoring (5-10 minutes)

### Step 1: Create Log Directory

```bash
sudo mkdir -p /var/log/zumodra
sudo chown -R $USER:$USER /var/log/zumodra
```

### Step 2: Install Cron Jobs

```bash
# Copy cron configuration
sudo cp scripts/zumodra.cron /etc/cron.d/zumodra

# Restart cron
sudo systemctl restart cron

# Verify it's installed
sudo cat /etc/cron.d/zumodra
```

This sets up:
- ✅ Migration monitoring every 15 minutes (auto-fixes issues)
- ✅ Health checks every 5 minutes (alerts on problems)
- ✅ Daily failsafe migration check at 2 AM

---

## Optional: Configure Notifications

Edit the monitoring scripts to enable alerts:

```bash
# Edit monitoring script
nano scripts/monitor_tenant_migrations.sh

# Find and uncomment Slack webhook lines:
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
# Uncomment the curl commands
```

Same for `scripts/health_check_cron.sh`.

---

## Test Everything

```bash
# Test verification command
python manage.py verify_tenant_migrations --json

# Test monitoring script
./scripts/monitor_tenant_migrations.sh

# Check logs
tail -f /var/log/zumodra/migration_monitor.log
```

---

## What Was Implemented

1. **Immediate Fix Script** - Applies missing migrations automatically
2. **Defensive Error Handling** - Finance views show friendly errors instead of 500
3. **Verification Command** - `verify_tenant_migrations` management command
4. **Enhanced Health Checks** - Detects migration issues early
5. **Automated Monitoring** - Self-healing with cron jobs

---

## Files Created

✅ `core/management/commands/verify_tenant_migrations.py` - Verification command
✅ `finance/templates/finance/subscription/index.html` - Error-safe template
✅ `scripts/fix_production_migrations.sh` - Immediate fix
✅ `scripts/monitor_tenant_migrations.sh` - Automated monitoring
✅ `scripts/health_check_cron.sh` - Health monitoring
✅ `scripts/deploy.sh` - Deployment automation
✅ `scripts/test_migration_resilience.sh` - Testing
✅ `scripts/README.md` - Detailed documentation
✅ `scripts/zumodra.cron` - Cron configuration

## Files Modified

✅ `finance/template_views.py` - Added error handling
✅ `core/management/commands/health_check.py` - Added tenant migration check
✅ `docker/entrypoint.sh` - Added verification step

---

## Need Help?

- **Full documentation:** See `scripts/README.md`
- **Implementation details:** See `MIGRATION_FIX_SUMMARY.md`
- **Detailed plan:** See `C:\Users\techn\.claude\plans\modular-baking-penguin.md`

---

## Success Checklist

After running the fix script:

- [ ] Finance subscription page loads without 500 errors
- [ ] `python manage.py verify_tenant_migrations` shows 0 issues
- [ ] Health check passes: `python manage.py health_check --full`
- [ ] Cron jobs installed: `sudo cat /etc/cron.d/zumodra`
- [ ] Logs being created: `ls -lh /var/log/zumodra/`

---

**Ready to fix production?**
```bash
./scripts/fix_production_migrations.sh
```
