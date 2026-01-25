# Migration Fix - Quick Reference

> **Issue:** `ProgrammingError: relation "finance_invoice" does not exist`
> **Root Cause:** Bootstrap commands didn't explicitly run migrations
> **Fix:** Explicit `migrate_schemas` calls + blocking verification

## 🚀 Quick Deploy (Production)

```bash
# 1. Pull changes
git pull origin main

# 2. Fix demo tenant (REQUIRED before restart)
docker exec -it zumodra-web-1 bash scripts/fix_demo_tenant_migrations.sh

# 3. Restart containers
docker compose restart web

# 4. Verify
curl -I https://demo.zumodra.rhematek-solutions.com/fr/app/finance/invoices/
# Should return HTTP/2 200
```

## 📝 Files Changed

| File | What Changed |
|------|--------------|
| `tenants/services.py` | Added explicit migration call to `create_tenant()` |
| `tenants/management/commands/bootstrap_demo_tenant.py` | Added explicit migration call after tenant creation |
| `tenants/management/commands/bootstrap_demo_tenants.py` | Added explicit migration call after tenant creation |
| `docker/entrypoint.sh` | Added Steps 4.5 & 4.6 - blocking migration verification |

## 🔧 Essential Commands

### Fix Current Demo Tenant
```bash
# Automated (recommended)
docker exec -it zumodra-web-1 bash scripts/fix_demo_tenant_migrations.sh

# Manual
docker exec -it zumodra-web-1 python manage.py verify_tenant_migrations --tenant=demo --fix
```

### Verify All Fixes Working
```bash
docker exec -it zumodra-web-1 bash scripts/verify_migration_fixes.sh
# Should pass all 10 tests
```

### Check Migration Status
```bash
# All tenants
docker exec -it zumodra-web-1 python manage.py verify_tenant_migrations

# Demo tenant only
docker exec -it zumodra-web-1 python manage.py verify_tenant_migrations --tenant=demo

# JSON output
docker exec -it zumodra-web-1 python manage.py verify_tenant_migrations --json
```

### Test Invoice Page
```bash
# Should return 200, not 500
curl -I https://demo.zumodra.rhematek-solutions.com/fr/app/finance/invoices/
```

### Watch Container Logs
```bash
# See new verification steps
docker compose logs -f web | grep -E "(Step 4\.[56]|BLOCKING|✓)"

# Monitor for errors
docker compose logs -f web | grep -E "(finance_invoice|FATAL|ERROR)"
```

## 🎯 What to Expect

### ✅ Success Indicators

**Container Startup:**
```
ℹ Step 4.5/6: Verifying demo tenant migrations (BLOCKING CHECK)...
✓ Demo tenant migrations verified and applied successfully!
ℹ Step 4.6/6: Verifying all tenant migrations (BLOCKING CHECK)...
✓ All tenant migrations verified and applied successfully!
```

**Invoice Page:**
```bash
$ curl -I https://demo.zumodra.rhematek-solutions.com/fr/app/finance/invoices/
HTTP/2 200
content-type: text/html; charset=utf-8
```

**Verification Tests:**
```
Total Tests:  10
Passed:       10
Failed:       0
✓ ALL TESTS PASSED!
```

### ❌ Failure Indicators (and how to fix)

**Container won't start:**
```
╔════════════════════════════════════════════════════════════════╗
║  FATAL: Demo tenant migration verification FAILED             ║
╚════════════════════════════════════════════════════════════════╝
```
**Fix:** Run `docker exec -it zumodra-web-1 bash scripts/fix_demo_tenant_migrations.sh`

**Invoice page 500 error:**
```
HTTP/2 500
```
**Fix:** Migrations not applied. Run: `python manage.py verify_tenant_migrations --tenant=demo --fix`

## 🔄 Bootstrap New Demo Tenant

```bash
# Will now include automatic migrations
docker exec -it zumodra-web-1 python manage.py bootstrap_demo_tenant --reset

# Should see:
# "Running migrations for tenant schema: demo..."
# "✓ Migrations completed for tenant: demo"
```

## 🛡️ Protection Mechanisms

1. **Explicit Migrations:** All tenant creation now calls `migrate_schemas` explicitly
2. **Automatic Rollback:** Failed migrations delete the broken tenant automatically
3. **Blocking Startup:** Container exits with code 1 if migrations missing
4. **Clear Errors:** Error boxes with specific action steps
5. **Verification:** Built-in `verify_tenant_migrations` command

## 📊 Coverage

| Tenant Creation Method | Before | After |
|------------------------|--------|-------|
| API/Web UI (`TenantService.create_tenant`) | ❌ Auto-create | ✅ Explicit |
| CLI (`create_tenant` command) | ❌ Auto-create | ✅ Explicit |
| Demo bootstrap (`bootstrap_demo_tenant`) | ❌ Auto-create | ✅ Explicit |
| Bulk bootstrap (`bootstrap_demo_tenants`) | ❌ Auto-create | ✅ Explicit |
| Container startup verification | ❌ None | ✅ Blocking |

## 🚨 Emergency Procedures

### Container won't start and you need it running NOW

```bash
# 1. Override entrypoint to skip checks
docker compose run --rm --entrypoint bash web

# 2. Inside container, fix migrations
python manage.py migrate_schemas --tenant --noinput

# 3. Exit and restart normally
exit
docker compose restart web
```

### Rollback entire change

```bash
git revert <commit-hash>
git push origin main
cd /path/to/zumodra
git pull origin main
docker compose restart web
```

## 🎓 New Behavior

### Old (Before Fix)
```python
tenant.save()  # Relies on auto_create_schema
# ⚠️ Sometimes migrations don't run
# ⚠️ No error detection
# ⚠️ Production breaks silently
```

### New (After Fix)
```python
tenant.save()
with schema_context(tenant.schema_name):
    call_command('migrate_schemas', ...)  # Explicit!
# ✅ Always runs migrations
# ✅ Errors are caught and tenant deleted
# ✅ Container blocks if migrations fail
```

## 📞 Troubleshooting

| Problem | Solution |
|---------|----------|
| `finance_invoice does not exist` | Run fix script: `bash scripts/fix_demo_tenant_migrations.sh` |
| Container won't start | Check logs, run migrations manually, restart |
| Verification tests fail | Review specific test output, fix issues, re-run |
| Invoice page 500 | Verify migrations: `python manage.py verify_tenant_migrations --tenant=demo` |
| Slow startup | Normal - verification adds 2-5 seconds |

## 💡 Key Points

- **All errors are blocking** - no silent failures
- **Automatic cleanup** - failed tenants are deleted
- **Safe operations** - migrations never delete data
- **Comprehensive** - covers all tenant creation paths
- **Tested** - 10 verification tests included

## 📚 Full Documentation

- **Detailed deployment:** `DEPLOYMENT_MIGRATION_FIX.md`
- **Fix script:** `scripts/fix_demo_tenant_migrations.sh`
- **Verification:** `scripts/verify_migration_fixes.sh`
- **Plan document:** `.claude/plans/rippling-swimming-prism.md`

---

**TL;DR:** Run `bash scripts/fix_demo_tenant_migrations.sh`, restart containers, done! 🎉
