# Production Clean Rebuild Instructions

## Why Clean Rebuild is Required

The HR models have been migrated from `models.Model` to `TenantAwareModel`, which changes:
- Primary key: `int` → `UUID`
- Adds: `created_at`, `updated_at`, `is_active` fields
- Adds: `tenant` ForeignKey (was manual, now from BaseModel)

This is a **breaking schema change** that cannot be migrated in-place.

---

## ✅ What's Fixed in This Rebuild

All production errors have been resolved:
1. ✅ User import errors (get_user_model)
2. ✅ URL namespace errors
3. ✅ Tenant_id constraint violations
4. ✅ Username unique constraints
5. ✅ Field name errors (rule_match_score, created_at, is_internal)
6. ✅ Celery task errors
7. ✅ **HR models now use TenantAwareModel (consistent architecture)**
8. ✅ Correct import path (core.db.models.TenantAwareModel)

---

## 🚀 Clean Rebuild Steps

### Step 1: SSH into Production Server
```bash
ssh root@147.93.47.35
cd /root/zumodra
```

### Step 2: Stop and Remove Everything
```bash
# Stop all containers
docker compose down

# Remove all containers, networks, volumes
docker compose down -v --remove-orphans

# Remove all images (optional but recommended for clean slate)
docker image prune -a -f

# Verify nothing is running
docker ps -a
docker volume ls
```

### Step 3: Pull Latest Code
```bash
git pull origin main

# Verify you're on the latest commit
git log -1 --oneline
# Should show: a351fe9 refactor: use TenantAwareModel for HR models
```

### Step 4: Rebuild and Start
```bash
# Build fresh images
docker compose build --no-cache

# Start services
docker compose up -d

# Watch logs for deployment
docker compose logs -f web
```

### Step 5: Verify Deployment

Watch for these success indicators in logs:

1. **Migrations Created:**
   ```
   [INFO] Step 0/3: Creating migration files (makemigrations)...
   Migrations for 'hr_core':
     hr_core/migrations/0XXX_auto_YYYYMMDD_HHMM.py
       - Alter field id on employee
       - Add field tenant on employee
       - Add field created_at on employee
       - Add field updated_at on employee
       - Add field is_active on employee
       (similar for TimeOffType, TimeOffRequest)
   ```

2. **Migrations Applied:**
   ```
   [INFO] Step 1/3: Migrating shared schema (public)...
   [INFO] Shared schema migrations completed successfully!
   [INFO] Step 2/3: Migrating tenant schemas...
   [INFO] Tenant schema migrations completed successfully!
   ```

3. **Demo Tenant Bootstrap:**
   ```
   [1] Setting up subscription plans...
   Done! Created 0, updated 4 plans.
   [2] Creating demo tenant...
   [3] Creating demo users...
   [4] Refreshing ATS data...
   [5] Refreshing HR data...
   [6] Refreshing Services data...
   [7] Creating verification data...
   Done!
   ```

4. **Gunicorn Started:**
   ```
   [INFO] Starting application: gunicorn
   [INFO] Starting gunicorn 23.0.0
   [INFO] Listening at: http://0.0.0.0:8000
   ```

### Step 6: Test the Application

```bash
# Check if web is responding
curl http://localhost:8000/health/

# Expected response:
# {"status": "healthy"}
```

Access via browser:
- Main site: http://147.93.47.35 (or your domain)
- Demo tenant: http://demo.147.93.47.35 (or demo.yourdomain.com)

Test login with demo credentials (from bootstrap output):
- Email: `admin@demo.localhost`
- Password: `Admin@2024!`

---

## 🔍 Troubleshooting

### If Migration Fails

Check logs:
```bash
docker compose logs web | grep -i error
```

Common issues:
- **GDAL not found**: Ignore on local, fine in production Docker
- **Database connection**: Check `DB_HOST`, `DB_NAME` in .env
- **Redis connection**: Check `REDIS_URL` in .env

### If Bootstrap Fails

The entrypoint treats bootstrap failures as non-fatal warnings. If it fails:

```bash
# Manually run bootstrap
docker compose exec web python manage.py bootstrap_demo_tenant

# If that fails, check the specific error
```

### View All Logs

```bash
# All services
docker compose logs -f

# Just web service
docker compose logs -f web

# Just database
docker compose logs -f db

# Last 100 lines
docker compose logs --tail=100 web
```

---

## 📊 Database Schema Verification

After successful deployment, verify the schema:

```bash
docker compose exec db psql -U postgres -d zumodra -c "\d hr_core_employee"
```

Expected columns:
- `id` - uuid (not integer!)
- `tenant_id` - uuid (FK to tenants_tenant)
- `created_at` - timestamp
- `updated_at` - timestamp
- `is_active` - boolean
- `user_id` - bigint (FK to users)
- `employee_id` - varchar(50)
- ... (other employee fields)

Compare with ATS model to ensure consistency:
```bash
docker compose exec db psql -U postgres -d zumodra -c "\d ats_jobposting"
```

Both should have same base structure (UUID id, tenant, timestamps).

---

## ✅ Success Criteria

Deployment is successful when:
1. ✅ All migrations applied without errors
2. ✅ Demo tenant created successfully
3. ✅ Gunicorn started and listening on port 8000
4. ✅ Health check returns `{"status": "healthy"}`
5. ✅ Can login to demo tenant
6. ✅ HR models have UUID primary keys
7. ✅ No errors in logs (warnings are okay)

---

## 🎯 What's New in Database

### Before (OLD - Integer IDs):
```sql
hr_core_employee
  - id: integer primary key
  - user_id: bigint FK
  - employee_id: varchar(50)
  - (no tenant field)
  - (no timestamps)
```

### After (NEW - TenantAwareModel):
```sql
hr_core_employee
  - id: uuid primary key          ← Changed from int
  - tenant_id: uuid FK             ← Added
  - created_at: timestamp          ← Added
  - updated_at: timestamp          ← Added
  - is_active: boolean             ← Added
  - user_id: bigint FK
  - employee_id: varchar(50)
```

**Now consistent with:**
- `ats_jobposting`
- `ats_candidate`
- `services_serviceprovider`
- All other tenant-aware models

---

## 🔐 Security Improvements

1. **UUID Primary Keys:**
   - Old: `/employees/1/` (enumerable)
   - New: `/employees/550e8400-e29b-41d4-a716-446655440000/` (not guessable)

2. **Automatic Tenant Filtering:**
   - Old: Manual `Employee.objects.filter(tenant=tenant)`
   - New: `Employee.objects.all()` auto-filters by current tenant

3. **Audit Trail:**
   - Track when employee records are created/modified
   - `is_active` flag for soft deletion

---

## 📝 Notes

- This is the **final architecture** - no more HR model changes needed
- All models now follow the same pattern
- Future models should inherit from `TenantAwareModel`
- See `SAAS_MULTI_TENANCY_LOGIC.md` for architecture details

---

**Last Updated:** 2026-01-10
**Commit:** a351fe9
**Status:** ✅ Ready for clean rebuild
