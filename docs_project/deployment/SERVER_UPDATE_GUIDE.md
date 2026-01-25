# Server Update Guide - Tenant Type System

## Critical: Server Must Pull Latest Changes

The error you're seeing indicates the server is running **old code** that doesn't have the latest fixes.

### Error Symptoms
```
NameError: name 'api_view' is not defined
File "/app/tenants/views.py", line 1323
```

This was **fixed in commit `26c9bb8`** but the server hasn't pulled the changes yet.

---

## Required Server Actions

### Option 1: Docker Deployment (Recommended)

```bash
# SSH into your server
ssh user@your-server.com

# Navigate to project directory
cd /path/to/zumodra

# Pull latest changes from GitHub
git pull origin main

# Rebuild and restart containers
docker-compose down
docker-compose build --no-cache web
docker-compose up -d

# Run migrations (if not auto-run by entrypoint)
docker-compose exec web python manage.py migrate_schemas --shared
docker-compose exec web python manage.py migrate_schemas --tenant

# Verify server is running
docker-compose logs -f web
```

### Option 2: Manual Deployment

```bash
# Pull latest code
git pull origin main

# Activate virtual environment
source venv/bin/activate

# Install any new dependencies (if any)
pip install -r requirements.txt

# Run migrations
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant

# Collect static files
python manage.py collectstatic --noinput

# Restart application server
sudo systemctl restart gunicorn
sudo systemctl restart daphne  # For WebSocket channels

# Restart Celery workers
sudo systemctl restart celery-worker
sudo systemctl restart celery-beat
```

---

## Verification After Update

### 1. Check Server Logs
```bash
# Docker
docker-compose logs -f web

# Manual
tail -f /var/log/gunicorn/error.log
```

**Expected:** No `NameError: name 'api_view' is not defined` errors

### 2. Test Verification Endpoints

```bash
# Test KYC endpoint
curl -X POST http://your-domain.com/api/verify/kyc/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: multipart/form-data" \
  -F "document_type=passport" \
  -F "document_file=@test.pdf" \
  -F "document_number=AB123456"

# Test CV endpoint
curl -X POST http://your-domain.com/api/verify/cv/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "cv_file=@resume.pdf"

# Test verification status
curl -X GET http://your-domain.com/api/verify/status/ \
  -H "Authorization: Bearer YOUR_TOKEN"

# Test EIN endpoint
curl -X POST http://your-domain.com/api/verify/ein/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ein_number": "12-3456789"}'
```

**Expected:** All return `200 OK` or `201 Created` (not 500 errors)

### 3. Test URL Accessibility

Visit these URLs in your browser (after logging in):

**Settings & Tenant Management:**
- `/settings/` - Should show tenant type switcher
- `/api/v1/tenants/` - Tenant API endpoint
- `/api/verify/status/` - Verification status

**ATS Templates (COMPANY-only):**
- `/jobs/jobs/` - Job list (shows warning for freelancers)
- `/jobs/jobs/create/` - Job creation (blocked for freelancers)

**HR Templates (COMPANY-only):**
- `/hr/employees/` - Employee list (shows warning for freelancers)
- `/hr/timeoff/` - Time off management (blocked for freelancers)

**Services Templates (All tenants):**
- `/services/` - Service marketplace
- `/services/create-request/` - Should show hiring context selector

---

## Latest Changes Summary

### Commit `26c9bb8` - Import Fixes & Components
**Files Changed:**
- `tenants/views.py` - Added `api_view, permission_classes` imports (line 28)
- `accounts/views.py` - Added `api_view, permission_classes` imports (line 15)
- `templates/components/company_only_wrapper_start.html` - NEW
- `templates/components/company_only_wrapper_end.html` - NEW
- `templates/components/company_only_check.html` - NEW
- `docs/components.md` - Updated with wrapper docs

### Commit `7a175df` - Template Updates
**Files Changed:**
- 50 templates updated with tenant type awareness
- All ATS, HR, Analytics, Careers templates have defensive checks
- Services templates have hiring context selectors
- Settings templates have tenant type switcher

### Commit `ba38a3b` - Core Implementation
**Files Changed:**
- 65 views protected with `@require_tenant_type` decorators
- 8 UI components created
- 14+ serializers enhanced
- 6 verification API endpoints created
- 4 documentation files created
- All migration files deleted (will be regenerated on server)

---

## Troubleshooting

### Error: "api_view is not defined"
**Cause:** Server running old code before commit `26c9bb8`
**Fix:** `git pull origin main && docker-compose restart web`

### Error: "No module named 'tenants.decorators'"
**Cause:** Missing `tenants/decorators.py` file
**Fix:** `git pull origin main` (file was added in commit `ba38a3b`)

### Error: Migration conflicts
**Cause:** Migration files were deleted
**Fix:**
```bash
# Delete all .pyc files
find . -name "*.pyc" -delete
find . -name "__pycache__" -delete

# Regenerate migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant
```

### Error: Template not found
**Cause:** Missing new component templates
**Fix:** `git pull origin main && python manage.py collectstatic --noinput`

---

## Post-Deployment Checklist

- [ ] Server pulled latest code (`git pull origin main`)
- [ ] Docker containers rebuilt (if using Docker)
- [ ] Migrations run successfully
- [ ] Static files collected
- [ ] Application server restarted
- [ ] No errors in server logs
- [ ] Verification endpoints return 200/201 (not 500)
- [ ] ATS pages show warning for freelancer tenants
- [ ] HR pages show warning for freelancer tenants
- [ ] Services pages show hiring context selector
- [ ] Tenant settings page shows type switcher

---

## Current Git Status

**Latest Commit:** `26c9bb8`
**Branch:** `main`

**All fixes are in the main branch and ready to deploy.**

Run `git log --oneline -5` on server to verify:
```
26c9bb8 fix: add missing api_view imports and create reusable company-only components
7a175df feat: add tenant type awareness to 50 templates
ba38a3b feat: complete tenant type system implementation with verification
ddd5c9a fix: replace uuid with id in hr_core admin after TenantAwareModel migration
dd72348 fix: add services namespace to public URLs for template compatibility
```

If you don't see `26c9bb8` as the latest commit, run `git pull origin main`.

---

## Troubleshooting Migration Issues

### Server Log Analysis

If the server starts successfully but migrations haven't been applied, follow these diagnostic steps.

#### Symptoms
- Application starts but database tables are missing
- Migration steps don't appear in startup logs
- Database errors about missing tables or columns

#### Required Logs

Check the **FULL startup logs** from the beginning of the container restart:

```bash
docker compose logs web | head -100
```

Look for these steps:
- Step 0/4: Checking for missing initial migrations...
- Step 1/4: Migrating shared schema (public)...
- Step 2/4: Migrating tenant schemas...
- Step 3/4: Creating demo tenants...
- Step 4/4: Verifying critical imports...

#### Expected vs Actual Behavior

**Expected**: Entrypoint runs migration steps BEFORE starting the application
**Actual**: If migrations are skipped, application starts immediately without migration steps

#### Possible Causes

1. **Server hasn't pulled the latest code**
   - Solution: Run `git pull origin main` and rebuild containers

2. **Container restart didn't trigger full entrypoint execution**
   - Solution: Use `docker compose down` then `docker compose up -d --build`

3. **Migrations ran but failed silently**
   - Solution: Check logs for error messages during migration steps

#### Diagnostic Commands

Run these on your server to diagnose the issue:

```bash
# Check if latest code is pulled
cd /app && git log --oneline -1
# Should show the latest commit (e.g., 9cc13a9 or newer)

# Check if migration files exist
ls -la tenants/migrations/
ls -la accounts/migrations/
ls -la custom_account_u/migrations/

# Check database migration status
docker compose exec web python manage.py showmigrations

# Restart with full rebuild to trigger entrypoint
docker compose down
docker compose up -d --build

# Watch logs for migration steps
docker compose logs -f web
```

#### Manual Migration Trigger

If automatic migrations fail, run them manually:

```bash
# Shared schema migrations
docker compose exec web python manage.py migrate_schemas --shared

# Tenant schema migrations
docker compose exec web python manage.py migrate_schemas --tenant

# Verify migrations applied
docker compose exec web python manage.py showmigrations
```

#### Verification

After fixing migration issues, verify:

- [ ] All migration steps appear in startup logs
- [ ] `showmigrations` shows all migrations applied (marked with [X])
- [ ] Application can access database tables
- [ ] No table/column not found errors in logs
- [ ] Tenant creation works without errors

