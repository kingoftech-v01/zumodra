# Django Settings Configuration Checklist

**Quick reference for Backend Lead - Phase 1 Tasks**

---

## Immediate Actions (High Priority)

### 1. Enable TenantMigrationCheckMiddleware ⚠️ CRITICAL

**Why:** Prevents requests to tenants with incomplete migrations (prevents database errors)

**File:** `zumodra/settings.py`
**Line:** 212 (in MIDDLEWARE list)

**Add this line:**
```python
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',
    'tenants.middleware.TenantURLConfMiddleware',
    'tenants.middleware.TenantMigrationCheckMiddleware',  # ← ADD THIS LINE
    'django.middleware.security.SecurityMiddleware',
    # ... rest of middleware
]
```

**Test:**
```bash
# Create tenant without migrations
python manage.py create_tenant test "Test" admin@test.com

# Should block access with migration error
curl http://test.localhost:8002/

# Fix migrations
python manage.py migrate_schemas --schema=test

# Should now work
curl http://test.localhost:8002/
```

---

## Code Cleanup (Low Priority)

### 1. Remove Duplicate Template Context Processors

**File:** `zumodra/settings.py`
**Lines to delete:** 271-273

**Current (lines 261-273):**
```python
'context_processors': [
    'django.template.context_processors.request',  # Line 262
    'django.contrib.auth.context_processors.auth',  # Line 263
    'django.contrib.messages.context_processors.messages',  # Line 264
    'django.template.context_processors.debug',
    'django.template.context_processors.i18n',
    'django.template.context_processors.media',
    'django.template.context_processors.static',
    'django.template.context_processors.tz',
    'django.template.context_processors.csrf',
    'django.template.context_processors.request',  # Line 271 ← DELETE
    'django.contrib.auth.context_processors.auth',  # Line 272 ← DELETE
    'django.contrib.messages.context_processors.messages',  # Line 273 ← DELETE
],
```

**Fixed:**
```python
'context_processors': [
    'django.template.context_processors.request',
    'django.contrib.auth.context_processors.auth',
    'django.contrib.messages.context_processors.messages',
    'django.template.context_processors.debug',
    'django.template.context_processors.i18n',
    'django.template.context_processors.media',
    'django.template.context_processors.static',
    'django.template.context_processors.tz',
    'django.template.context_processors.csrf',
],
```

---

### 2. Remove Duplicate LOGGING Definition

**File:** `zumodra/settings.py`
**Lines to delete:** 612-627

**Reason:** LOGGING is defined twice. The second definition (lines 931-978) overwrites the first.

**Keep:** Lines 931-978 (comprehensive logging with file handler)
**Delete:** Lines 612-627 (basic logging)

---

### 3. Remove Commented DATABASE_ROUTERS

**File:** `zumodra/settings.py`
**Lines to delete:** 333-336

**Current:**
```python
# Line 311-313 (KEEP THIS)
DATABASE_ROUTERS = (
    'django_tenants.routers.TenantSyncRouter',
)

# Lines 333-336 (DELETE THIS)
# ROUTERS FOR TENANTS
# DATABASE_ROUTERS = (
#     'django_tenants.routers.TenantSyncRouter',
# )
```

---

## Documentation Updates (Medium Priority)

### 1. Update .env.example

**File:** `.env.example`
**Line:** 66

**Current:**
```bash
EMAIL_HOST_PASSWORD=
```

**Change to:**
```bash
EMAIL_HOST_PASSWORD=your-smtp-password  # REQUIRED for production
```

---

### 2. Configure GeoIP Path (Optional)

**File:** `zumodra/settings.py`
**Line:** 609

**Current:**
```python
GEOIP_PATH = 'path/to/geoip_data'
```

**If you want to use GeoIP features:**

1. Download MaxMind GeoLite2 database:
```bash
mkdir -p geoip
cd geoip
# Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
```

2. Update settings:
```python
GEOIP_PATH = BASE_DIR / 'geoip'
```

**If not using GeoIP:** Leave as is (won't affect functionality)

---

## Verification Steps

### 1. Verify All Apps Load

```bash
python manage.py check
```

**Expected:** No errors

---

### 2. Verify Database Configuration

```bash
python manage.py dbshell
```

**Expected:** Connects to PostgreSQL successfully

**SQL to run:**
```sql
-- Check PostGIS extension
SELECT PostGIS_version();

-- Check schemas
SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT LIKE 'pg_%' AND schema_name != 'information_schema';

-- Should show: public, demo (if demo tenant exists)
```

---

### 3. Verify GDAL/GEOS (GeoDjango)

```bash
python manage.py shell
```

**Python to run:**
```python
from django.contrib.gis import gdal, geos
print(f"GDAL: {gdal.HAS_GDAL}")  # Should be True
print(f"GEOS: {geos.HAS_GEOS}")  # Should be True
print(f"GDAL Version: {gdal.gdal_version()}")
print(f"GEOS Version: {geos.geos_version()}")
```

---

### 4. Verify Caching

```bash
python manage.py shell
```

**Python to run:**
```python
from django.core.cache import cache
cache.set('test', 'hello', 60)
print(cache.get('test'))  # Should print 'hello'
```

---

### 5. Verify Static Files

```bash
python manage.py collectstatic --dry-run
```

**Expected:** Lists all files that would be collected (no errors)

---

### 6. Run Migrations

```bash
# Public schema
python manage.py migrate_schemas --shared

# All tenants
python manage.py migrate_schemas --tenant
```

**Expected:** All migrations apply successfully

---

### 7. Create Test Tenant

```bash
python manage.py create_tenant test-tenant "Test Tenant" admin@test.com
```

**Expected:** Tenant created with schema and domain

**Verify:**
```bash
python manage.py shell
```

```python
from tenants.models import Tenant, Domain
tenant = Tenant.objects.get(slug='test-tenant')
print(f"Tenant: {tenant.name}")
print(f"Schema: {tenant.schema_name}")
print(f"Domains: {[d.domain for d in tenant.domains.all()]}")
```

---

## Production Deployment Checklist

Before deploying to production, verify:

### Environment Variables

- [ ] `SECRET_KEY` - Generated with Django's get_random_secret_key (50+ chars)
- [ ] `DEBUG=False` - Never True in production
- [ ] `ALLOWED_HOSTS` - Includes production domain (e.g., `zumodra.com,.zumodra.com`)
- [ ] `DB_PASSWORD` - Strong password (16+ chars)
- [ ] `EMAIL_HOST_PASSWORD` - SMTP password configured
- [ ] `REDIS_URL` - Redis connection string (with password in production)
- [ ] `CELERY_BROKER_URL` - RabbitMQ connection string
- [ ] `STRIPE_SECRET_KEY` - Production Stripe key (starts with `sk_live_`)
- [ ] `STRIPE_PUBLIC_KEY` - Production Stripe public key (starts with `pk_live_`)

### Security

- [ ] `SESSION_COOKIE_SECURE=True`
- [ ] `CSRF_COOKIE_SECURE=True`
- [ ] `SECURE_SSL_REDIRECT=True`
- [ ] HSTS enabled (automatic when DEBUG=False)
- [ ] SSL certificate valid and configured
- [ ] Firewall rules configured (only allow 80, 443, SSH)

### Database

- [ ] PostgreSQL 16 with PostGIS extension installed
- [ ] Database backups configured (daily minimum)
- [ ] Connection pooling configured
- [ ] Slow query logging enabled

### Services

- [ ] Redis running and secured with password
- [ ] RabbitMQ running and secured
- [ ] Celery workers running (at least 1 per queue)
- [ ] Celery beat scheduler running
- [ ] Daphne (Channels) running for WebSockets
- [ ] nginx reverse proxy configured

### Static Files

- [ ] `python manage.py collectstatic` run successfully
- [ ] WhiteNoise serving static files
- [ ] Static files cached (check response headers)
- [ ] S3 configured for media files (optional but recommended)

### Monitoring

- [ ] Error tracking configured (Sentry or equivalent)
- [ ] Uptime monitoring configured
- [ ] Log aggregation configured
- [ ] Performance monitoring configured
- [ ] Database performance monitoring

### Testing

- [ ] All tests passing: `pytest`
- [ ] Coverage above 60%: `pytest --cov`
- [ ] Security tests passing: `pytest -m security`
- [ ] Load testing completed
- [ ] Smoke test on production completed

---

## Documentation Created

The following comprehensive documentation has been created:

### 1. docs/SETTINGS.md (Complete Settings Guide)

**Contents:**
- All settings explained in detail
- Environment variable requirements
- Security settings checklist
- Multi-tenancy configuration
- Common pitfalls and solutions
- Production deployment checklist
- Quick reference tables

**Use for:** Onboarding new developers, configuring production, troubleshooting

---

### 2. docs/SETTINGS_AUDIT_REPORT.md (Audit Findings)

**Contents:**
- Executive summary of audit
- Detailed findings for all settings files
- Verification of all INSTALLED_APPS
- Security analysis
- Priority-ranked recommendations
- Testing recommendations

**Use for:** Understanding current state, planning improvements, compliance

---

### 3. docs/SETTINGS_CHECKLIST.md (This File)

**Contents:**
- Quick action items for Backend Lead
- Code cleanup tasks
- Verification steps
- Production deployment checklist

**Use for:** Day-to-day reference, deployment preparation

---

## Next Steps for Backend Lead

### Phase 1: Immediate (Today)

1. ✅ Review audit report (`docs/SETTINGS_AUDIT_REPORT.md`)
2. ⚠️ Enable `TenantMigrationCheckMiddleware` (5 minutes)
3. ✅ Run verification steps (above)
4. ✅ Share `docs/SETTINGS.md` with team

### Phase 2: This Week

1. Clean up duplicate template processors (5 minutes)
2. Clean up duplicate LOGGING definition (5 minutes)
3. Update `.env.example` documentation (5 minutes)
4. Add settings validation tests (`tests/test_settings.py`)

### Phase 3: Before Production Launch

1. Review production checklist (above)
2. Run full test suite with coverage
3. Load test with 1000+ concurrent users
4. Security audit with OWASP Top 10 checklist
5. Disaster recovery test (database restore, failover)

---

## Support

For questions or issues:
- **Settings Documentation:** `docs/SETTINGS.md`
- **Audit Report:** `docs/SETTINGS_AUDIT_REPORT.md`
- **Troubleshooting:** Check Django debug logs in `logs/django.log`
- **Security Issues:** Review `zumodra/settings_security.py` for reference configs

**Last Updated:** 2026-01-16
**Maintained By:** Backend Lead Team
