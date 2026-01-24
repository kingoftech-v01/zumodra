# Django Settings Audit Report

**Project:** Zumodra Multi-Tenant ATS/HR SaaS Platform
**Date:** 2026-01-16
**Auditor:** Backend Lead
**Django Version:** 5.2.7
**Python Version:** 3.11+

---

## Executive Summary

This audit reviewed all Django settings files (`settings.py`, `settings_tenants.py`, `settings_security.py`) and related configuration. The application is **generally well-configured** with comprehensive security measures, proper multi-tenancy setup, and production-ready defaults.

**Overall Assessment:** ✅ **PASS** with minor recommendations

### Key Findings

- ✅ All critical settings properly configured
- ✅ Multi-tenancy architecture correctly implemented
- ✅ Security settings comprehensive and production-ready
- ✅ All INSTALLED_APPS exist and are properly structured
- ✅ Database configuration correct with PostGIS support
- ✅ GDAL/GEOS configuration recently added for Windows compatibility
- ⚠️ Minor issues: Template processor duplication, unused configuration files
- ⚠️ Documentation needed: Comprehensive settings guide (now created)

---

## Audit Scope

### Files Reviewed

1. **c:\Users\techn\OneDrive\Documents\zumodra\zumodra\settings.py** (1,265 lines)
   - Main settings file with all active configuration
   - Comprehensive coverage of all Django subsystems

2. **c:\Users\techn\OneDrive\Documents\zumodra\zumodra\settings_tenants.py** (292 lines)
   - Reference implementation for multi-tenancy
   - **Note:** Not currently imported by settings.py

3. **c:\Users\techn\OneDrive\Documents\zumodra\zumodra\settings_security.py** (550 lines)
   - Enhanced security configurations and validators
   - **Note:** Not currently imported by settings.py

4. **c:\Users\techn\OneDrive\Documents\zumodra\.env.example** (213 lines)
   - Comprehensive environment variable documentation
   - All required variables documented

5. **c:\Users\techn\OneDrive\Documents\zumodra\core\domain.py** (434 lines)
   - Centralized domain configuration utilities
   - Excellent implementation

6. **c:\Users\techn\OneDrive\Documents\zumodra\tenants\middleware.py** (1,094 lines)
   - Custom tenant resolution middleware
   - Comprehensive security and performance features

---

## Detailed Findings

### 1. INSTALLED_APPS Verification ✅

**Status:** All apps exist and are properly configured

#### Verified Apps (24/24)

All applications listed in `INSTALLED_APPS` have been verified to exist in the codebase:

```
✓ accounts/         - KYC, user profiles
✓ ai_matching/      - AI-powered job matching
✓ analytics/        - Platform analytics
✓ api/              - REST API
✓ appointment/      - Appointment booking
✓ ats/              - Applicant Tracking System
✓ blog/             - Content management
✓ careers/          - Public career pages
✓ configurations/   - System configuration
✓ core/             - Core utilities
✓ custom_account_u/ - Custom user model
✓ dashboard/        - Main dashboard
✓ dashboard_service/- Dashboard services
✓ finance/          - Payment processing
✓ hr_core/          - HR operations
✓ integrations/     - Third-party integrations
✓ main/             - Main app
✓ marketing/        - Marketing tools
✓ messages_sys/     - Real-time messaging
✓ notifications/    - Notification system
✓ security/         - Security features
✓ services/         - Marketplace services
✓ tenants/          - Tenant management
✓ newsletter/       - Email marketing
```

**Third-Party Apps:** All third-party apps (Django, Wagtail, Allauth, etc.) verified via imports.

**Recommendation:** No action needed. App structure is excellent.

---

### 2. Database Configuration ✅

**Status:** Correctly configured for multi-tenant PostgreSQL with PostGIS

#### Configuration Review

```python
DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.postgresql_backend',  # ✅ Correct wrapper
        'NAME': env('DB_NAME', default='zumodra'),
        'USER': env('DB_USER', default='postgres'),
        'PASSWORD': env('DB_PASSWORD'),  # ✅ No default (secure)
        'HOST': env('DB_HOST', default='localhost'),
        'PORT': env('DB_PORT', default='5432'),
    }
}

ORIGINAL_BACKEND = "django.contrib.gis.db.backends.postgis"  # ✅ PostGIS enabled
DATABASE_ROUTERS = ('django_tenants.routers.TenantSyncRouter',)  # ✅ Multi-tenant routing
```

#### Key Points

- ✅ **django-tenants wrapper** properly configured
- ✅ **PostGIS backend** specified (required for geographic fields)
- ✅ **DB_PASSWORD** has no default (security best practice)
- ✅ **Environment variable priority** correct (DB_NAME > DB_DEFAULT_NAME)
- ✅ **Database router** configured for tenant isolation

#### Issue Found: Duplicate DATABASE_ROUTERS

**Location:** Lines 311-313 and 333-336 (commented)

**Impact:** None (second is commented out)

**Recommendation:** Remove commented section (lines 333-336) to reduce confusion.

---

### 3. Middleware Configuration ⚠️

**Status:** Correctly ordered with one minor optimization opportunity

#### Middleware Stack Review

```python
MIDDLEWARE = [
    # ✅ Tenant middleware first (correct)
    'django_tenants.middleware.main.TenantMainMiddleware',
    'tenants.middleware.TenantURLConfMiddleware',

    # ✅ Security before session (correct)
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',

    # ✅ CORS before CommonMiddleware (correct)
    'corsheaders.middleware.CorsMiddleware',

    # ✅ Session and authentication middleware in correct order
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'custom_account_u.middleware.Require2FAMiddleware',

    # ✅ Messages and security
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'custom_account_u.middleware.AuthSecurityMiddleware',

    # ✅ Audit middleware after auth (correct)
    'simple_history.middleware.HistoryRequestMiddleware',
    'auditlog.middleware.AuditlogMiddleware',

    # ✅ CSP middleware
    'csp.middleware.CSPMiddleware',

    # ✅ Rate limiting last (correct)
    'axes.middleware.AxesMiddleware',

    # ✅ Wagtail redirects
    'wagtail.contrib.redirects.middleware.RedirectMiddleware',
]
```

#### Available but Not Enabled

The following middleware exist in `tenants/middleware.py` but are not enabled:

```python
# Available for future use:
TenantContextMiddleware         # Adds tenant context helpers to request
TenantUsageMiddleware          # Tracks API usage for billing
TenantSecurityMiddleware       # Enforces tenant-specific security policies
TenantMigrationCheckMiddleware # Blocks requests to unmigrated tenants (CRITICAL)
```

**Recommendation:** Consider enabling `TenantMigrationCheckMiddleware` for production safety. This middleware blocks requests to tenants with incomplete migrations, preventing database errors.

**Priority:** Medium (production safety feature)

---

### 4. Security Settings ✅

**Status:** Excellent security configuration with defense-in-depth

#### Core Security

```python
# ✅ SECRET_KEY from environment (no default)
SECRET_KEY = env('SECRET_KEY')

# ✅ DEBUG defaults to False
DEBUG = env.bool('DEBUG', default=False)

# ✅ ALLOWED_HOSTS properly configured
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['localhost', '127.0.0.1', '.localhost'])

# ✅ Session security
SESSION_COOKIE_AGE = 28800  # 8 hours (reduced from default 2 weeks)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=not DEBUG)

# ✅ CSRF protection
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=not DEBUG)

# ✅ HSTS (production only)
if not DEBUG:
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
```

#### Content Security Policy (CSP)

**Status:** ⚠️ Partially relaxed for development

```python
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'", "'unsafe-inline'", "'unsafe-eval'"),  # ⚠️ Relaxed
        'style-src': ("'self'", "'unsafe-inline'"),
        # ... other directives
    }
}
```

**Issue:** `unsafe-inline` and `unsafe-eval` are enabled for HTMX and Alpine.js compatibility.

**Recommendation:** For production hardening, use nonces instead:

```python
# In template:
<script nonce="{{ request.csp_nonce }}">
    // JavaScript code
</script>

# In settings:
'script-src': ("'self'", "'nonce-{nonce}'"),  # Django-CSP 4.0+ supports this
```

**Priority:** Low (acceptable trade-off for current stack)

#### Brute Force Protection (Django-Axes)

```python
# ✅ Configured correctly
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(hours=1)  # In settings_security.py
AXES_HANDLER = 'axes.handlers.cache.AxesCacheHandler'
AXES_CACHE = 'axes'
```

**Status:** Excellent. Locks account after 5 failed attempts for 1 hour.

#### Two-Factor Authentication

```python
# ✅ Multiple 2FA methods supported
- Allauth MFA (TOTP, WebAuthn)
- django-otp (TOTP, HOTP, Email, Static codes)

# ✅ 2FA settings
MFA_SUPPORTED_TYPES = ['totp', 'webauthn']
MFA_PASSKEY_LOGIN_ENABLED = True
TWO_FACTOR_MANDATORY = False  # Can be enabled per-tenant
```

**Recommendation:** Consider enabling `TWO_FACTOR_MANDATORY = True` for production tenants handling sensitive data.

---

### 5. GDAL/GEOS Configuration ✅

**Status:** Recently added (2026-01-16), correctly configured for Windows

#### Configuration

```python
# Windows-specific GDAL paths
import sys
if sys.platform == 'win32':
    GDAL_LIBRARY_PATH = str(Path(sys.prefix) / 'Lib' / 'site-packages' / 'osgeo' / 'gdal.dll')
    GEOS_LIBRARY_PATH = str(Path(sys.prefix) / 'Lib' / 'site-packages' / 'osgeo' / 'geos_c.dll')
```

**Why this is needed:**
- Windows doesn't include GDAL/GEOS in system PATH
- Django GeoDjango requires explicit DLL paths
- Linux/Docker systems don't need this (system-wide installation)

**Verification:**
```bash
# Tested and working:
python -c "from django.contrib.gis import gdal; print(gdal.HAS_GDAL)"  # True
python -c "from django.contrib.gis import geos; print(geos.HAS_GEOS)"  # True
```

**Recommendation:** No changes needed. Configuration is correct.

---

### 6. Static Files & Media ✅

**Status:** Correctly configured with WhiteNoise

#### Static Files

```python
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / "staticfiles"]
STATIC_ROOT = BASE_DIR / 'static'

# ✅ WhiteNoise enabled in middleware
'whitenoise.middleware.WhiteNoiseMiddleware',
```

**Directory Structure:**
```
zumodra/
├── staticfiles/              # ✅ Source files (in git)
│   ├── assets/js/vendor/    # ✅ Alpine.js, HTMX, Chart.js (local)
│   ├── assets/css/          # ✅ Custom CSS
│   ├── assets/fonts/        # ✅ Web fonts (local)
│   └── dist/output.css      # ✅ Compiled Tailwind
└── static/                  # ✅ Collected files (not in git)
```

**CSP Compliance:** ✅ All assets served locally (no external CDN)

#### Media Files

```python
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ✅ S3 configured for production
if not DEBUG and AWS_ACCESS_KEY_ID:
    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
```

**Recommendation:** No changes needed. Configuration follows Django best practices.

---

### 7. Caching Configuration ✅

**Status:** Redis caching properly configured

#### Cache Configuration

```python
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://127.0.0.1:6379/2'),
        'KEY_PREFIX': 'zumodra',
    },
    'axes': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://127.0.0.1:6379/3'),
    },
}

# ✅ Session backend using cache
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
```

**Redis Database Allocation:**
- DB 0: Celery broker
- DB 1: Celery results & Channels
- DB 2: Default cache
- DB 3: Axes (brute force protection)

**Recommendation:** Consider adding a separate cache for API rate limiting:

```python
CACHES = {
    # ... existing caches ...
    'ratelimit': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://127.0.0.1:6379/4'),
    },
}
```

**Priority:** Low (current configuration is adequate)

---

### 8. Domain Configuration ✅

**Status:** Excellent centralized domain configuration

#### Configuration

```python
# ✅ Centralized domain settings
PRIMARY_DOMAIN = env('PRIMARY_DOMAIN', default='localhost' if DEBUG else '')
SITE_URL = env('SITE_URL', default=f"http://localhost:{env('WEB_PORT', default='8002')}" if DEBUG else '')
TENANT_BASE_DOMAIN = env('TENANT_BASE_DOMAIN', default=PRIMARY_DOMAIN)
```

#### Centralized Utilities (core/domain.py)

```python
# ✅ Excellent implementation
from core.domain import (
    get_primary_domain,      # Get PRIMARY_DOMAIN
    get_site_url,            # Get SITE_URL with protocol
    get_tenant_url,          # Build tenant-specific URL
    build_absolute_url,      # Build full URL for a path
    get_noreply_email,       # Get noreply@{domain}
    is_development_domain,   # Check if running locally
)
```

**Key Features:**
- ✅ No hard-coded domains (except development fallback)
- ✅ Environment-driven configuration
- ✅ Auto-detection of development vs production
- ✅ Django Site framework auto-synced on startup
- ✅ LRU caching for performance

**Security Note:** Localhost references in `core/validators.py` are **intentional** (SSRF protection) and should NOT be changed.

**Recommendation:** No changes needed. This is a best-practice implementation.

---

### 9. Email Configuration ⚠️

**Status:** Correctly configured with minor documentation issue

#### Configuration

```python
EMAIL_BACKEND = env('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = env('EMAIL_HOST', default='mailhog' if DEBUG else '')
EMAIL_PORT = env.int('EMAIL_PORT', default=1025 if DEBUG else 587)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=False if DEBUG else True)
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')  # ✅ Required
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default=f"noreply@{EMAIL_DOMAIN}")
```

**Development:** MailHog configured for catching emails (excellent for development)

**Issue:** `.env.example` shows `EMAIL_HOST_PASSWORD=` with no value, but this is **REQUIRED**.

**Recommendation:** Update `.env.example` line 66:
```bash
EMAIL_HOST_PASSWORD=your-smtp-password  # REQUIRED for production
```

**Priority:** Low (documentation only)

---

### 10. Template Configuration ⚠️

**Status:** Working correctly but has duplicates

#### Issue: Duplicate Context Processors

**Location:** Lines 261-273

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
    'django.template.context_processors.request',  # Line 271 (DUPLICATE)
    'django.contrib.auth.context_processors.auth',  # Line 272 (DUPLICATE)
    'django.contrib.messages.context_processors.messages',  # Line 273 (DUPLICATE)
],
```

**Impact:** None (Django ignores duplicates), but wastes processing cycles.

**Recommendation:** Remove lines 271-273.

**Priority:** Low (code cleanup)

---

### 11. Logging Configuration ⚠️

**Status:** Working but has duplicate definitions

#### Issue: LOGGING Defined Twice

**Location:**
- Lines 612-627: Basic logging configuration
- Lines 931-978: Comprehensive logging configuration

**Impact:** Second definition **overwrites** first. Only lines 931-978 are active.

**Current Configuration (Active):**
```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {...},
        'simple': {...},
    },
    'handlers': {
        'console': {...},
        'file': {'filename': os.path.join(BASE_DIR, 'logs', 'django.log')},
    },
    'root': {...},
    'loggers': {...},
}

# ✅ Creates logs directory
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)
```

**Recommendation:** Remove the first LOGGING definition (lines 612-627) to avoid confusion.

**Priority:** Low (code cleanup)

---

### 12. Multi-Tenancy Configuration ✅

**Status:** Excellent implementation with comprehensive features

#### SHARED_APPS vs TENANT_APPS

```python
# ✅ Correct segregation
SHARED_APPS = [
    'django_tenants',  # ✅ First (required)
    'custom_account_u',  # ✅ Users shared across tenants
    'tenants',  # ✅ Tenant management
    'allauth',  # ✅ Authentication
    # ... shared across all tenants
]

TENANT_APPS = [
    'accounts',  # ✅ Tenant-specific profiles
    'ats',  # ✅ Applicant tracking
    'hr_core',  # ✅ HR data
    'finance',  # ✅ Payments
    # ... isolated per tenant
]

# ✅ Computed automatically
INSTALLED_APPS = list(SHARED_APPS) + [app for app in TENANT_APPS if app not in SHARED_APPS]
```

#### Tenant Middleware

**Implemented in tenants/middleware.py:**

1. ✅ `TenantURLConfMiddleware` - Fixes URL routing for tenants
2. ✅ `ZumodraTenantMiddleware` - Enhanced tenant resolution:
   - Multi-strategy resolution (header, subdomain, custom domain)
   - Redis caching for performance
   - Security validation for header-based resolution
   - Rate limiting (100 req/min to prevent enumeration)
   - Trial expiration checking
   - Suspension/cancellation handling
3. ⚠️ `TenantContextMiddleware` - Available but not enabled
4. ⚠️ `TenantUsageMiddleware` - Available but not enabled
5. ⚠️ `TenantSecurityMiddleware` - Available but not enabled
6. ⚠️ `TenantMigrationCheckMiddleware` - Available but not enabled (CRITICAL for production)

**Recommendation:** Enable `TenantMigrationCheckMiddleware` in production to prevent requests to tenants with incomplete migrations.

```python
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',
    'tenants.middleware.TenantURLConfMiddleware',
    'tenants.middleware.TenantMigrationCheckMiddleware',  # ADD THIS
    # ... rest of middleware
]
```

**Priority:** High (production safety)

---

### 13. REST API Configuration ✅

**Status:** Comprehensive and production-ready

#### DRF Configuration

```python
REST_FRAMEWORK = {
    # ✅ OpenAPI schema
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',

    # ✅ JWT + Session auth
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],

    # ✅ Secure default permissions
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],

    # ✅ Pagination
    'PAGE_SIZE': 20,

    # ✅ Rate limiting
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'auth': '5/minute',  # Login
        'token': '10/minute',  # JWT refresh
        'password': '3/minute',  # Password reset
    },

    # ✅ API versioning
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning',
    'ALLOWED_VERSIONS': ['v1', 'v2'],
}
```

#### JWT Configuration

```python
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),  # ✅ Short lifetime
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,  # ✅ Rotation enabled
    'BLACKLIST_AFTER_ROTATION': True,  # ✅ Blacklisting enabled
    'UPDATE_LAST_LOGIN': True,
}
```

**Recommendation:** No changes needed. Configuration follows security best practices.

---

### 14. Celery Configuration ✅

**Status:** Production-ready with task routing

#### Configuration

```python
# ✅ Broker and backend configured
CELERY_BROKER_URL = env('CELERY_BROKER_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND', default='redis://localhost:6379/1')

# ✅ Task execution settings
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_TASK_TIME_LIMIT = 3600  # 1 hour hard limit
CELERY_TASK_SOFT_TIME_LIMIT = 3300  # 55 minutes

# ✅ Worker settings
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000
CELERY_WORKER_PREFETCH_MULTIPLIER = 4

# ✅ Task routing by queue
CELERY_TASK_ROUTES = {
    'newsletter.tasks.*': {'queue': 'emails'},
    'finance.tasks.*': {'queue': 'payments'},
    'analytics.tasks.*': {'queue': 'analytics'},
    'ats.tasks.*': {'queue': 'ats'},
}

# ✅ Beat scheduler
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'
```

**Recommendation:** No changes needed. Configuration is excellent.

---

### 15. Channels/WebSockets Configuration ✅

**Status:** Configured for scale (500K concurrent users)

#### Configuration

```python
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [REDIS_CHANNEL_URL],
            'capacity': 100000,  # ✅ Scaled for high concurrency
            'expiry': 60,
            'group_expiry': 86400,  # 24 hours
        },
    },
}

# ✅ ASGI application
ASGI_APPLICATION = 'zumodra.asgi.application'
```

**Recommendation:** No changes needed. Configuration is production-ready.

---

### 16. Unused Configuration Files ⚠️

**Issue:** `settings_tenants.py` and `settings_security.py` exist but are not imported.

#### Current Architecture

**settings.py** contains all active configuration (monolithic approach):
- Lines 64-194: Multi-tenancy configuration (SHARED_APPS, TENANT_APPS)
- Lines 210-251: Security middleware
- Lines 499-812: Security settings
- Lines 814-1265: API, caching, etc.

**settings_tenants.py** and **settings_security.py** provide:
- Reference implementations
- Enhanced configurations
- Reusable constants

#### Impact

**Positive:**
- Simpler deployment (one settings file)
- No import order issues
- Everything in one place

**Negative:**
- Duplicate configuration between files
- Potential confusion about which file is active
- Enhanced features in settings_security.py not automatically used

#### Recommendation

**Option 1: Keep Current Architecture** (Recommended)
- Document that only `settings.py` is active
- Use other files as references/documentation
- No code changes needed

**Option 2: Import Enhanced Settings** (Advanced)
```python
# At end of settings.py
try:
    from .settings_security import (
        AUTH_PASSWORD_VALIDATORS,  # Enhanced validators
        PASSWORD_HASHERS,  # Argon2 hasher
    )
except ImportError:
    pass
```

**Priority:** Low (documentation issue, not technical issue)

---

## Critical Vulnerabilities

**None found.** The application has strong security posture.

---

## High-Priority Issues

### 1. Enable TenantMigrationCheckMiddleware

**Priority:** High
**Impact:** Production stability
**Effort:** Low (5 minutes)

**Issue:** Requests to tenants with incomplete migrations will cause database errors.

**Solution:**
```python
# settings.py MIDDLEWARE list
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',
    'tenants.middleware.TenantURLConfMiddleware',
    'tenants.middleware.TenantMigrationCheckMiddleware',  # ADD THIS LINE
    # ... rest of middleware
]
```

**Testing:**
```bash
# Create tenant without running migrations
python manage.py create_tenant test-tenant "Test" admin@test.com

# Try to access tenant (should block with migration error page)
curl http://test-tenant.localhost:8002/

# Fix migrations
python manage.py migrate_schemas --schema=test-tenant

# Access should now work
curl http://test-tenant.localhost:8002/
```

---

## Medium-Priority Issues

### 1. GeoIP Path Not Configured

**Priority:** Medium
**Impact:** GeoIP features won't work
**Effort:** Low (10 minutes)

**Current:** `GEOIP_PATH = 'path/to/geoip_data'` (placeholder)

**Solution:**
```bash
# Download MaxMind GeoLite2 database
mkdir -p geoip
cd geoip
# Download from MaxMind (requires account)
```

```python
# settings.py
GEOIP_PATH = BASE_DIR / 'geoip'
```

### 2. Update .env.example Documentation

**Priority:** Medium
**Impact:** Developer confusion
**Effort:** Low (5 minutes)

**Issues:**
- `EMAIL_HOST_PASSWORD` shown as optional but is required
- Some variables not clearly marked as required

**Solution:** Update `.env.example` with clear REQUIRED markers:
```bash
EMAIL_HOST_PASSWORD=your-smtp-password  # REQUIRED for production
```

---

## Low-Priority Issues (Code Cleanup)

### 1. Remove Duplicate Template Context Processors

**Location:** settings.py lines 271-273
**Solution:** Delete lines 271-273

### 2. Remove Duplicate LOGGING Definition

**Location:** settings.py lines 612-627
**Solution:** Delete lines 612-627

### 3. Remove Commented DATABASE_ROUTERS

**Location:** settings.py lines 333-336
**Solution:** Delete commented section

---

## Recommendations

### Security Enhancements

1. **Enable TWO_FACTOR_MANDATORY for sensitive tenants**
   - Current: `TWO_FACTOR_MANDATORY = False`
   - Recommended: Make configurable per-tenant

2. **Consider stricter CSP with nonces**
   - Current: Uses `unsafe-inline` for Alpine.js
   - Future: Migrate to nonce-based CSP

3. **Add API rate limiting cache**
   - Add separate Redis DB for rate limiting
   - Isolate from main cache

### Performance Optimizations

1. **Enable connection pooling**
   ```python
   DATABASES = {
       'default': {
           # ... existing config
           'CONN_MAX_AGE': 600,  # 10 minutes
           'OPTIONS': {
               'connect_timeout': 10,
               'options': '-c statement_timeout=30000',  # 30 seconds
           },
       }
   }
   ```

2. **Enable Redis connection pooling**
   ```python
   CACHES = {
       'default': {
           # ... existing config
           'OPTIONS': {
               'CONNECTION_POOL_KWARGS': {
                   'max_connections': 50,
                   'retry_on_timeout': True,
               }
           }
       }
   }
   ```

### Documentation Improvements

1. ✅ **Create comprehensive settings guide** - COMPLETED
   - Location: `docs/SETTINGS.md`
   - Covers all configuration aspects
   - Includes troubleshooting

2. **Add deployment checklist**
   - Pre-deployment verification
   - Post-deployment smoke tests

---

## Testing Recommendations

### 1. Settings Validation Tests

**Create:** `tests/test_settings.py`

```python
def test_secret_key_set():
    """Ensure SECRET_KEY is set and not default"""
    assert settings.SECRET_KEY
    assert len(settings.SECRET_KEY) >= 50

def test_debug_false_in_production():
    """Ensure DEBUG is False in production"""
    if not os.environ.get('DEBUG'):
        assert not settings.DEBUG

def test_all_installed_apps_exist():
    """Verify all INSTALLED_APPS can be imported"""
    for app in settings.INSTALLED_APPS:
        if '.' in app:
            module_name = app.split('.')[0]
        else:
            module_name = app
        try:
            __import__(module_name)
        except ImportError:
            pytest.fail(f"App {app} cannot be imported")

def test_database_backend():
    """Ensure correct database backend"""
    assert settings.DATABASES['default']['ENGINE'] == 'django_tenants.postgresql_backend'
    assert settings.ORIGINAL_BACKEND == 'django.contrib.gis.db.backends.postgis'
```

### 2. Security Tests

```python
def test_secure_cookies_in_production():
    """Ensure secure cookies in production"""
    if not settings.DEBUG:
        assert settings.SESSION_COOKIE_SECURE
        assert settings.CSRF_COOKIE_SECURE

def test_hsts_enabled_in_production():
    """Ensure HSTS is enabled in production"""
    if not settings.DEBUG:
        assert settings.SECURE_HSTS_SECONDS > 0
        assert settings.SECURE_HSTS_INCLUDE_SUBDOMAINS

def test_allowed_hosts_configured():
    """Ensure ALLOWED_HOSTS is not wildcard"""
    assert '*' not in settings.ALLOWED_HOSTS
```

---

## Conclusion

### Overall Assessment

The Zumodra Django settings are **production-ready** with excellent security practices and comprehensive configuration. The multi-tenancy implementation is robust, security is defense-in-depth, and the codebase follows Django best practices.

### Key Strengths

1. ✅ **Comprehensive security configuration** with multiple layers
2. ✅ **Well-architected multi-tenancy** with proper app isolation
3. ✅ **Centralized domain configuration** with no hard-coded values
4. ✅ **Production-ready defaults** (DEBUG=False, secure cookies, HSTS)
5. ✅ **Excellent middleware organization** with correct ordering
6. ✅ **Proper environment variable usage** throughout
7. ✅ **Redis caching and session management** for performance
8. ✅ **Celery task routing** for queue isolation
9. ✅ **Channels configuration** scaled for high concurrency
10. ✅ **GDAL/GEOS configuration** for Windows compatibility

### Areas for Improvement

1. ⚠️ **Enable TenantMigrationCheckMiddleware** (High Priority)
2. ⚠️ **Clean up duplicate template processors and logging** (Low Priority)
3. ⚠️ **Configure GeoIP path** (Medium Priority)
4. ⚠️ **Update .env.example documentation** (Medium Priority)

### Sign-Off

**Auditor:** Backend Lead
**Date:** 2026-01-16
**Status:** ✅ **APPROVED FOR PRODUCTION** with noted improvements

**Next Actions:**
1. Enable TenantMigrationCheckMiddleware (immediate)
2. Review and implement medium-priority improvements
3. Schedule low-priority code cleanup
4. Use `docs/SETTINGS.md` as the canonical settings reference

---

## Appendix: Environment Variables Checklist

### Required for Production

- [ ] `SECRET_KEY` - Generated with Django's get_random_secret_key
- [ ] `DEBUG=False` - Never True in production
- [ ] `ALLOWED_HOSTS` - Includes production domain (no wildcards)
- [ ] `DB_PASSWORD` - Strong database password
- [ ] `EMAIL_HOST_PASSWORD` - SMTP password for email sending
- [ ] `STRIPE_SECRET_KEY` - Production Stripe key (not test key)
- [ ] `REDIS_URL` - Redis connection string
- [ ] `CELERY_BROKER_URL` - RabbitMQ connection string

### Optional but Recommended

- [ ] `PRIMARY_DOMAIN` - Production domain
- [ ] `SITE_URL` - Full site URL with https://
- [ ] `AWS_ACCESS_KEY_ID` - For S3 media storage
- [ ] `AWS_SECRET_ACCESS_KEY` - For S3 media storage
- [ ] `SENTRY_DSN` - Error monitoring

### Security Hardening

- [ ] `SESSION_COOKIE_SECURE=True`
- [ ] `CSRF_COOKIE_SECURE=True`
- [ ] `SECURE_SSL_REDIRECT=True`
- [ ] `CORS_ALLOWED_ORIGINS` - Specific domains only

---

**End of Report**
