# Django Settings Configuration Guide

**Last Updated:** 2026-01-16
**Project:** Zumodra Multi-Tenant ATS/HR SaaS Platform
**Django Version:** 5.2.7

This document provides comprehensive documentation for all Django settings in the Zumodra project, including configuration requirements, security best practices, and troubleshooting guidance.

---

## Table of Contents

1. [Settings Files Overview](#settings-files-overview)
2. [Critical Environment Variables](#critical-environment-variables)
3. [Database Configuration](#database-configuration)
4. [Multi-Tenancy Configuration](#multi-tenancy-configuration)
5. [Security Settings](#security-settings)
6. [Middleware Configuration](#middleware-configuration)
7. [Caching Configuration](#caching-configuration)
8. [Static Files & Media](#static-files--media)
9. [Email Configuration](#email-configuration)
10. [Domain Configuration](#domain-configuration)
11. [REST API Configuration](#rest-api-configuration)
12. [Celery Configuration](#celery-configuration)
13. [Channels/WebSockets Configuration](#channelswebsockets-configuration)
14. [GDAL/GeoDjango Configuration](#gdalgeodjango-configuration)
15. [Common Pitfalls & Solutions](#common-pitfalls--solutions)
16. [Production Checklist](#production-checklist)

---

## Settings Files Overview

The Zumodra project splits settings across three main files for modularity:

| File | Purpose | Import Priority |
|------|---------|-----------------|
| `zumodra/settings.py` | Main settings, database, apps, middleware | Base (loaded first) |
| `zumodra/settings_tenants.py` | Multi-tenancy specific configuration | Optional (not currently imported) |
| `zumodra/settings_security.py` | Security hardening, CSP, rate limiting | Optional (provides reusable configs) |

### Current Architecture

**Important:** The project currently uses a **monolithic settings.py** approach. The `settings_tenants.py` and `settings_security.py` files exist but are **NOT automatically imported**. All active configuration is in `settings.py`.

**Why This Matters:**
- `settings.py` contains **all active configuration** including tenant and security settings
- `settings_tenants.py` and `settings_security.py` provide **reference implementations** and **reusable constants**
- Any changes to `settings_tenants.py` or `settings_security.py` will NOT take effect unless manually copied to `settings.py`

---

## Critical Environment Variables

These environment variables **must** be set before the application can start:

### Required Variables

```bash
# Security (REQUIRED)
SECRET_KEY=your-secret-key-here  # Generate with: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Database (REQUIRED)
DB_HOST=db                       # Database host (db for Docker, localhost for local dev)
DB_PORT=5432                     # PostgreSQL port (5434 external, 5432 internal)
DB_NAME=zumodra                  # Database name
DB_USER=postgres                 # Database user
DB_PASSWORD=your-db-password     # Database password (REQUIRED, no default)

# Redis (REQUIRED for caching, sessions, channels)
REDIS_URL=redis://redis:6379/0   # Redis connection URL

# Email Password (REQUIRED for SMTP)
EMAIL_HOST_PASSWORD=your-smtp-password  # SMTP password for sending emails
```

### Optional But Recommended

```bash
# Environment Mode
DEBUG=True                       # False for production

# Security
ALLOWED_HOSTS=localhost,127.0.0.1,.localhost  # Comma-separated list

# Domain Configuration
PRIMARY_DOMAIN=localhost         # Main domain (yourdomain.com in production)
SITE_URL=http://localhost:8002   # Full URL with protocol
TENANT_BASE_DOMAIN=localhost     # Base domain for tenant subdomains

# Email
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=mailhog               # SMTP host (mailhog for dev, smtp.gmail.com for production)
EMAIL_PORT=1025                  # SMTP port (1025 for mailhog, 587 for TLS)
DEFAULT_FROM_EMAIL=noreply@localhost

# RabbitMQ (for Celery)
RABBITMQ_USER=zumodra
RABBITMQ_PASSWORD=your-rabbitmq-password
CELERY_BROKER_URL=amqp://zumodra:password@rabbitmq:5672/zumodra

# Stripe (for payments)
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_PUBLIC_KEY=pk_test_xxx
```

### How to Set Environment Variables

**Development (.env file):**
```bash
# Copy the example file
cp .env.example .env

# Edit .env with your values
nano .env
```

**Production (Docker Compose):**
```yaml
# docker-compose.yml
services:
  web:
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DB_PASSWORD=${DB_PASSWORD}
```

**Production (Kubernetes):**
```yaml
# kubernetes/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: zumodra-secrets
type: Opaque
data:
  secret-key: <base64-encoded-secret-key>
  db-password: <base64-encoded-db-password>
```

---

## Database Configuration

### Basic Configuration

```python
# zumodra/settings.py (lines 293-305)
DATABASES = {
    'default': {
        # Use django-tenants database backend wrapper for PostGIS
        'ENGINE': 'django_tenants.postgresql_backend',
        'NAME': env('DB_NAME', default='zumodra'),
        'USER': env('DB_USER', default='postgres'),
        'PASSWORD': env('DB_PASSWORD'),  # REQUIRED, no default
        'HOST': env('DB_HOST', default='localhost'),
        'PORT': env('DB_PORT', default='5432'),
    }
}

# Original backend for django-tenants to wrap
ORIGINAL_BACKEND = "django.contrib.gis.db.backends.postgis"
```

### Key Points

1. **Django-Tenants Wrapper**: The `ENGINE` uses `django_tenants.postgresql_backend` which wraps the PostGIS backend for multi-tenant schema isolation
2. **ORIGINAL_BACKEND**: Required by django-tenants to know which backend to wrap
3. **PostGIS Required**: The project uses geographic fields (django.contrib.gis), so PostgreSQL with PostGIS extension is **mandatory**
4. **No Password Default**: `DB_PASSWORD` has no default for security - must be set in environment

### Environment Variable Priority

The database configuration supports both short and legacy environment variable names:

```bash
# Short names (preferred)
DB_NAME=zumodra
DB_PORT=5432

# Legacy names (fallback)
DB_DEFAULT_NAME=zumodra
DB_DEFAULT_PORT=5432
```

Priority: `DB_NAME` > `DB_DEFAULT_NAME` > hardcoded default

### Database Routers

```python
# Multi-tenant database routing
DATABASE_ROUTERS = (
    'django_tenants.routers.TenantSyncRouter',
)
```

This router ensures:
- **Shared apps** (SHARED_APPS) → `public` schema
- **Tenant apps** (TENANT_APPS) → tenant-specific schemas
- Automatic query routing based on current tenant

### Common Database Issues

**Issue: "relation does not exist"**
```bash
# Solution: Run migrations for the schema
python manage.py migrate_schemas --shared    # Public schema
python manage.py migrate_schemas --tenant    # All tenant schemas
python manage.py migrate_schemas --schema=demo  # Specific tenant
```

**Issue: "could not connect to server"**
- Check DB_HOST is correct (use `db` for Docker, `localhost` for local)
- Verify PostgreSQL is running: `docker-compose ps db`
- Check port forwarding: `DB_PORT=5434` (external) vs `5432` (internal)

**Issue: "password authentication failed"**
- Ensure DB_PASSWORD is set in .env
- Password must match PostgreSQL user password
- Check for special characters that need escaping

---

## Multi-Tenancy Configuration

Zumodra uses `django-tenants` for schema-based multi-tenancy. Each tenant gets its own PostgreSQL schema.

### Core Configuration

```python
# Tenant models (lines 199-200)
TENANT_MODEL = "tenants.Tenant"
TENANT_DOMAIN_MODEL = "tenants.Domain"

# Public schema settings (lines 1202-1212)
PUBLIC_SCHEMA_URLCONF = 'zumodra.urls_public'
SHOW_PUBLIC_IF_NO_TENANT_FOUND = True
DEFAULT_SCHEMA_NAME = 'public'
AUTO_CREATE_PUBLIC_SCHEMA = True
```

### App Isolation: SHARED_APPS vs TENANT_APPS

**CRITICAL:** Django-tenants uses `SHARED_APPS` and `TENANT_APPS` to determine which apps are migrated to which schemas.

```python
# SHARED_APPS (lines 64-126)
# Migrated to PUBLIC schema ONLY (shared across all tenants)
SHARED_APPS = [
    'django_tenants',  # MUST be first
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sites',
    'django.contrib.admin',
    'custom_account_u',  # Users shared across tenants
    'tenants',  # Tenant management
    'allauth',  # Authentication
    'django_otp',  # Two-factor auth
    'axes',  # Brute force protection
    # ... other shared apps
]

# TENANT_APPS (lines 128-190)
# Migrated to TENANT schemas ONLY (isolated per tenant)
TENANT_APPS = [
    'django.contrib.contenttypes',  # Needed again for tenant-specific content types
    'django.contrib.sites',  # Each tenant needs its own Site
    'django.contrib.gis',  # Geographic fields
    'rest_framework',
    'accounts',  # KYC, profiles
    'ats',  # Applicant Tracking System
    'hr_core',  # HR operations
    'services',  # Marketplace
    'finance',  # Payments
    'messages_sys',  # Real-time messaging
    # ... other tenant-specific apps
]

# INSTALLED_APPS computed automatically (line 194)
INSTALLED_APPS = list(SHARED_APPS) + [app for app in TENANT_APPS if app not in SHARED_APPS]
```

### Why This Matters

1. **SHARED_APPS**: Tables in `public` schema, accessible to all tenants
2. **TENANT_APPS**: Tables in tenant schemas (`demo`, `acme`, etc.), isolated per tenant
3. **Duplicate Entries**: Some apps (like `contenttypes`, `sites`) appear in BOTH lists because:
   - Public schema needs them for shared functionality
   - Tenant schemas need them for tenant-specific content types and foreign keys

### Tenant Resolution

Tenants are resolved via multiple strategies (priority order):

1. **HTTP Header**: `X-Tenant-ID: tenant-slug` (for API clients)
2. **Subdomain**: `acme.zumodra.com` → tenant slug `acme`
3. **Custom Domain**: Custom domains mapped in `Domain` model

Implementation: `tenants/middleware.py` (`ZumodraTenantMiddleware`)

### Tenant Middleware Stack

```python
# MIDDLEWARE order (lines 210-251)
MIDDLEWARE = [
    # Multi-Tenancy (MUST BE FIRST)
    'django_tenants.middleware.main.TenantMainMiddleware',
    'tenants.middleware.TenantURLConfMiddleware',

    # Security
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',

    # Session & Authentication
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'custom_account_u.middleware.Require2FAMiddleware',

    # Messages & Security
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'custom_account_u.middleware.AuthSecurityMiddleware',

    # Audit & History
    'simple_history.middleware.HistoryRequestMiddleware',
    'auditlog.middleware.AuditlogMiddleware',

    # Content Security Policy
    'csp.middleware.CSPMiddleware',

    # Rate Limiting
    'axes.middleware.AxesMiddleware',

    # Wagtail
    'wagtail.contrib.redirects.middleware.RedirectMiddleware',
]
```

**Critical Order Requirements:**
1. `TenantMainMiddleware` MUST be first
2. `TenantURLConfMiddleware` MUST be immediately after
3. Security middleware should come before session/auth
4. Audit middleware should come after auth
5. Rate limiting (Axes) should come last

### Tenant Management Commands

```bash
# Create a tenant
python manage.py create_tenant acme "ACME Corp" admin@acme.com

# Bootstrap demo tenant with sample data
python manage.py bootstrap_demo_tenant

# Setup production tenant
python manage.py setup_beta_tenant "Company Name" "admin@company.com"

# Add sample data to tenant
python manage.py setup_demo_data --num-jobs 20 --num-candidates 100

# Migrate specific tenant
python manage.py migrate_schemas --schema=acme

# Migrate all tenants
python manage.py migrate_schemas --tenant
```

---

## Security Settings

### SECRET_KEY

**CRITICAL:** Must be set in environment variables and NEVER committed to version control.

```python
# settings.py line 40
SECRET_KEY = env('SECRET_KEY')  # No default - REQUIRED
```

Generate a new key:
```bash
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```

### DEBUG Mode

```python
# settings.py line 43
DEBUG = env.bool('DEBUG', default=False)
```

**Production MUST set:** `DEBUG=False`

**Why:** DEBUG mode:
- Exposes sensitive system information in error pages
- Disables security features like ALLOWED_HOSTS checking
- Shows full stack traces to users
- Serves static files inefficiently

### ALLOWED_HOSTS

```python
# settings.py line 47
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['localhost', '127.0.0.1', '.localhost'])
```

**Production Configuration:**
```bash
# .env
ALLOWED_HOSTS=yourdomain.com,.yourdomain.com,api.yourdomain.com
```

**Why the dot prefix?** `.yourdomain.com` allows all subdomains (tenant subdomains).

**Common Issues:**
- Blank page on production → Check ALLOWED_HOSTS includes your domain
- "Invalid HTTP_HOST header" → Add the domain to ALLOWED_HOSTS
- Wildcard `*` → NEVER use in production (major security risk)

### Password Validators

```python
# settings.py lines 318-331
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

**Enhanced validators** available in `settings_security.py` (lines 150-191):
- `MixedCaseValidator`: Requires uppercase and lowercase
- `NumberValidator`: Requires at least one digit
- `SpecialCharacterValidator`: Requires at least one special character
- `NoUsernameValidator`: Prevents password containing username

**To enable enhanced validators:** Add them to AUTH_PASSWORD_VALIDATORS in settings.py

### Password Hashers

```python
# settings_security.py lines 194-199
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',  # Recommended
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',  # Default
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]
```

**Note:** Argon2 is more secure but requires `pip install argon2-cffi`

### Session Security

```python
# settings.py lines 499-505
SESSION_COOKIE_AGE = 28800  # 8 hours
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# Production only (settings.py lines 803-804)
SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=not DEBUG)
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=not DEBUG)
```

**Best Practices:**
- SESSION_COOKIE_SECURE=True in production (HTTPS only)
- SESSION_COOKIE_HTTPONLY=True prevents JavaScript access
- SESSION_COOKIE_SAMESITE='Lax' prevents CSRF attacks
- SESSION_COOKIE_AGE reduced to 8 hours (was 2 weeks) for security

### HSTS (HTTP Strict Transport Security)

```python
# settings.py lines 806-812 (production only)
if not DEBUG:
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "SAMEORIGIN"
```

**Production Settings:**
```bash
# .env
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
```

### Brute Force Protection (Django-Axes)

```python
# settings.py lines 651-653
AXES_FAILURE_LIMIT = 5
AXES_NEVER_LOCKOUT_WHITELIST = ['127.0.0.1']

# settings_security.py lines 36-88 (full configuration)
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(hours=1)
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
AXES_HANDLER = 'axes.handlers.cache.AxesCacheHandler'
AXES_CACHE = 'axes'
```

**How it works:**
1. User fails login 5 times → Account locked for 1 hour
2. Lockout is per username+IP combination
3. Uses Redis cache for performance
4. Localhost (127.0.0.1) is whitelisted for development

**Check locked users:**
```bash
python manage.py axes_list_attempts
python manage.py axes_reset_username admin@example.com
```

### Content Security Policy (CSP)

```python
# settings.py lines 1222-1254
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'", "'unsafe-inline'", "'unsafe-eval'"),
        'style-src': ("'self'", "'unsafe-inline'"),
        'font-src': ("'self'",),
        'img-src': ("'self'", "data:", "https:", "blob:"),
        'connect-src': ("'self'", "wss:", "https:"),
        'frame-src': ("'self'",),
        'object-src': ("'none'",),
        'base-uri': ("'self'",),
        'form-action': ("'self'",),
    }
}
```

**STRICT CSP - No External CDN Policy:**
- All JavaScript must be served from `/static/` (self)
- All CSS must be served from `/static/` (self)
- All fonts must be served from `/static/` (self)
- No external CDN resources allowed (no jsdelivr, unpkg, Google Fonts, etc.)

**Why?** Security and privacy:
- Prevents external scripts from accessing sensitive data
- Eliminates third-party tracking
- Ensures application works offline
- Complies with GDPR requirements

**Vendors Included Locally:**
- Alpine.js → `staticfiles/assets/js/vendor/alpine.min.js`
- HTMX → `staticfiles/assets/js/vendor/htmx.min.js`
- Chart.js → `staticfiles/assets/js/vendor/chart.min.js`
- Tailwind CSS → `staticfiles/dist/output.css`

---

## Middleware Configuration

### Middleware Order (Critical)

```python
# settings.py lines 210-251
MIDDLEWARE = [
    # 1. Multi-Tenancy (MUST BE FIRST)
    'django_tenants.middleware.main.TenantMainMiddleware',
    'tenants.middleware.TenantURLConfMiddleware',

    # 2. Security
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',

    # 3. CORS (BEFORE CommonMiddleware)
    'corsheaders.middleware.CorsMiddleware',

    # 4. Session & Common
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',

    # 5. Authentication
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'custom_account_u.middleware.Require2FAMiddleware',

    # 6. Messages & Security
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'custom_account_u.middleware.AuthSecurityMiddleware',

    # 7. Audit & History
    'simple_history.middleware.HistoryRequestMiddleware',
    'auditlog.middleware.AuditlogMiddleware',

    # 8. Content Security Policy
    'csp.middleware.CSPMiddleware',

    # 9. Rate Limiting (LAST)
    'axes.middleware.AxesMiddleware',

    # 10. Wagtail
    'wagtail.contrib.redirects.middleware.RedirectMiddleware',
]
```

### Middleware Order Rules

**MUST BE FIRST:**
1. `TenantMainMiddleware` - Sets `request.tenant` before anything else
2. `TenantURLConfMiddleware` - Fixes URL routing for tenants

**MUST COME BEFORE SESSION:**
- `SecurityMiddleware` - Sets security headers
- `CorsMiddleware` - Handles CORS preflight requests

**MUST COME AFTER AUTHENTICATION:**
- `AuditlogMiddleware` - Needs `request.user` to log who made changes
- `AuthSecurityMiddleware` - Enforces authentication policies

**MUST COME LAST:**
- `AxesMiddleware` - Needs to intercept after auth failures

### Custom Middleware

**Available but not enabled** in settings.py:

```python
# tenants/middleware.py
TenantContextMiddleware    # Adds tenant context helpers to request
TenantUsageMiddleware      # Tracks API usage for billing
TenantSecurityMiddleware   # Enforces tenant-specific security policies
TenantMigrationCheckMiddleware  # Blocks requests to unmigrated tenants
```

**To enable:** Add to MIDDLEWARE list after `TenantMainMiddleware`

---

## Caching Configuration

### Redis Caches

```python
# settings.py lines 1112-1122
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
```

**Redis Databases:**
- Database 0: Celery broker (CELERY_BROKER_URL)
- Database 1: Celery results (CELERY_RESULT_BACKEND) & Channels (REDIS_CHANNEL_URL)
- Database 2: Default cache
- Database 3: Axes brute force protection cache

**Why separate databases?**
- Isolation: Each system's data doesn't interfere
- Flushing: Can clear cache without affecting Celery/Axes
- Performance: Separate key spaces improve performance

### Session Backend

```python
# settings.py lines 1124-1126
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
```

**Why cache-backed sessions?**
- Fast: No database queries for session data
- Scalable: Redis can handle millions of sessions
- Auto-expiry: Redis TTL handles session expiration

**Trade-off:** Sessions lost if Redis crashes (acceptable for most use cases)

**Alternative (persistent sessions):**
```python
SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'
```

### Tenant-Aware Caching

```python
# core/cache/tenant_cache.py provides tenant-scoped caching
from core.cache import tenant_cache

# Automatically prefixes keys with tenant schema
tenant_cache.set('user_count', 100)  # Key: tenant:{schema}:user_count
```

---

## Static Files & Media

### Static Files Configuration

```python
# settings.py lines 365-371
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / "staticfiles"]
STATIC_ROOT = BASE_DIR / 'static'
```

**Directory Structure:**
```
zumodra/
├── staticfiles/           # Source static files (checked into git)
│   ├── assets/
│   │   ├── js/vendor/    # Alpine.js, HTMX, Chart.js
│   │   ├── css/          # Custom CSS
│   │   └── fonts/        # Web fonts
│   └── dist/             # Compiled Tailwind CSS
│       └── output.css
└── static/               # Collected static files (generated, not in git)
    └── ...               # Django collectstatic output
```

**Development vs Production:**

**Development (DEBUG=True):**
- Django serves static files from `STATICFILES_DIRS`
- No need to run `collectstatic`

**Production (DEBUG=False):**
- Run `python manage.py collectstatic` to copy all static files to `STATIC_ROOT`
- Serve static files with WhiteNoise (configured) or nginx

**WhiteNoise:**
```python
# Enabled via middleware (line 217)
'whitenoise.middleware.WhiteNoiseMiddleware',
```

WhiteNoise serves static files efficiently in production without nginx.

### Media Files Configuration

```python
# settings.py lines 373-375
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
```

**Production Recommendation: Use AWS S3**

```python
# settings.py lines 1128-1144
# AWS S3 Configuration
AWS_ACCESS_KEY_ID = env('AWS_ACCESS_KEY_ID', default='')
AWS_SECRET_ACCESS_KEY = env('AWS_SECRET_ACCESS_KEY', default='')
AWS_STORAGE_BUCKET_NAME = env('AWS_STORAGE_BUCKET_NAME', default='zumodra-media')
AWS_S3_REGION_NAME = env('AWS_S3_REGION_NAME', default='us-east-1')

# Use S3 for media storage in production
if not DEBUG and AWS_ACCESS_KEY_ID:
    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
```

**Why S3?**
- Scalable: No disk space concerns
- Fast: CDN-backed delivery
- Reliable: 99.999999999% durability
- Cost-effective: Pay only for storage used

### Content Security Policy (CSP) for Static Files

**CRITICAL:** No external CDN allowed. All assets must be local.

```python
# settings.py lines 1222-1254
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'script-src': ("'self'",),  # Only /static/, no CDN
        'style-src': ("'self'", "'unsafe-inline'"),
        'font-src': ("'self'",),
        # ... all resources must be 'self'
    }
}
```

**How to add a new JavaScript library:**

1. Download the library to `staticfiles/assets/js/vendor/`
2. Reference it in templates: `<script src="{% static 'assets/js/vendor/library.min.js' %}"></script>`
3. Do NOT use CDN links (will be blocked by CSP)

---

## Email Configuration

### SMTP Configuration

```python
# settings.py lines 429-438
EMAIL_BACKEND = env('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = env('EMAIL_HOST', default='mailhog' if DEBUG else '')
EMAIL_PORT = env.int('EMAIL_PORT', default=1025 if DEBUG else 587)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=False if DEBUG else True)
EMAIL_USE_SSL = env.bool('EMAIL_USE_SSL', default=False)
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')  # REQUIRED
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default=f"noreply@{EMAIL_DOMAIN}")
```

### Development Email (MailHog)

**MailHog** is configured for development to catch all outgoing emails:

```yaml
# docker-compose.yml
mailhog:
  image: mailhog/mailhog
  ports:
    - "8026:8025"  # Web UI
    - "1025:1025"  # SMTP
```

**Access MailHog UI:** http://localhost:8026

**Configuration:**
```bash
# .env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=mailhog
EMAIL_PORT=1025
EMAIL_USE_TLS=False
```

### Production Email Providers

**Gmail:**
```bash
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password  # Use App Password, not account password
```

**SendGrid:**
```bash
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=your-sendgrid-api-key
```

**AWS SES:**
```bash
EMAIL_BACKEND=django_ses.SESBackend
AWS_SES_REGION_NAME=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

### Console Backend (Alternative Development)

```bash
# .env
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
```

Emails will be printed to console instead of sent. Useful for debugging.

---

## Domain Configuration

Zumodra uses **centralized domain configuration** via environment variables and `core/domain.py`.

### Environment Variables

```bash
# .env

# Primary domain (without protocol)
PRIMARY_DOMAIN=zumodra.com           # Production
PRIMARY_DOMAIN=localhost             # Development (default when DEBUG=True)

# Full site URL (with protocol)
SITE_URL=https://zumodra.com         # Production
SITE_URL=http://localhost:8002       # Development

# Tenant base domain
TENANT_BASE_DOMAIN=zumodra.com       # Tenants: acme.zumodra.com
TENANT_BASE_DOMAIN=localhost         # Tenants: acme.localhost

# Optional specialized domains
API_BASE_URL=https://api.zumodra.com/api
CAREERS_BASE_DOMAIN=careers.zumodra.com
EMAIL_DOMAIN=zumodra.com
ANONYMIZED_EMAIL_DOMAIN=anonymized.zumodra.com
```

### Centralized Domain Utilities

```python
# core/domain.py provides centralized domain configuration
from core.domain import (
    get_primary_domain,      # Get PRIMARY_DOMAIN
    get_site_url,            # Get SITE_URL with protocol
    get_tenant_url,          # Build tenant-specific URL
    build_absolute_url,      # Build full URL for a path
    get_noreply_email,       # Get noreply@{domain}
    is_development_domain,   # Check if running locally
)
```

### Usage Examples

```python
# Get main site URL
site_url = get_site_url()  # https://zumodra.com

# Get tenant URL
tenant_url = get_tenant_url('acme', '/dashboard/')  # https://acme.zumodra.com/dashboard/

# Build absolute URL
api_url = build_absolute_url('/api/v1/jobs/')  # https://zumodra.com/api/v1/jobs/

# Get email address
from_email = get_noreply_email()  # noreply@zumodra.com

# Check if development
if is_development_domain(request.get_host()):
    # Running on localhost
```

### Django Site Framework Integration

The Django Site framework is auto-synced on startup:

```python
# core/apps.py - runs on startup
def ready(self):
    from django.contrib.sites.models import Site
    site_url = get_site_url()
    domain = urlparse(site_url).netloc
    Site.objects.update_or_create(
        id=settings.SITE_ID,
        defaults={'domain': domain, 'name': 'Zumodra'}
    )
```

**Manual sync:**
```bash
python manage.py sync_site_domain
```

### Security: Localhost References

**IMPORTANT:** `localhost` references in security code are **intentional** and should NOT be changed:

```python
# core/validators.py - SSRF protection
LOCALHOST_PATTERNS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    # ... intentionally blocks local addresses for security
]
```

These are security validators that **block** localhost/private IPs to prevent SSRF attacks. They are NOT domain configuration.

---

## REST API Configuration

### DRF Settings

```python
# settings.py lines 814-875
REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'auth': '5/minute',
        'token': '10/minute',
        'password': '3/minute',
    },
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning',
    'DEFAULT_VERSION': 'v1',
    'ALLOWED_VERSIONS': ['v1', 'v2'],
}
```

### JWT Configuration

```python
# settings.py lines 879-893
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}
```

### API Documentation

**Swagger UI:** http://localhost:8002/api/docs/
**ReDoc:** http://localhost:8002/api/redoc/

```python
# settings.py lines 990-1069
SPECTACULAR_SETTINGS = {
    'TITLE': 'Zumodra API',
    'DESCRIPTION': 'Multi-Tenant ATS/HR SaaS Platform REST API',
    'VERSION': '1.0.0',
    'SERVE_PERMISSIONS': ['rest_framework.permissions.IsAdminUser'],
}
```

### Rate Limiting

**Per-user throttling:**
- Anonymous: 100 requests/hour
- Authenticated: 1000 requests/hour

**Per-endpoint throttling:**
- Login/auth: 5 requests/minute
- Password reset: 3 requests/minute
- File upload: 20 requests/hour

### CORS Configuration

```python
# settings.py lines 898-918
CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=[])

if DEBUG:
    CORS_ALLOWED_ORIGINS += [
        "http://localhost:3000",  # React dev server
        "http://localhost:8080",  # Vue dev server
    ]

CORS_ALLOW_CREDENTIALS = True
```

**Production:**
```bash
# .env
CORS_ALLOWED_ORIGINS=https://app.zumodra.com,https://api.zumodra.com
```

---

## Celery Configuration

### Broker & Backend

```python
# settings.py lines 528-529
CELERY_BROKER_URL = env('CELERY_BROKER_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND', default='redis://localhost:6379/1')
```

**Production with RabbitMQ:**
```bash
# .env
CELERY_BROKER_URL=amqp://zumodra:password@rabbitmq:5672/zumodra
CELERY_RESULT_BACKEND=redis://redis:6379/1
```

**Why RabbitMQ?**
- More reliable than Redis as a broker
- Better task acknowledgment and retry handling
- Handles large task queues efficiently

### Task Routing

```python
# settings.py lines 564-588
CELERY_TASK_ROUTES = {
    'newsletter.tasks.*': {'queue': 'emails'},
    'notifications.tasks.send_*': {'queue': 'emails'},
    'finance.tasks.*': {'queue': 'payments'},
    'analytics.tasks.*': {'queue': 'analytics'},
    'ats.tasks.*': {'queue': 'ats'},
}
```

**Start workers for specific queues:**
```bash
# Email worker
celery -A zumodra worker -Q emails -n worker-emails@%h

# Payment worker
celery -A zumodra worker -Q payments -n worker-payments@%h

# Default worker (all queues)
celery -A zumodra worker -n worker-default@%h
```

### Celery Beat (Scheduled Tasks)

```python
# settings.py line 600
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'
```

**Start beat scheduler:**
```bash
celery -A zumodra beat -l info
```

**Schedule tasks via Django admin:**
- Navigate to: http://localhost:8002/admin/django_celery_beat/periodictask/
- Add periodic task with cron schedule

### Worker Configuration

```python
# settings.py lines 545-553
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_TASK_TIME_LIMIT = 3600  # 1 hour hard limit
CELERY_TASK_SOFT_TIME_LIMIT = 3300  # 55 minutes soft limit
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000
CELERY_WORKER_PREFETCH_MULTIPLIER = 4
CELERY_WORKER_CONCURRENCY = env.int('CELERY_WORKER_CONCURRENCY', default=4)
```

---

## Channels/WebSockets Configuration

### Redis Channel Layer

```python
# settings.py lines 1074-1094
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [REDIS_CHANNEL_URL],
            'capacity': 100000,  # Max messages per channel
            'expiry': 60,  # Message expiry in seconds
            'group_expiry': 86400,  # 24 hours
        },
    },
}
```

**Environment Variables:**
```bash
# .env
REDIS_CHANNEL_URL=redis://redis:6379/1
CHANNEL_REDIS_POOL_SIZE=100
WEBSOCKET_RATE_LIMIT=10  # messages per second
WEBSOCKET_MAX_FILE_MB=50  # max file upload size
```

### ASGI Application

```python
# settings.py line 280
ASGI_APPLICATION = 'zumodra.asgi.application'
```

**Start Daphne (WebSocket server):**
```bash
daphne -b 0.0.0.0 -p 8003 zumodra.asgi:application
```

**Docker Compose:**
```yaml
channels:
  image: zumodra:latest
  command: daphne -b 0.0.0.0 -p 8003 zumodra.asgi:application
  ports:
    - "8003:8003"
```

### WebSocket URL Pattern

```python
# zumodra/asgi.py
application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter([
            path("ws/chat/<room_name>/", ChatConsumer.as_asgi()),
            path("ws/notifications/", NotificationConsumer.as_asgi()),
        ])
    ),
})
```

**Connect to WebSocket:**
```javascript
const socket = new WebSocket(
    'ws://' + window.location.host + '/ws/chat/room-123/'
);
```

---

## GDAL/GeoDjango Configuration

**Added:** 2026-01-16 (recent addition)

### Windows Configuration

```python
# settings.py lines 28-34
import sys
if sys.platform == 'win32':
    GDAL_LIBRARY_PATH = str(Path(sys.prefix) / 'Lib' / 'site-packages' / 'osgeo' / 'gdal.dll')
    GEOS_LIBRARY_PATH = str(Path(sys.prefix) / 'Lib' / 'site-packages' / 'osgeo' / 'geos_c.dll')
```

**Why this is needed:**
- Windows does not include GDAL/GEOS in system PATH
- Django GeoDjango requires explicit DLL paths
- Installed via: `pip install gdal` (from wheel)

### Linux/Docker Configuration

**Linux systems typically don't need explicit paths** because GDAL/GEOS are installed system-wide:

```dockerfile
# Dockerfile
RUN apt-get update && apt-get install -y \
    gdal-bin \
    libgdal-dev \
    libgeos-dev \
    binutils
```

### Verification

```bash
# Check GDAL installation
python -c "from django.contrib.gis import gdal; print(gdal.HAS_GDAL)"  # Should print True

# Check GEOS installation
python -c "from django.contrib.gis import geos; print(geos.HAS_GEOS)"  # Should print True
```

### Common GDAL Issues

**Issue: "Could not find GDAL library"**
```bash
# Solution: Install GDAL
# Windows: Download wheel from https://www.lfd.uci.edu/~gohlke/pythonlibs/#gdal
pip install GDAL-3.4.3-cp311-cp311-win_amd64.whl

# Linux:
sudo apt-get install gdal-bin libgdal-dev python3-gdal
```

**Issue: "GDAL version mismatch"**
```bash
# Check versions
gdalinfo --version  # System GDAL
python -c "from osgeo import gdal; print(gdal.__version__)"  # Python GDAL

# Solution: Reinstall matching version
pip uninstall gdal
pip install gdal==$(gdalinfo --version | cut -d' ' -f2 | cut -d',' -f1)
```

---

## Common Pitfalls & Solutions

### 1. Template Context Processor Duplication

**Issue:** `settings.py` lines 261-273 contain duplicate context processors:

```python
'context_processors': [
    'django.template.context_processors.request',  # Line 262
    'django.contrib.auth.context_processors.auth',  # Line 263
    'django.contrib.messages.context_processors.messages',  # Line 264
    # ... other processors ...
    'django.template.context_processors.request',  # Line 271 (DUPLICATE)
    'django.contrib.auth.context_processors.auth',  # Line 272 (DUPLICATE)
    'django.contrib.messages.context_processors.messages',  # Line 273 (DUPLICATE)
],
```

**Impact:** None (Django ignores duplicates), but wastes processing time.

**Solution:** Remove lines 271-273.

### 2. DATABASE_ROUTERS Duplication

**Issue:** Database routers defined twice in settings.py:

```python
# Line 311-313
DATABASE_ROUTERS = (
    'django_tenants.routers.TenantSyncRouter',
)

# Lines 333-336 (commented out)
# DATABASE_ROUTERS = (
#     'django_tenants.routers.TenantSyncRouter',
# )
```

**Impact:** None (second is commented), but creates confusion.

**Solution:** Remove commented section.

### 3. LOGGING Configuration Duplication

**Issue:** LOGGING defined twice:

```python
# Lines 612-627 (basic logging)
LOGGING = { ... }

# Lines 931-978 (comprehensive logging)
LOGGING = { ... }
```

**Impact:** Second definition **overwrites** the first. Only the second config is active.

**Solution:** Remove the first LOGGING definition or merge them.

### 4. Missing Logs Directory

**Issue:** `LOGGING` references `BASE_DIR / 'logs' / 'django.log'` but directory may not exist.

**Current Fix:** Lines 980-982 create the directory:
```python
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)
```

**Best Practice:** Also add `logs/` to `.gitignore` and create `.gitkeep`:
```bash
echo "*.log" >> .gitignore
mkdir -p logs
touch logs/.gitkeep
```

### 5. GeoIP Path Not Configured

**Issue:** Line 609 has placeholder path:
```python
GEOIP_PATH = 'path/to/geoip_data'
```

**Impact:** GeoIP features won't work until configured.

**Solution:** Download MaxMind GeoLite2 database:
```bash
mkdir -p geoip
cd geoip
wget https://download.maxmind.com/app/geoip_download?...
```

Update settings:
```python
GEOIP_PATH = BASE_DIR / 'geoip'
```

### 6. settings_security.py Not Imported

**Issue:** `settings_security.py` defines enhanced password validators and security configs, but they're not imported into `settings.py`.

**Impact:** Enhanced security features not active.

**Solution:** Add to end of `settings.py`:
```python
# Import enhanced security settings
try:
    from .settings_security import (
        AUTH_PASSWORD_VALIDATORS,
        PASSWORD_HASHERS,
        AXES_COOLOFF_TIME,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP,
    )
except ImportError:
    pass
```

### 7. Celery Broker URL Contains Credentials

**Issue:** Line 528 may have credentials in URL:
```python
CELERY_BROKER_URL = 'amqp://user:password@rabbitmq:5672/zumodra'
```

**Security Risk:** Credentials in settings file (should be in .env)

**Solution:** Use environment variable:
```python
CELERY_BROKER_URL = env('CELERY_BROKER_URL')
```

### 8. Django Site Not Synced

**Issue:** SITE_ID=1 but Site object may not exist or have wrong domain.

**Current Fix:** `core/apps.py` auto-syncs Site on startup.

**Manual sync:**
```bash
python manage.py sync_site_domain
```

### 9. Redis Connection Issues

**Symptoms:**
- "Connection refused" errors
- Caching not working
- Celery tasks stuck

**Common Causes:**
1. Redis not running: `docker-compose ps redis`
2. Wrong REDIS_URL: Check host is `redis` (not `localhost`) in Docker
3. Redis out of memory: Check `redis-cli info memory`

**Solution:**
```bash
# Restart Redis
docker-compose restart redis

# Check Redis connection
redis-cli -h redis -p 6379 ping  # Should respond "PONG"

# Check memory
redis-cli -h redis -p 6379 info memory
```

### 10. SECRET_KEY Not Set

**Symptoms:**
- "ImproperlyConfigured: SECRET_KEY must be set"
- Application won't start

**Solution:**
```bash
# Generate a new key
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Add to .env
echo "SECRET_KEY=your-generated-key-here" >> .env
```

---

## Production Checklist

Before deploying to production, verify all these settings:

### Security

- [ ] `DEBUG=False` in .env
- [ ] `SECRET_KEY` set to strong random value (50+ characters)
- [ ] `ALLOWED_HOSTS` includes production domain (no wildcards)
- [ ] `SESSION_COOKIE_SECURE=True`
- [ ] `CSRF_COOKIE_SECURE=True`
- [ ] `SECURE_SSL_REDIRECT=True`
- [ ] `SECURE_HSTS_SECONDS=31536000`
- [ ] Database password is strong (16+ characters)
- [ ] Redis password is set (not default)
- [ ] Stripe keys are production keys (not test keys)

### Performance

- [ ] Redis configured for caching
- [ ] Celery workers running with RabbitMQ
- [ ] Celery beat scheduler running
- [ ] Static files collected: `python manage.py collectstatic`
- [ ] WhiteNoise configured for static file serving
- [ ] Database connection pooling configured
- [ ] GZIP compression enabled (nginx/Cloudflare)

### Reliability

- [ ] Database backups configured (daily minimum)
- [ ] Error monitoring configured (Sentry)
- [ ] Logging configured and working
- [ ] Health check endpoint responding
- [ ] Uptime monitoring configured (UptimeRobot, Pingdom)

### Email

- [ ] Email backend configured (not console backend)
- [ ] SMTP credentials set and tested
- [ ] DEFAULT_FROM_EMAIL set to production domain
- [ ] SPF/DKIM/DMARC records configured for email domain

### Multi-Tenancy

- [ ] Public schema migrated: `python manage.py migrate_schemas --shared`
- [ ] Demo tenant created and tested
- [ ] Tenant domains configured in DNS
- [ ] Tenant migration verification enabled

### Storage

- [ ] Media files configured for S3 (or equivalent)
- [ ] S3 bucket has correct permissions
- [ ] Static files CDN configured (optional but recommended)

### Monitoring

- [ ] Django admin accessible and secured
- [ ] API documentation accessible to admins only
- [ ] Log rotation configured (logrotate)
- [ ] Disk space monitoring configured
- [ ] Memory usage monitoring configured

### Testing

- [ ] All tests passing: `pytest`
- [ ] Coverage above 60%: `pytest --cov`
- [ ] Security tests passing: `pytest -m security`
- [ ] Load testing completed
- [ ] Smoke test on production environment passed

---

## Quick Reference

### Environment Variable Defaults

| Variable | Development Default | Production Default | Required? |
|----------|--------------------|--------------------|-----------|
| `DEBUG` | `True` | `False` | No |
| `SECRET_KEY` | None | None | **YES** |
| `DB_HOST` | `localhost` | `localhost` | No |
| `DB_PORT` | `5432` | `5432` | No |
| `DB_NAME` | `zumodra` | `zumodra` | No |
| `DB_USER` | `postgres` | `postgres` | No |
| `DB_PASSWORD` | None | None | **YES** |
| `REDIS_URL` | `redis://127.0.0.1:6379/0` | `redis://127.0.0.1:6379/0` | No |
| `EMAIL_HOST_PASSWORD` | None | None | **YES** |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | None | **YES (prod)** |

### Port Reference

| Service | Internal Port | External Port (Docker) | Description |
|---------|--------------|----------------------|-------------|
| Django (web) | 8000 | 8002 | Main application |
| Daphne (channels) | 8003 | 8003 | WebSocket server |
| PostgreSQL | 5432 | 5434 | Database |
| Redis | 6379 | 6380 | Cache/Sessions/Celery |
| RabbitMQ AMQP | 5672 | 5673 | Message broker |
| RabbitMQ Mgmt | 15672 | 15673 | Management UI |
| MailHog SMTP | 1025 | 1025 | Email (dev) |
| MailHog Web | 8025 | 8026 | Email UI (dev) |
| Nginx | 80 | 8084 | Reverse proxy |

### Command Reference

```bash
# Migrations
python manage.py migrate_schemas --shared    # Public schema
python manage.py migrate_schemas --tenant    # All tenants
python manage.py migrate_schemas --schema=demo  # Specific tenant

# Tenant Management
python manage.py create_tenant acme "ACME Corp" admin@acme.com
python manage.py bootstrap_demo_tenant
python manage.py setup_demo_data --num-jobs 20

# Static Files
python manage.py collectstatic --no-input

# Health Check
python manage.py health_check --full

# Celery
celery -A zumodra worker -l info
celery -A zumodra beat -l info

# Daphne
daphne -b 0.0.0.0 -p 8003 zumodra.asgi:application
```

---

## Support

For additional help:
- **Documentation:** `/docs` directory
- **Issues:** Check `docs/TROUBLESHOOTING.md`
- **Migrations:** Check `docs/MIGRATIONS_FIX.md`
- **Security:** Check `zumodra/settings_security.py` for reference configs

**Last Updated:** 2026-01-16
**Maintained By:** Backend Lead Team
