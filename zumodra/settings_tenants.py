"""
Django-Tenants Configuration for Zumodra
Multi-Tenant Jobs/HR SaaS Platform

This file contains the tenant-specific settings that override/extend base settings.
Import this at the end of settings.py when multi-tenancy is enabled.
"""

# ============================================
# DJANGO-TENANTS CONFIGURATION
# ============================================

# Shared apps run on public schema (shared across all tenants)
SHARED_APPS = [
    'django_tenants',  # Must be first

    # Django core apps needed in public schema
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    'django.contrib.sites',

    # Tenant management
    'tenants',

    # Shared third-party apps
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_filters',
    'drf_spectacular',  # API documentation
    'user_agents',  # User agent parsing
    'analytical',  # Analytics tracking
    'django_celery_beat',  # Scheduled tasks

    # Core identity & verification (shared across tenants - PUBLIC schema)
    'core_identity',

    # Integrations (shared - webhooks dispatched from public schema)
    'integrations',

    # Core utilities (shared)
    'core',
    'security',
    'ai_matching',  # AI matching engine
    # REMOVED (2026-01-17): 'marketing' merged into 'marketing_campaigns' (now in TENANT_APPS)

    # REMOVED (2026-01-17): 'newsletter' merged into 'marketing_campaigns' (now in TENANT_APPS)

    # Platform Billing (PUBLIC schema - Zumodra charges tenants)
    'billing',  # Platform subscription management

    # MULTI-TENANT CONFIGURATION (2026-01-16):
    # Wagtail CMS apps are in SHARED_APPS (public schema only) because:
    # - Only the system admin (public schema) publishes blog posts
    # - Individual tenants do not need blog/CMS functionality
    # - This prevents creating unnecessary Wagtail tables in every tenant schema
    # - Reduces database bloat and improves tenant provisioning speed
    'wagtail.contrib.forms',
    'wagtail.contrib.redirects',
    'wagtail.embeds',
    'wagtail.sites',
    'wagtail.users',
    'wagtail.snippets',
    'wagtail.documents',
    'wagtail.images',
    'wagtail.search',
    'wagtail.admin',
    'wagtail_localize',
    'wagtail_localize.locales',
    'wagtail',

    # Blog app (shared - only system admin publishes blog posts)
    'blog',

    # PUBLIC CATALOG APPS (shared - cross-tenant browsing without tenant context)
    'jobs_public',  # Public job catalog for browsing
    'services_public',  # Public service/provider catalog for marketplace
    'projects_public',  # Public project catalog for cross-tenant project browsing
]

# Tenant-specific apps (each tenant gets their own tables)
TENANT_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.admin',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.sites',
    'django.contrib.humanize',
    'django.contrib.sitemaps',
    'django.contrib.gis',

    # Authentication & 2FA
    'allauth',
    'allauth.mfa',  # Built-in MFA support (TOTP, WebAuthn) in allauth 65.3.0+
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.github',

    # Third-party tenant apps
    'widget_tweaks',
    'tinymce',
    'leaflet',
    'auditlog',
    'import_export',
    'crispy_forms',
    'sorl.thumbnail',
    'phonenumber_field',
    'taggit',
    'modelcluster',

    # Security
    'admin_honeypot',
    'csp',
    'axes',

    # Async tasks
    'django_q',
    'django_extensions',

    # REMOVED (2026-01-16): Wagtail CMS apps moved to SHARED_APPS (public schema only)
    # Tenants do not need blog/CMS functionality - only system admin publishes blog posts

    # Real-time
    'channels',

    # Existing Zumodra apps (tenant-scoped)
    'main',
    'messages_sys',
    'configurations',
    'dashboard',
    'services',  # Ongoing service offerings (marketplace)
    'projects',  # Time-bound project missions with deliverables
    'api',
    'notifications',
    'analytics',
    'marketing_campaigns',  # Unified marketing & campaigns (tenant-aware, replaces marketing + newsletter)

    # Finance Apps (TENANT schema - tenant payment processing)
    'payments',          # Tenant payment processing with multi-currency
    'subscriptions',     # Tenant's own subscription products (SaaS tenants selling to their clients)
    'escrow',           # Marketplace escrow for services/projects
    'stripe_connect',   # Stripe Connect for freelancer payouts
    'payroll',          # Employee payroll processing
    'expenses',         # Business expense tracking
    'tax',              # Tax calculation and Avalara integration
    'accounting',       # QuickBooks/Xero integration
    'finance_webhooks', # Webhook handling for finance integrations

    # Interview Scheduling (renamed from appointment)
    'interviews',  # Interview scheduling and appointment booking system

    # NEW JOBS/HR Apps
    'tenant_profiles',  # Tenant-specific user profiles & membership (renamed from accounts - Phase 10)
    'jobs',  # Jobs & Recruitment (renamed from ats - Phase 7)
    'hr_core',  # HR operations
    'careers',  # Career pages (tenant-specific, TODO: PublicJobCatalog needed for cross-tenant public API)
]

# Combine for INSTALLED_APPS
INSTALLED_APPS = list(SHARED_APPS) + [app for app in TENANT_APPS if app not in SHARED_APPS]

# Tenant and Domain models
TENANT_MODEL = "tenants.Tenant"
TENANT_DOMAIN_MODEL = "tenants.Domain"

# Public schema name
PUBLIC_SCHEMA_NAME = 'public'

# TENANT NOT FOUND BEHAVIOR
# This setting controls how the middleware handles requests to non-existent tenants
# (e.g., accessing nonexistent.zumodra.com)
#
# SHOW_PUBLIC_IF_NO_TENANT_FOUND = True  (DEFAULT - Development/Testing)
#   - Falls back to public schema when no tenant is found
#   - Allows access to marketing/public pages on any subdomain
#   - Prevents 404 errors during development
#   - RECOMMENDED for: development, testing, public landing pages
#
# SHOW_PUBLIC_IF_NO_TENANT_FOUND = False (Production)
#   - Returns HTTP 404 when tenant is not found
#   - Strict tenant resolution - only registered tenants can be accessed
#   - Prevents information leakage via tenant enumeration
#   - RECOMMENDED for: production, when you want to protect tenant existence
#
# See tenants/middleware.py for detailed error handling documentation
SHOW_PUBLIC_IF_NO_TENANT_FOUND = True

# Database router for tenant isolation
DATABASE_ROUTERS = [
    'django_tenants.routers.TenantSyncRouter',
]

# Middleware - TenantMainMiddleware MUST be first
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',  # MUST BE FIRST
    'tenants.middleware.TenantContextMiddleware',  # Custom tenant context
    'tenants.middleware.TenantMigrationCheckMiddleware',  # CRITICAL: Block unmigrated tenants

    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Static files
    'corsheaders.middleware.CorsMiddleware',  # CORS
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'core_identity.middleware.UnifiedMFAEnforcementMiddleware',  # 30-day MFA grace period
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'core_identity.middleware.AuthSecurityMiddleware',  # Brute force protection
    'auditlog.middleware.AuditlogMiddleware',
    'csp.middleware.CSPMiddleware',
    'axes.middleware.AxesMiddleware',
    # Wagtail middleware: Only affects public schema (admin blog) - safe for tenant requests
    'wagtail.contrib.redirects.middleware.RedirectMiddleware',

    'tenants.middleware.TenantUsageMiddleware',  # Usage tracking
]

# Database configuration for multi-tenancy
DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.postgresql_backend',
        'NAME': 'zumodra',
        'USER': 'postgres',
        'PASSWORD': '',  # Set via environment
        'HOST': 'localhost',
        'PORT': '5433',
        'OPTIONS': {
            'connect_timeout': 10,
        },
    }
}

# Original backend for GIS operations
ORIGINAL_BACKEND = "django.contrib.gis.db.backends.postgis"

# ============================================
# TENANT-AWARE CACHES
# ============================================

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://localhost:6379/0',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'KEY_PREFIX': 'zumodra',
        },
        'KEY_FUNCTION': 'django_tenants.cache.make_key',
        'REVERSE_KEY_FUNCTION': 'django_tenants.cache.reverse_key',
    }
}

# ============================================
# TENANT SETTINGS
# ============================================

# Base domain for tenant subdomains
TENANT_BASE_DOMAIN = 'zumodra.com'

# Default trial period in days
TENANT_TRIAL_DAYS = 14

# File storage path pattern (includes tenant schema)
DEFAULT_FILE_STORAGE = 'tenants.storage.TenantFileSystemStorage'

# ============================================
# LOGGING FOR TENANTS
# ============================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'tenant_format': {
            'format': '[{asctime}] [{levelname}] [tenant:{tenant}] {name}: {message}',
            'style': '{',
        },
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'filters': {
        'tenant_context': {
            '()': 'tenants.logging.TenantContextFilter',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'tenant_format',
            'filters': ['tenant_context'],
        },
        'file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/zumodra.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django_tenants': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'tenants': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'jobs': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'hr_core': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
    },
}
