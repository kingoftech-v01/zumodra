"""
Django Test Settings for Zumodra Project

This module contains test-specific settings that override the main settings
for faster and more isolated test execution. Use this configuration when
running pytest or Django's test runner.

Usage:
    pytest --ds=zumodra.settings_test
    python manage.py test --settings=zumodra.settings_test
"""

from .settings import *  # noqa: F401, F403

# =============================================================================
# TEST ENVIRONMENT CONFIGURATION
# =============================================================================

DEBUG = False
TESTING = True

# Use a faster password hasher for tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# Use PostgreSQL for tests with PostGIS support
# The ai_matching app uses PostgreSQL-specific features like ArrayField
import os

DATABASES = {
    'default': {
        'ENGINE': 'django.contrib.gis.db.backends.postgis',
        'NAME': os.environ.get('TEST_DB_NAME', 'zumodra_test'),
        'USER': os.environ.get('TEST_DB_USER', os.environ.get('DB_USER', 'postgres')),
        'PASSWORD': os.environ.get('TEST_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'zumodra_dev_password')),
        'HOST': os.environ.get('TEST_DB_HOST', os.environ.get('DB_HOST', 'localhost')),
        'PORT': os.environ.get('TEST_DB_PORT', os.environ.get('DB_PORT', '5432')),
        'TEST': {
            'NAME': 'zumodra_test',
        },
    }
}

# Disable django-tenants routers for unit testing (all tables in public schema)
DATABASE_ROUTERS = []

# =============================================================================
# CACHING CONFIGURATION
# =============================================================================

# Use local memory cache for tests
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    },
    'axes': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'axes-cache',
    },
}

# =============================================================================
# CELERY CONFIGURATION
# =============================================================================

# Execute tasks synchronously during tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = 'memory://'
CELERY_RESULT_BACKEND = 'cache+memory://'

# =============================================================================
# CHANNEL LAYERS CONFIGURATION
# =============================================================================

# Use in-memory channel layer for tests
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}

# =============================================================================
# EMAIL CONFIGURATION
# =============================================================================

# Use in-memory email backend for tests
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# =============================================================================
# MEDIA & STATIC FILES
# =============================================================================

# Use temporary directories for media during tests
import tempfile
MEDIA_ROOT = tempfile.mkdtemp()
STATIC_ROOT = tempfile.mkdtemp()

# =============================================================================
# SECURITY SETTINGS
# =============================================================================

# Disable security features that slow down tests
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Disable axes rate limiting in tests
AXES_ENABLED = False
AXES_FAILURE_LIMIT = 100000

# =============================================================================
# AUTHENTICATION SETTINGS
# =============================================================================

# Disable 2FA requirement for tests
ALLAUTH_2FA_FORCE_2FA = False
TWO_FACTOR_MANDATORY = False

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Minimal logging during tests
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'null': {
            'class': 'logging.NullHandler',
        },
    },
    'root': {
        'handlers': ['null'],
        'level': 'CRITICAL',
    },
    'loggers': {
        'django': {
            'handlers': ['null'],
            'level': 'CRITICAL',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['null'],
            'level': 'CRITICAL',
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['null'],
            'level': 'CRITICAL',
            'propagate': False,
        },
    },
}

# =============================================================================
# THIRD-PARTY SERVICE MOCKING
# =============================================================================

# Stripe test keys
STRIPE_SECRET_KEY = 'sk_test_mock_key_for_testing'
STRIPE_PUBLIC_KEY = 'pk_test_mock_key_for_testing'

# Twilio test credentials
TWILIO_ACCOUNT_SID = 'test_account_sid'
TWILIO_AUTH_TOKEN = 'test_auth_token'
TWILIO_PHONE_NUMBER = '+15551234567'

# OpenAI test key
OPENAI_API_KEY = 'sk-test-mock-key-for-testing'

# =============================================================================
# MIDDLEWARE ADJUSTMENTS
# =============================================================================

# Remove middleware that may interfere with tests
MIDDLEWARE = [m for m in MIDDLEWARE if m not in [
    'django_tenants.middleware.main.TenantMainMiddleware',
    'csp.middleware.CSPMiddleware',
    'axes.middleware.AxesMiddleware',
    'simple_history.middleware.HistoryRequestMiddleware',
    'auditlog.middleware.AuditlogMiddleware',
]]

# =============================================================================
# INSTALLED APPS ADJUSTMENTS
# =============================================================================

# Remove django_tenants for unit tests (all tables in single schema)
INSTALLED_APPS = [app for app in INSTALLED_APPS if app not in [
    'django_tenants',
]]

# =============================================================================
# REST FRAMEWORK TEST SETTINGS
# =============================================================================

REST_FRAMEWORK['TEST_REQUEST_DEFAULT_FORMAT'] = 'json'
REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES'] = []  # Disable throttling in tests
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] = {}

# =============================================================================
# FEATURE FLAGS FOR TESTING
# =============================================================================

FEATURE_FLAGS = {
    'ENABLE_2FA': False,
    'ENABLE_ESCROW': True,
    'ENABLE_WEBSOCKETS': False,
    'ENABLE_AI_MATCHING': False,
    'ENABLE_SMS_NOTIFICATIONS': False,
}

# =============================================================================
# PYTEST-DJANGO CONFIGURATION
# =============================================================================

# pytest.ini or conftest.py should contain:
# [pytest]
# DJANGO_SETTINGS_MODULE = zumodra.settings_test
# python_files = tests.py test_*.py *_tests.py

# =============================================================================
# TEST FIXTURES CONFIGURATION
# =============================================================================

# Factory Boy settings
FACTORY_BOY_RANDOM_SEED = 12345

# Faker locale
FAKER_LOCALE = 'en_US'

# =============================================================================
# WAGTAIL TEST SETTINGS
# =============================================================================

WAGTAIL_SITE_NAME = 'Zumodra Test'
WAGTAILADMIN_BASE_URL = 'http://testserver'

# =============================================================================
# DJANGO Q TEST SETTINGS
# =============================================================================

Q_CLUSTER = {
    'name': 'zumodra-test',
    'workers': 1,
    'timeout': 10,
    'retry': 20,
    'queue_limit': 10,
    'bulk': 5,
    'orm': 'default',
    'sync': True,  # Execute tasks synchronously in tests
}
USE_DJANGO_Q_FOR_EMAILS = False

# =============================================================================
# APPOINTMENT TEST SETTINGS
# =============================================================================

APPOINTMENT_START_TIME = 8
APPOINTMENT_END_TIME = 18
