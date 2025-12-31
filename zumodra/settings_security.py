"""
Security Settings for Zumodra

Comprehensive security configuration for the multi-tenant ATS/HR SaaS platform.
Import these settings in your main settings.py:

    from zumodra.settings_security import *

Or selectively import specific configurations:

    from zumodra.settings_security import (
        AXES_SETTINGS,
        PASSWORD_VALIDATORS,
        SESSION_SECURITY,
    )

This module provides:
- Django-Axes configuration (brute force protection)
- CSRF settings
- Session security
- Password validators
- Secure cookie settings
- Content Security Policy defaults
- Security middleware configuration
"""

import os
from datetime import timedelta

# =============================================================================
# DJANGO-AXES CONFIGURATION
# =============================================================================
# Brute force protection - locks out after failed login attempts
# Documentation: https://django-axes.readthedocs.io/

# Number of failed login attempts before lockout
AXES_FAILURE_LIMIT = 5

# Lockout duration in hours (None = until manual unlock)
AXES_COOLOFF_TIME = timedelta(hours=1)

# Lock based on combination of username and IP
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True

# Also lock based on IP alone after many failures
AXES_LOCK_OUT_BY_USER_OR_IP = False

# Reset failure count on successful login
AXES_RESET_ON_SUCCESS = True

# Use cache backend for storing failure attempts (faster than database)
AXES_HANDLER = 'axes.handlers.cache.AxesCacheHandler'
AXES_CACHE = 'axes'

# Whitelist localhost for development
AXES_NEVER_LOCKOUT_WHITELIST = [
    '127.0.0.1',
    '::1',
    'localhost',
]

# Enable verbose logging for debugging
AXES_VERBOSE = True

# Use username as the only credential for lockout tracking
AXES_USERNAME_FORM_FIELD = 'username'

# Callable to get the lockout response (can customize the error page)
# AXES_LOCKOUT_CALLABLE = 'custom_account_u.views.lockout_response'

# IP address header for reverse proxy setups
AXES_META_PRECEDENCE_ORDER = [
    'HTTP_X_FORWARDED_FOR',
    'HTTP_X_REAL_IP',
    'REMOTE_ADDR',
]

# Only consider first IP in X-Forwarded-For chain
AXES_PROXY_COUNT = 1

# Enable AXES for API endpoints too
AXES_ENABLE_ADMIN = True

# Store access attempt records in database for audit
AXES_ACCESS_ATTEMPT_LOG = True

# How long to keep access attempt records (in days)
AXES_SENSITIVE_PARAMETERS = ['password', 'token', 'secret']


# =============================================================================
# CSRF PROTECTION
# =============================================================================

# CSRF cookie settings
CSRF_COOKIE_NAME = 'zumodra_csrftoken'
CSRF_COOKIE_AGE = 60 * 60 * 24 * 7  # 1 week
CSRF_COOKIE_HTTPONLY = False  # Must be False for AJAX requests
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_USE_SESSIONS = False

# CSRF header name for AJAX requests
CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'

# Trusted origins for CSRF (add your production domains)
CSRF_TRUSTED_ORIGINS = [
    'https://zumodra.com',
    'https://*.zumodra.com',
]

# CSRF failure view
CSRF_FAILURE_VIEW = 'django.views.csrf.csrf_failure'


# =============================================================================
# SESSION SECURITY
# =============================================================================

# Session engine (cache-backed for performance)
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# Session cookie settings
SESSION_COOKIE_NAME = 'zumodra_session'
SESSION_COOKIE_AGE = 60 * 60 * 24 * 14  # 2 weeks
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# Expire session when browser closes (set to False for persistent sessions)
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# Save session on every request (keeps session alive during activity)
SESSION_SAVE_EVERY_REQUEST = True

# Session expiry warning (optional, for UI notification)
SESSION_EXPIRY_WARNING_SECONDS = 300  # 5 minutes before expiry

# Minimum session ID length (security measure)
SESSION_COOKIE_PATH = '/'

# Session serializer (JSON is more secure than pickle)
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'


# =============================================================================
# PASSWORD VALIDATORS
# =============================================================================
# Strong password policy with NIST guidelines

AUTH_PASSWORD_VALIDATORS = [
    {
        # Prevents passwords similar to user attributes
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
        'OPTIONS': {
            'user_attributes': ('username', 'email', 'first_name', 'last_name'),
            'max_similarity': 0.7,
        }
    },
    {
        # Minimum length requirement (NIST recommends 8+)
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 10,  # Strong: 10+ characters
        }
    },
    {
        # Prevents common passwords
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        # Prevents all-numeric passwords
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    # Custom validators for enterprise requirements
    {
        # Requires mixed case
        'NAME': 'core.security.password_validators.MixedCaseValidator',
    },
    {
        # Requires at least one number
        'NAME': 'core.security.password_validators.NumberValidator',
    },
    {
        # Requires at least one special character
        'NAME': 'core.security.password_validators.SpecialCharacterValidator',
    },
    {
        # Prevents passwords containing username
        'NAME': 'core.security.password_validators.NoUsernameValidator',
    },
]

# Password hashing algorithm (Argon2 is recommended, PBKDF2 is default)
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]


# =============================================================================
# SECURE COOKIE SETTINGS
# =============================================================================
# These are automatically applied in production (DEBUG=False)

# Secure cookies (HTTPS only) - set in production
SECURE_COOKIE_SETTINGS = {
    'SESSION_COOKIE_SECURE': True,
    'CSRF_COOKIE_SECURE': True,
}

# HTTP Strict Transport Security
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Redirect HTTP to HTTPS
SECURE_SSL_REDIRECT = True

# Prevent browser from guessing content types
SECURE_CONTENT_TYPE_NOSNIFF = True

# Enable browser XSS filtering
SECURE_BROWSER_XSS_FILTER = True

# Prevent clickjacking
X_FRAME_OPTIONS = 'DENY'

# Referrer policy
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Cross-origin opener policy
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'


# =============================================================================
# CONTENT SECURITY POLICY
# =============================================================================
# Used by django-csp middleware 4.0+
# This provides default secure settings; override in main settings.py as needed

CONTENT_SECURITY_POLICY_DEFAULTS = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'",),
        'style-src': ("'self'",),
        'img-src': ("'self'", "data:", "https:"),
        'font-src': ("'self'",),
        'connect-src': ("'self'", "wss:"),
        'frame-src': ("'none'",),
        'object-src': ("'none'",),
        'base-uri': ("'self'",),
        'form-action': ("'self'",),
        'frame-ancestors': ("'none'",),
        'upgrade-insecure-requests': True,
    }
}

# Report-only mode for testing (set to False in production after testing)
# CONTENT_SECURITY_POLICY_REPORT_ONLY = True


# =============================================================================
# RATE LIMITING
# =============================================================================

# DRF throttle rates
REST_FRAMEWORK_THROTTLE_RATES = {
    'anon': '100/hour',
    'user': '1000/hour',
    'ip_rate': '10/minute',
    'user_rate': '100/minute',
    'sensitive': '5/minute',
    'burst': '5/second',
}

# Custom rate limits
DRF_THROTTLE_IP_RATE = '10/minute'
DRF_THROTTLE_USER_RATE = '100/minute'

# Brute force protection settings
BRUTE_FORCE_LOCKOUT_THRESHOLDS = [
    (3, 60),      # 3 failures: 1 minute lockout
    (5, 300),     # 5 failures: 5 minute lockout
    (10, 1800),   # 10 failures: 30 minute lockout
    (20, 86400),  # 20 failures: 24 hour lockout
]


# =============================================================================
# SECURITY HEADERS MIDDLEWARE CONFIGURATION
# =============================================================================

SECURITY_HEADERS = {
    # Content Security Policy
    'CSP_ENABLED': True,
    'CSP_REPORT_ONLY': False,
    'CSP_REPORT_URI': None,
    'CSP_DIRECTIVES': {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'"],
        'connect-src': ["'self'", "wss:"],
        'frame-src': ["'none'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': [],
    },

    # HSTS
    'HSTS_ENABLED': True,
    'HSTS_SECONDS': 31536000,  # 1 year
    'HSTS_INCLUDE_SUBDOMAINS': True,
    'HSTS_PRELOAD': True,

    # Other headers
    'X_FRAME_OPTIONS': 'DENY',
    'REFERRER_POLICY': 'strict-origin-when-cross-origin',

    # Paths excluded from strict CSP
    'CSP_EXCLUDE_PATHS': [
        '/admin/',
        '/api/docs/',
        '/wagtail/',
    ],
}


# =============================================================================
# API SECURITY CONFIGURATION
# =============================================================================

API_SECURITY = {
    'REQUIRE_CONTENT_TYPE': True,
    'MAX_BODY_SIZE': 10 * 1024 * 1024,  # 10MB
    'REQUIRE_API_KEY': False,
    'ALLOWED_CONTENT_TYPES': [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
    ],
}


# =============================================================================
# HONEYPOT CONFIGURATION
# =============================================================================

HONEYPOT_MIN_FORM_TIME = 3  # Minimum seconds for form submission
HONEYPOT_MAX_FORM_TIME = 3600  # Maximum seconds (1 hour)
HONEYPOT_TRACKING_TIMEOUT = 86400  # 24 hours

# Paths protected by honeypot middleware
HONEYPOT_PROTECTED_PATHS = [
    '/contact/',
    '/register/',
    '/api/auth/',
    '/accounts/',
]


# =============================================================================
# FILE UPLOAD SECURITY
# =============================================================================

# Maximum upload size
SECURITY_MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB

# Allowed file extensions
SECURITY_ALLOWED_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.csv', '.json', '.xml',
    '.zip', '.rar', '.7z', '.gz',
}

# Enable virus scanning (requires ClamAV or similar)
SECURITY_VIRUS_SCAN_ENABLED = False
SECURITY_CLAMAV_SOCKET = '/var/run/clamav/clamd.ctl'


# =============================================================================
# LOGGING CONFIGURATION FOR SECURITY
# =============================================================================

SECURITY_LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'security': {
            'format': '[SECURITY] {asctime} {levelname} {name} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'security_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/security.log',
            'maxBytes': 10 * 1024 * 1024,  # 10MB
            'backupCount': 10,
            'formatter': 'security',
        },
        'security_console': {
            'level': 'WARNING',
            'class': 'logging.StreamHandler',
            'formatter': 'security',
        },
    },
    'loggers': {
        'security': {
            'handlers': ['security_file', 'security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security.authentication': {
            'handlers': ['security_file', 'security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security.rate_limiting': {
            'handlers': ['security_file', 'security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security.honeypot': {
            'handlers': ['security_file', 'security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security.validators': {
            'handlers': ['security_file', 'security_console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'security.brute_force': {
            'handlers': ['security_file', 'security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security.login_tracker': {
            'handlers': ['security_file', 'security_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'axes': {
            'handlers': ['security_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


# =============================================================================
# TWO-FACTOR AUTHENTICATION
# =============================================================================

# Enforce 2FA for all users
ALLAUTH_2FA_FORCE_2FA = True
TWO_FACTOR_MANDATORY = True

# 2FA token validity period
OTP_TOTP_ISSUER = 'Zumodra'
OTP_TOTP_INTERVAL = 30  # Token refresh interval in seconds

# Backup codes
OTP_STATIC_THROTTLE_FACTOR = 1  # Rate limit backup code attempts


# =============================================================================
# JWT SECURITY (for REST API)
# =============================================================================

SIMPLE_JWT_SECURITY = {
    # Short access token lifetime
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),

    # Longer refresh token lifetime
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),

    # Rotate refresh tokens on use
    'ROTATE_REFRESH_TOKENS': True,

    # Blacklist old refresh tokens
    'BLACKLIST_AFTER_ROTATION': True,

    # Update last login on token refresh
    'UPDATE_LAST_LOGIN': True,

    # Algorithm
    'ALGORITHM': 'HS256',

    # Token type
    'AUTH_HEADER_TYPES': ('Bearer',),

    # Audience/Issuer claims for additional security
    'AUDIENCE': 'zumodra-api',
    'ISSUER': 'zumodra',
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def apply_production_security(settings_module):
    """
    Apply production security settings to a settings module.

    Usage in settings.py:
        from zumodra.settings_security import apply_production_security
        apply_production_security(globals())
    """
    if not settings_module.get('DEBUG', False):
        settings_module['SESSION_COOKIE_SECURE'] = True
        settings_module['CSRF_COOKIE_SECURE'] = True
        settings_module['SECURE_SSL_REDIRECT'] = True
        settings_module['SECURE_HSTS_SECONDS'] = 31536000
        settings_module['SECURE_HSTS_INCLUDE_SUBDOMAINS'] = True
        settings_module['SECURE_HSTS_PRELOAD'] = True
        settings_module['SECURE_CONTENT_TYPE_NOSNIFF'] = True
        settings_module['SECURE_BROWSER_XSS_FILTER'] = True
        settings_module['X_FRAME_OPTIONS'] = 'DENY'


def get_security_middleware():
    """
    Get list of security middleware to add to MIDDLEWARE setting.

    Usage in settings.py:
        from zumodra.settings_security import get_security_middleware
        MIDDLEWARE += get_security_middleware()
    """
    return [
        'api.middleware.SecurityHeadersMiddleware',
        'api.middleware.APISecurityMiddleware',
        'core.security.honeypot.HoneypotMiddleware',
    ]
