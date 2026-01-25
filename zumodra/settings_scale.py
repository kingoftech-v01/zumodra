"""
Zumodra Scale Settings - Production Configuration for 1M+ Users

This module extends base settings with optimizations for high-traffic:
- Database connection pooling (PgBouncer configuration)
- Redis cluster settings for caching and sessions
- Multi-tier cache configuration
- Session backend optimization
- ASGI async settings

Import this in production with:
    from zumodra.settings_scale import *
"""

import os
from zumodra.settings import *  # noqa: F401, F403

# =============================================================================
# DATABASE CONNECTION POOLING (PgBouncer)
# =============================================================================

# PgBouncer connection settings
# PgBouncer should be configured in transaction pooling mode
DATABASES['default'].update({
    # Connect to PgBouncer instead of PostgreSQL directly
    'HOST': env('PGBOUNCER_HOST', default=env('DB_HOST', default='localhost')),
    'PORT': env('PGBOUNCER_PORT', default='6432'),

    # Connection settings optimized for pooling
    'CONN_MAX_AGE': 0,  # Let PgBouncer manage connection lifetime
    'CONN_HEALTH_CHECKS': True,  # Verify connections are alive

    'OPTIONS': {
        # Disable prepared statements (required for transaction pooling)
        'options': '-c statement_timeout=30000',  # 30 second query timeout

        # Connection pool settings (Django-level)
        'connect_timeout': 10,

        # SSL in production
        'sslmode': env('DB_SSL_MODE', default='prefer'),
    },
})

# Add read replica for read-heavy operations
if env.bool('USE_READ_REPLICA', default=False):
    DATABASES['replica'] = {
        'ENGINE': 'django_tenants.postgresql_backend',
        'NAME': env('DB_REPLICA_NAME', default=env('DB_DEFAULT_NAME', default='zumodra')),
        'USER': env('DB_REPLICA_USER', default=env('DB_USER', default='postgres')),
        'PASSWORD': env('DB_REPLICA_PASSWORD', default=env('DB_PASSWORD')),
        'HOST': env('DB_REPLICA_HOST', default='localhost'),
        'PORT': env('DB_REPLICA_PORT', default='5433'),
        'CONN_MAX_AGE': 0,
        'OPTIONS': {
            'options': '-c statement_timeout=60000',
        },
    }

    # Database router for read/write splitting
    DATABASE_ROUTERS = [
        'core.db.routers.ReadReplicaRouter',
        'django_tenants.routers.TenantSyncRouter',
    ]


# =============================================================================
# REDIS CLUSTER SETTINGS
# =============================================================================

# Primary Redis URL (or cluster endpoint)
REDIS_URL = env('REDIS_URL', default='redis://127.0.0.1:6379')

# Redis Sentinel configuration (for high availability)
REDIS_SENTINELS = env.list('REDIS_SENTINELS', default=[])
REDIS_MASTER_NAME = env('REDIS_MASTER_NAME', default='mymaster')

# Connection pool settings
REDIS_MAX_CONNECTIONS = env.int('REDIS_MAX_CONNECTIONS', default=100)
REDIS_SOCKET_TIMEOUT = env.int('REDIS_SOCKET_TIMEOUT', default=5)
REDIS_SOCKET_CONNECT_TIMEOUT = env.int('REDIS_SOCKET_CONNECT_TIMEOUT', default=5)


# =============================================================================
# MULTI-TIER CACHE CONFIGURATION
# =============================================================================

CACHES = {
    # Hot cache: Short TTL, high frequency data
    # API responses, session data, rate limits
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'{REDIS_URL}/0',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_CLASS': 'redis.connection.BlockingConnectionPool',
            'CONNECTION_POOL_CLASS_KWARGS': {
                'max_connections': REDIS_MAX_CONNECTIONS,
                'timeout': 20,
            },
            'SOCKET_CONNECT_TIMEOUT': REDIS_SOCKET_CONNECT_TIMEOUT,
            'SOCKET_TIMEOUT': REDIS_SOCKET_TIMEOUT,
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
            'IGNORE_EXCEPTIONS': True,
            'PARSER_CLASS': 'redis.connection.HiredisParser',  # Faster parsing
        },
        'KEY_PREFIX': 'zum:hot',
        'TIMEOUT': 300,  # 5 minutes default
    },

    # Warm cache: Medium TTL, frequently accessed computed data
    # Dashboard stats, aggregations, search results
    'warm': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'{REDIS_URL}/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_CLASS': 'redis.connection.BlockingConnectionPool',
            'CONNECTION_POOL_CLASS_KWARGS': {
                'max_connections': 50,
                'timeout': 20,
            },
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
            'IGNORE_EXCEPTIONS': True,
        },
        'KEY_PREFIX': 'zum:warm',
        'TIMEOUT': 3600,  # 1 hour default
    },

    # Cold cache: Long TTL, rarely changing reference data
    # Configuration, translations, static lookups
    'cold': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'{REDIS_URL}/2',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
            'IGNORE_EXCEPTIONS': True,
        },
        'KEY_PREFIX': 'zum:cold',
        'TIMEOUT': 86400,  # 24 hours default
    },

    # Session cache: User sessions
    'sessions': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'{REDIS_URL}/3',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
            'CONNECTION_POOL_CLASS': 'redis.connection.BlockingConnectionPool',
            'CONNECTION_POOL_CLASS_KWARGS': {
                'max_connections': 100,
            },
        },
        'KEY_PREFIX': 'zum:sess',
        'TIMEOUT': 1209600,  # 2 weeks
    },

    # Rate limiting cache: Isolated for performance
    'ratelimit': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'{REDIS_URL}/4',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'zum:rl',
        'TIMEOUT': 60,
    },

    # Axes lockout cache
    'axes': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'{REDIS_URL}/5',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'zum:axes',
        'TIMEOUT': 86400,
    },

    # Celery results cache
    'celery': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'{REDIS_URL}/6',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'zum:celery',
        'TIMEOUT': 86400,
    },

    # Local memory cache for ultra-fast access (per-process)
    # Use for frequently accessed config that rarely changes
    'locmem': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'TIMEOUT': 300,
        'OPTIONS': {
            'MAX_ENTRIES': 1000,
        },
    },
}


# =============================================================================
# SESSION BACKEND (Redis)
# =============================================================================

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'sessions'
SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_SAVE_EVERY_REQUEST = False  # Only save when modified (reduces writes)
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'


# =============================================================================
# ASGI SETTINGS (Async Support)
# =============================================================================

ASGI_APPLICATION = 'zumodra.asgi.application'

# Channels layer configuration (Redis)
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [f'{REDIS_URL}/7'],
            'capacity': 1500,
            'expiry': 10,
            'group_expiry': 86400,

            # Prefix for channel keys
            'prefix': 'zum:asgi:',

            # Symmetric encryption key (optional)
            # 'symmetric_encryption_keys': [env('CHANNELS_ENCRYPTION_KEY', default=None)],
        },
    },
}


# =============================================================================
# REST FRAMEWORK SCALE SETTINGS
# =============================================================================

REST_FRAMEWORK.update({
    # Cursor pagination for large datasets
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.CursorPagination',
    'PAGE_SIZE': 50,

    # Increased throttle rates for production
    'DEFAULT_THROTTLE_RATES': {
        'anon': '500/hour',
        'user': '5000/hour',
        'burst': '60/minute',
    },

    # Response compression
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
})


# =============================================================================
# CELERY SCALE SETTINGS
# =============================================================================

# Broker connection pooling
CELERY_BROKER_URL = f'{REDIS_URL}/8'
CELERY_RESULT_BACKEND = f'{REDIS_URL}/9'

CELERY_BROKER_POOL_LIMIT = 50  # Max broker connections
CELERY_BROKER_CONNECTION_TIMEOUT = 10
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# Result backend settings
CELERY_RESULT_BACKEND_MAX_RETRIES = 3
CELERY_RESULT_EXPIRES = 3600  # 1 hour (reduce from 24h to save memory)
CELERY_RESULT_EXTENDED = True

# Worker optimization
CELERY_WORKER_PREFETCH_MULTIPLIER = 1  # Disable prefetching for fair scheduling
CELERY_WORKER_CONCURRENCY = env.int('CELERY_CONCURRENCY', default=8)
CELERY_WORKER_MAX_TASKS_PER_CHILD = 500  # Restart worker after N tasks to prevent memory leaks

# Task settings
CELERY_TASK_ACKS_LATE = True  # Acknowledge after task completion
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_TASK_TIME_LIMIT = 1800  # 30 minute hard limit
CELERY_TASK_SOFT_TIME_LIMIT = 1500  # 25 minute soft limit

# Compression
CELERY_TASK_COMPRESSION = 'gzip'
CELERY_RESULT_COMPRESSION = 'gzip'

# Task routing for queue separation
CELERY_TASK_ROUTES = {
    # High priority queue
    'notifications.tasks.send_*': {'queue': 'high'},
    'finance.tasks.process_payment': {'queue': 'high'},

    # Default queue
    'analytics.tasks.*': {'queue': 'default'},
    'jobs.tasks.*': {'queue': 'default'},

    # Low priority queue
    'zumodra.tasks.cleanup_*': {'queue': 'low'},
    'zumodra.tasks.generate_reports': {'queue': 'low'},

    # Dedicated queues
    'newsletter.tasks.*': {'queue': 'email'},
    'hr_core.tasks.*': {'queue': 'hr'},
}


# =============================================================================
# LOGGING SCALE SETTINGS
# =============================================================================

LOGGING.update({
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'zumodra.log'),
            'maxBytes': 10 * 1024 * 1024,  # 10 MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'error_file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'errors.log'),
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'sql_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'sql.log'),
            'maxBytes': 50 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console', 'error_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['sql_file'] if env.bool('LOG_SQL', default=False) else [],
            'level': 'DEBUG' if env.bool('LOG_SQL', default=False) else 'WARNING',
            'propagate': False,
        },
        'celery': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'core.db.optimizations': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'WARNING',
            'propagate': False,
        },
        'core.cache.layers': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'WARNING',
            'propagate': False,
        },
    },
})


# =============================================================================
# SECURITY SCALE SETTINGS
# =============================================================================

# HTTPS everywhere in production
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# HSTS
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookies
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Additional security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'


# =============================================================================
# RATE LIMITING SCALE SETTINGS
# =============================================================================

# Axes settings for brute force protection
AXES_CACHE = 'axes'
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=15)
AXES_LOCK_OUT_AT_FAILURE = True
AXES_LOCKOUT_CALLABLE = None  # Use default lockout response

# Custom rate limits by endpoint
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'ratelimit'

# Per-tenant rate limits (override in tenant settings)
TENANT_RATE_LIMITS = {
    'free': {
        'api_calls_per_hour': 100,
        'api_calls_per_day': 1000,
    },
    'professional': {
        'api_calls_per_hour': 1000,
        'api_calls_per_day': 10000,
    },
    'enterprise': {
        'api_calls_per_hour': 10000,
        'api_calls_per_day': 100000,
    },
}


# =============================================================================
# PERFORMANCE MONITORING
# =============================================================================

# Query count warning threshold
QUERY_COUNT_WARNING_THRESHOLD = 50

# Slow query logging threshold (ms)
SLOW_QUERY_THRESHOLD_MS = 100

# Enable Django Debug Toolbar in staging only
if env.bool('ENABLE_DEBUG_TOOLBAR', default=False):
    INSTALLED_APPS += ['debug_toolbar']
    MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')
    INTERNAL_IPS = ['127.0.0.1']
    DEBUG_TOOLBAR_CONFIG = {
        'SHOW_TOOLBAR_CALLBACK': lambda r: env.bool('ENABLE_DEBUG_TOOLBAR', default=False),
    }


# =============================================================================
# FILE UPLOAD SCALE SETTINGS
# =============================================================================

# Use streaming for large files
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5 MB (stream larger files)
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10 MB

# S3 storage for media in production
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

AWS_S3_FILE_OVERWRITE = False
AWS_S3_OBJECT_PARAMETERS = {
    'CacheControl': 'max-age=86400',  # 1 day cache
}
AWS_S3_SIGNATURE_VERSION = 's3v4'
AWS_S3_ADDRESSING_STYLE = 'virtual'


# =============================================================================
# TEMPLATE CACHING
# =============================================================================

TEMPLATES[0]['OPTIONS']['loaders'] = [
    ('django.template.loaders.cached.Loader', [
        'django.template.loaders.filesystem.Loader',
        'django.template.loaders.app_directories.Loader',
    ]),
]


# =============================================================================
# STATIC FILES CDN
# =============================================================================

if env('STATIC_CDN_URL', default=None):
    STATIC_URL = env('STATIC_CDN_URL')
    STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.ManifestStaticFilesStorage'


# =============================================================================
# MIDDLEWARE OPTIMIZATION
# =============================================================================

# Add GZip compression middleware
MIDDLEWARE.insert(
    MIDDLEWARE.index('django.middleware.common.CommonMiddleware'),
    'django.middleware.gzip.GZipMiddleware'
)

# Add response time header middleware (optional)
if env.bool('ADD_RESPONSE_TIME_HEADER', default=False):
    MIDDLEWARE.append('api.middleware.ResponseTimeMiddleware')
