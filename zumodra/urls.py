"""
URL configuration for zumodra project.

This is the main URL configuration that routes all requests to appropriate apps.
Includes i18n patterns for multi-language support, API versioning, and health checks.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf.urls.i18n import i18n_patterns
from django.conf.urls.static import static
from django.conf import settings
from django.http import JsonResponse
from django.views.defaults import (
    page_not_found,
    server_error,
    permission_denied,
    bad_request,
)

from .views import (
    home_view,
    about_us_view,
    term_of_use_view,
    privacy_policy_view,
    auth_test_view,
    js_dir_view,
)

# Wagtail imports
from wagtail.admin import urls as wagtailadmin_urls
from wagtail import urls as wagtail_urls
from wagtail.documents import urls as wagtaildocs_urls


# ==================== Health Check Endpoint ====================

def health_check(request):
    """
    Health check endpoint for load balancers and monitoring.
    Returns basic health status and optional detailed checks.
    """
    from django.db import connection
    from django.core.cache import cache
    import time

    health_status = {
        'status': 'healthy',
        'timestamp': time.time(),
        'version': getattr(settings, 'APP_VERSION', '1.0.0'),
    }

    # Check database connection
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        health_status['database'] = 'connected'
    except Exception as e:
        health_status['database'] = 'error'
        health_status['status'] = 'degraded'
        health_status['database_error'] = str(e)

    # Check cache (if Redis/Memcached is configured)
    try:
        cache.set('health_check', 'ok', 1)
        if cache.get('health_check') == 'ok':
            health_status['cache'] = 'connected'
        else:
            health_status['cache'] = 'error'
            health_status['status'] = 'degraded'
    except Exception as e:
        health_status['cache'] = 'unavailable'

    status_code = 200 if health_status['status'] == 'healthy' else 503
    return JsonResponse(health_status, status=status_code)


def readiness_check(request):
    """
    Readiness check endpoint for Kubernetes/container orchestration.
    Returns 200 only when the application is ready to serve traffic.
    """
    from django.db import connection

    try:
        # Verify database connection
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        return JsonResponse({'ready': True}, status=200)
    except Exception:
        return JsonResponse({'ready': False}, status=503)


def liveness_check(request):
    """
    Liveness check endpoint for Kubernetes/container orchestration.
    Returns 200 if the application process is alive.
    """
    return JsonResponse({'alive': True}, status=200)


# ==================== API Root View ====================

def api_root(request):
    """
    API root view providing API information and documentation links.
    """
    base_url = request.build_absolute_uri('/api/')
    return JsonResponse({
        'name': 'Zumodra API',
        'version': 'v1',
        'description': 'Zumodra Multi-Tenant SaaS Platform API',
        'endpoints': {
            'v1': f'{base_url}v1/',
            'auth': f'{base_url}v1/auth/token/',
            'docs': f'{base_url}docs/',
            'schema': f'{base_url}schema/',
        },
        'documentation': 'https://docs.zumodra.com/api',
        'support': 'support@zumodra.com',
    })


# ==================== Custom Error Handlers ====================

def custom_400_handler(request, exception=None):
    """Custom 400 Bad Request handler for API requests."""
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Bad Request',
            'status_code': 400,
            'detail': 'The request was invalid or malformed.',
        }, status=400)
    return bad_request(request, exception)


def custom_403_handler(request, exception=None):
    """Custom 403 Forbidden handler for API requests."""
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Forbidden',
            'status_code': 403,
            'detail': 'You do not have permission to perform this action.',
        }, status=403)
    return permission_denied(request, exception)


def custom_404_handler(request, exception=None):
    """Custom 404 Not Found handler for API requests."""
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Not Found',
            'status_code': 404,
            'detail': 'The requested resource was not found.',
            'path': request.path,
        }, status=404)
    return page_not_found(request, exception)


def custom_500_handler(request):
    """Custom 500 Internal Server Error handler for API requests."""
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Internal Server Error',
            'status_code': 500,
            'detail': 'An unexpected error occurred. Please try again later.',
        }, status=500)
    return server_error(request)


# ==================== URL Patterns ====================

# Non-i18n URL patterns (API, health checks, etc.)
urlpatterns = [
    # Health checks (no auth, no i18n)
    path('health/', health_check, name='health_check'),
    path('health/ready/', readiness_check, name='readiness_check'),
    path('health/live/', liveness_check, name='liveness_check'),

    # i18n endpoint
    path('i18n/', include('django.conf.urls.i18n')),

    # API Root
    path('api/', api_root, name='api_root'),

    # API v1 (versioned API endpoints)
    path('api/v1/', include('api.urls_v1')),

    # Legacy API (for backwards compatibility)
    path('api/legacy/', include('api.urls')),

    # Public Career Pages (no auth required, outside i18n)
    path('careers/', include('careers.urls', namespace='careers_public')),
]

# Import and add public verification view
from accounts.template_views import EmploymentVerificationResponseView

urlpatterns += [
    # Public Verification Response Endpoint (no auth, no i18n)
    path('verify/employment/<str:token>/', EmploymentVerificationResponseView.as_view(), name='employment-verify-public'),
]

# Add API documentation URLs if drf-spectacular is installed
try:
    from drf_spectacular.views import (
        SpectacularAPIView,
        SpectacularRedocView,
        SpectacularSwaggerView,
    )
    urlpatterns += [
        # API Schema
        path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
        # Swagger UI
        path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
        # ReDoc
        path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    ]
except ImportError:
    # drf-spectacular not installed, skip documentation URLs
    pass

# Static and media files
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# i18n patterns (language-prefixed URLs)
urlpatterns += i18n_patterns(
    # Admin panels
    path('admin-panel/', admin.site.urls),                      # Django admin panel
    path('cms/', include(wagtailadmin_urls)),                   # Wagtail CMS admin
    path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),  # Fake admin honeypot

    # Public pages
    path('', home_view, name='home'),
    path('about/', about_us_view, name='about'),
    path('terms/', term_of_use_view, name='term_of_use'),
    path('privacy/', privacy_policy_view, name='privacy_policy'),

    # Authentication (hidden from public but functional)
    path('accounts/', include('allauth.urls')),                 # allauth URLs
    path('accounts/two-factor/', include('allauth.mfa.urls')),  # MFA URLs
    path('authentication/', include('allauth_2fa.urls')),       # 2FA URLs

    # Frontend Template Views (HTMX-powered)
    # All frontend views including dashboard, appointments, messages are handled through core.urls_frontend
    path('app/', include('core.urls_frontend')),                # All frontend views

    # Legacy standalone routes (redirects to frontend namespace)
    # Note: Dashboard, appointment, messages are now served via core.urls_frontend
    # Keep these only if you need backward-compatible URLs
    path('app/messages/', include('messages_sys.urls')),        # Messages (standalone)

    # Services Marketplace
    path('services/', include('services.urls')),                # Services marketplace

    # Notifications (web views)
    path('notifications/', include('notifications.urls')),      # In-app notifications

    # Analytics (web views)
    path('analytics/', include('analytics.urls')),              # Analytics dashboards

    # Finance (payments, subscriptions, invoices)
    path('finance/', include('finance.urls', namespace='finance')),

    # Newsletter
    path('newsletter/', include('newsletter.urls')),

    # Wagtail documents
    path('documents/', include(wagtaildocs_urls)),

    # Blog search (auxiliary)
    path('blog/', include('blog.urls')),

    # Development/testing
    path('auth-test/', auth_test_view, name='auth_test'),
    path('static/js/dir/<str:file_name>', js_dir_view, name='js_dir'),
)

# Wagtail pages - must be last (catch-all routing)
urlpatterns += i18n_patterns(
    path('', include(wagtail_urls)),  # Wagtail page routing
)

# Custom error handlers (using branded error pages from views_errors.py)
handler400 = 'zumodra.views_errors.handler400'
handler403 = 'zumodra.views_errors.handler403'
handler404 = 'zumodra.views_errors.handler404'
handler500 = 'zumodra.views_errors.handler500'


"""
URL Structure Overview:
=======================

Health Checks (no auth):
    /health/                - Full health check with DB and cache status
    /health/ready/          - Readiness check for container orchestration
    /health/live/           - Liveness check for container orchestration

API Endpoints:
    /api/                   - API root with version info and links
    /api/v1/                - API version 1 (current)
    /api/v1/auth/           - JWT authentication
    /api/v1/tenants/        - Multi-tenant management
    /api/v1/accounts/       - User accounts and profiles
    /api/v1/ats/            - Applicant Tracking System
    /api/v1/hr/             - Human Resources core
    /api/v1/careers/        - Career pages (public + admin)
    /api/v1/analytics/      - Analytics and reporting
    /api/v1/integrations/   - Third-party integrations
    /api/v1/notifications/  - Notification system
    /api/v1/ai/             - AI matching and recommendations
    /api/v1/marketplace/    - Services marketplace
    /api/legacy/            - Legacy API (backwards compatibility)

API Documentation:
    /api/schema/            - OpenAPI schema (JSON)
    /api/docs/              - Swagger UI interactive docs
    /api/redoc/             - ReDoc documentation

Public Pages (with language prefix):
    /careers/               - Public career portal (no i18n prefix)
    /<lang>/                - Home page
    /<lang>/about/          - About us
    /<lang>/terms/          - Terms of use
    /<lang>/privacy/        - Privacy policy

Admin Panels (with language prefix):
    /<lang>/admin-panel/    - Django admin
    /<lang>/cms/            - Wagtail CMS
    /<lang>/admin/          - Honeypot (fake admin)

Authentication (with language prefix):
    /<lang>/accounts/       - Allauth authentication
    /<lang>/authentication/ - 2FA authentication

Application Features (with language prefix):
    /<lang>/app/dashboard/  - User dashboard
    /<lang>/app/appointment/- Appointments
    /<lang>/app/messages/   - Messaging system
    /<lang>/services/       - Services marketplace
    /<lang>/notifications/  - Notifications
    /<lang>/analytics/      - Analytics
    /<lang>/newsletter/     - Newsletter
    /<lang>/blog/           - Blog

Content Management:
    /<lang>/documents/      - Wagtail documents
    /<lang>/*               - Wagtail pages (catch-all)

Supported Languages:
    en - English
    es - Spanish
    fr - French
    de - German
    it - Italian
    pt - Portuguese
    ru - Russian
    zh-hans - Simplified Chinese
    zh-hant - Traditional Chinese
"""
