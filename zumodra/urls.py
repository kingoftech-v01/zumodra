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
    services_view,
    pricing_view,
    faq_view,
    contact_us_view,
    become_seller_view,
    become_buyer_view,
    term_of_use_view,
    privacy_policy_view,
    auth_test_view,
    # js_dir_view removed - security vulnerability (2026-01-16)
    # Redirect views for old URLs
    redirect_login,
    redirect_signup,
    redirect_dashboard,
    redirect_ats_applications,
    redirect_ats_pipeline,
    redirect_hr_timeoff,
    redirect_profile,
    redirect_find_work,
    redirect_find_talent,
    redirect_marketplace,
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
    path('our-services/', services_view, name='services'),
    path('pricing/', pricing_view, name='pricing'),
    path('faq/', faq_view, name='faq'),
    path('contact/', contact_us_view, name='contact_us'),
    path('become-seller/', become_seller_view, name='become_seller'),
    path('become-buyer/', become_buyer_view, name='become_buyer'),
    path('terms/', term_of_use_view, name='term_of_use'),
    path('privacy/', privacy_policy_view, name='privacy_policy'),

    # Authentication (hidden from public but functional)
    path('accounts/', include('allauth.urls')),                 # allauth URLs
    path('accounts/two-factor/', include('allauth.mfa.urls')),  # MFA URLs (built-in allauth 65.3.0+)

    # Redirect old URLs to new locations (backwards compatibility)
    # These redirect views prevent 404/500 errors for bookmarked old URLs
    path('login/', redirect_login, name='redirect_login'),
    path('signup/', redirect_signup, name='redirect_signup'),
    path('dashboard/', redirect_dashboard, name='redirect_dashboard'),
    path('ats/applications/', redirect_ats_applications, name='redirect_ats_applications'),
    path('ats/pipeline/', redirect_ats_pipeline, name='redirect_ats_pipeline'),
    path('hr/time-off/', redirect_hr_timeoff, name='redirect_hr_timeoff'),
    path('profile/', redirect_profile, name='redirect_profile'),
    path('accounts/profile/', redirect_profile, name='redirect_accounts_profile'),
    path('find-work/', redirect_find_work, name='redirect_find_work'),
    path('find-talent/', redirect_find_talent, name='redirect_find_talent'),
    path('marketplace/', redirect_marketplace, name='redirect_marketplace'),

    # Frontend Template Views (HTMX-powered)
    # All frontend views including dashboard, appointments, messages are handled through core.urls_frontend
    path('app/', include('core.urls_frontend', namespace='frontend')),  # All frontend views with namespace

    # Custom Account & User Management
    # Public profile, KYC, and profile sync settings
    path('user/', include('custom_account_u.urls', namespace='custom_account_u')),

    # Legacy standalone routes (redirects to frontend namespace)
    # Note: Dashboard, appointment, messages are now served via core.urls_frontend
    # Keep these only if you need backward-compatible URLs
    path('app/messages/', include('messages_sys.urls', namespace='messages_sys')),  # Messages (standalone)

    # Services Marketplace (tenant-specific)
    path('services/', include('services.urls', namespace='services')),  # Services marketplace

    # Notifications (web views)
    path('notifications/', include('notifications.urls', namespace='notifications')),  # In-app notifications

    # Analytics (web views)
    path('analytics/', include('analytics.urls', namespace='analytics')),  # Analytics dashboards

    # Finance (payments, subscriptions, invoices)
    path('finance/', include('finance.urls', namespace='finance')),

    # Newsletter
    path('newsletter/', include('newsletter.urls', namespace='newsletter')),

    # Configurations (staff dashboard)
    path('configurations/', include('configurations.urls', namespace='configurations')),

    # Marketing (staff dashboard)
    path('marketing/', include('marketing.urls', namespace='marketing')),

    # Security (staff dashboard)
    path('security/', include('security.urls', namespace='security')),

    # Careers (public job listings - also available with i18n prefix)
    path('careers/', include('careers.urls', namespace='careers')),

    # Wagtail documents
    path('documents/', include(wagtaildocs_urls)),

    # Blog search (auxiliary)
    path('blog/', include('blog.urls', namespace='blog')),

    # Development/testing
    path('auth-test/', auth_test_view, name='auth_test'),
    # SECURITY: js_dir URL pattern removed (2026-01-16) - path traversal vulnerability
    # Use Django's native staticfiles serving instead (collectstatic + WhiteNoise/nginx)
)

# ==================== CRITICAL: Wagtail CMS Catch-All Routing ====================
#
# IMPORTANT: Wagtail's URL pattern MUST be the LAST pattern in urlpatterns!
#
# Why Wagtail must be last:
# ------------------------
# Wagtail uses a catch-all URL pattern (`path('', include(wagtail_urls))`) that
# attempts to match ANY URL that wasn't matched by previous patterns. Wagtail's
# routing system tries to find a Page object that matches the requested URL path.
#
# How Wagtail routing works:
# --------------------------
# 1. Django processes URL patterns in order from top to bottom
# 2. If a URL matches a specific pattern (e.g., /careers/, /services/), that view is used
# 3. If no specific pattern matches, the request reaches Wagtail's catch-all pattern
# 4. Wagtail then searches its Page tree to find a page with a matching URL path
# 5. If found, Wagtail serves that page using the Page.serve() method
# 6. If not found, Django's 404 handler is called
#
# What happens if Wagtail is NOT last:
# ------------------------------------
# - Wagtail would intercept URLs meant for other apps (e.g., /careers/, /services/)
# - This causes 'ContentType' object has no attribute 'route' errors when Wagtail's
#   root page is misconfigured or points to a ContentType instead of a Page object
# - Application URLs would never be reached, breaking functionality
#
# The fix:
# --------
# 1. Always keep Wagtail's pattern as the LAST pattern in i18n_patterns
# 2. Define all specific URL patterns (apps, views) BEFORE the Wagtail catch-all
# 3. Run `python manage.py fix_wagtail_site` to ensure Site.root_page is valid
# 4. Verify that Wagtail's Site.root_page is a Page object, not a ContentType
#
# ==================================================================================

urlpatterns += i18n_patterns(
    # Wagtail CMS page routing - MUST BE LAST!
    # This is a catch-all pattern that matches any remaining URLs
    # and attempts to serve them as Wagtail CMS pages
    path('', include(wagtail_urls)),
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
    /api/v1/finance/        - Finance & payments
    /api/v1/messages/       - Messaging (REST complement to WebSocket)
    /api/v1/configurations/ - Configuration management
    /api/v1/marketing/      - Marketing & analytics
    /api/v1/security/       - Security monitoring
    /api/legacy/            - Legacy API (backwards compatibility)

API Documentation:
    /api/schema/            - OpenAPI schema (JSON)
    /api/docs/              - Swagger UI interactive docs
    /api/redoc/             - ReDoc documentation

Public Pages (with language prefix):
    /careers/               - Public career portal (no i18n prefix)
    /<lang>/                - Home page
    /<lang>/about/          - About us
    /<lang>/our-services/   - Services overview
    /<lang>/pricing/        - Pricing plans
    /<lang>/faq/            - Frequently asked questions
    /<lang>/contact/        - Contact page
    /<lang>/become-seller/  - Freelancer onboarding
    /<lang>/become-buyer/   - Employer onboarding
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
    /<lang>/finance/        - Finance (payments, subscriptions)
    /<lang>/newsletter/     - Newsletter
    /<lang>/configurations/ - Configurations dashboard (staff)
    /<lang>/marketing/      - Marketing dashboard (staff)
    /<lang>/security/       - Security dashboard (staff)
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
