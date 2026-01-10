"""
URL configuration for the public schema in django-tenants.

This file defines the URL patterns accessible without a tenant context,
such as the landing page, signup, and tenant administration.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf.urls.i18n import i18n_patterns
from django.conf.urls.static import static
from django.conf import settings
from django.http import JsonResponse

# Wagtail CMS imports
from wagtail import urls as wagtail_urls
from wagtail.documents import urls as wagtaildocs_urls

from .views import (
    home_view,
    about_us_view,
    contact_us_view,
    faq_view,
    services_view,
    pricing_view,
    term_of_use_view,
    privacy_policy_view,
    auth_test_view,
    become_seller_view,
    become_buyer_view,
)


# ==================== Health Check Endpoint ====================

def health_check(request):
    """
    Health check endpoint for load balancers and monitoring.
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
    """Readiness check endpoint."""
    from django.db import connection

    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        return JsonResponse({'ready': True}, status=200)
    except Exception:
        return JsonResponse({'ready': False}, status=503)


def liveness_check(request):
    """Liveness check endpoint."""
    return JsonResponse({'alive': True}, status=200)


# ==================== URL Patterns ====================

# Non-i18n URL patterns (API, health checks, etc.)
urlpatterns = [
    # Health checks (no auth, no i18n)
    path('health/', health_check, name='health_check'),
    path('health/ready/', readiness_check, name='readiness_check'),
    path('health/live/', liveness_check, name='liveness_check'),

    # i18n endpoint
    path('i18n/', include('django.conf.urls.i18n')),

    # API endpoints accessible from public schema
    path('api/', include('api.urls')),
    path('api/v1/', include('api.urls_v1')),
]

# Add API documentation URLs if drf-spectacular is installed
try:
    from drf_spectacular.views import (
        SpectacularAPIView,
        SpectacularRedocView,
        SpectacularSwaggerView,
    )
    urlpatterns += [
        path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
        path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
        path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    ]
except ImportError:
    pass

# Static and media files
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# i18n patterns (language-prefixed URLs)
urlpatterns += i18n_patterns(
    # Admin panels
    path('admin-panel/', admin.site.urls),
    path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),

    # Public pages
    path('', home_view, name='home'),
    path('about/', about_us_view, name='about'),
    path('contact/', contact_us_view, name='contact_us'),
    path('faq/', faq_view, name='faq'),
    path('pricing/', pricing_view, name='pricing'),
    path('terms/', term_of_use_view, name='term_of_use'),
    path('privacy/', privacy_policy_view, name='privacy_policy'),
    path('become-seller/', become_seller_view, name='become_seller'),
    path('become-buyer/', become_buyer_view, name='become_buyer'),
    path('auth-test/', auth_test_view, name='auth_test'),

    # Services Marketplace (included with namespace for template compatibility)
    path('services/', include('services.urls', namespace='services')),

    # Careers (public job listings)
    path('careers/', include('careers.urls', namespace='careers')),

    # Blog (Wagtail CMS)
    path('blog/', include('blog.urls')),

    # Wagtail documents
    path('documents/', include(wagtaildocs_urls)),

    # Authentication
    path('accounts/', include('allauth.urls')),
    path('accounts/two-factor/', include('allauth.mfa.urls')),
    path('authentication/', include('allauth_2fa.urls')),

    # Newsletter
    path('newsletter/', include('newsletter.urls')),

    # Wagtail page routing (catch-all, must be last)
    path('', include(wagtail_urls)),
)

# Custom error handlers
handler400 = 'zumodra.views_errors.handler400'
handler403 = 'zumodra.views_errors.handler403'
handler404 = 'zumodra.views_errors.handler404'
handler500 = 'zumodra.views_errors.handler500'
