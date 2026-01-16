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
    browse_companies_view,
)

# Public careers views (for public schema - aggregates jobs from all tenants)
from main.views import (
    public_careers_landing,
    public_careers_map,
    public_companies_grid,
    public_companies_map,
    public_job_detail,
    public_job_alert_save,
)


# Simple newsletter views for public schema (newsletter tables only exist in tenant schemas)
def newsletter_public_view(request):
    """Simple newsletter landing page for public schema."""
    from django.shortcuts import render
    return render(request, 'newsletter/public_newsletter.html', {
        'page_title': 'Newsletter',
        'meta_description': 'Subscribe to our newsletter to stay updated.',
    })


def newsletter_subscribe_view(request):
    """Handle newsletter subscription from public schema."""
    from django.shortcuts import redirect
    from django.contrib import messages
    from django.utils.translation import gettext_lazy as _

    if request.method != 'POST':
        return redirect('newsletter:newsletter_list')

    email = request.POST.get('email', '').strip()
    if not email:
        messages.error(request, _('Email is required.'))
        return redirect('newsletter:newsletter_list')

    # For the public schema, we just acknowledge the request
    messages.success(request, _('Thank you for subscribing! You will receive updates at %(email)s.') % {'email': email})
    return redirect('newsletter:newsletter_list')


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
    path('our-services/', services_view, name='services'),
    path('companies/', browse_companies_view, name='browse_companies'),
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

    # Careers - Public Landing Pages (aggregated from all tenants)
    # Note: The careers app is in TENANT_APPS, so its database tables only exist
    # in tenant schemas. On the public schema, we aggregate jobs from PublicJobCatalog.
    # Tenant-specific career pages are accessed via tenant subdomains.
    path('careers/', include(([
        # Job browsing (grid and map)
        path('', public_careers_landing, name='home'),
        path('jobs/', public_careers_landing, name='job_list'),
        path('browse/', public_careers_landing, name='browse_jobs'),
        path('browse/map/', public_careers_map, name='browse_jobs_map'),

        # Job detail pages
        path('job/<int:pk>/', public_job_detail, name='job_detail'),
        path('job/<slug:slug>/', public_job_detail, name='job_detail'),

        # Company browsing (grid and map)
        path('companies/', public_companies_grid, name='browse_companies'),
        path('companies/map/', public_companies_map, name='browse_companies_map'),

        # Job alerts (public schema stub - actual functionality in tenant schema)
        path('job-alert/save/', public_job_alert_save, name='job_alert_save'),
    ], 'careers'), namespace='careers')),

    # Blog (Wagtail CMS)
    path('blog/', include('blog.urls')),

    # Wagtail documents
    path('documents/', include(wagtaildocs_urls)),

    # Authentication
    path('accounts/', include('allauth.urls')),
    path('accounts/two-factor/', include('allauth.mfa.urls')),  # Built-in MFA URLs (allauth 65.3.0+)

    # Frontend Template Views (HTMX-powered)
    # All frontend views including dashboard, appointments, messages
    path('app/', include('core.urls_frontend', namespace='frontend')),

    # Custom Account & User Management
    # Public profile, KYC, and profile sync settings
    path('user/', include('custom_account_u.urls', namespace='custom_account_u')),

    # Newsletter (simplified for public schema - tables only exist in tenant schemas)
    path('newsletter/', include(([
        path('', newsletter_public_view, name='newsletter_list'),
        path('subscribe/', newsletter_subscribe_view, name='subscribe'),
    ], 'newsletter'), namespace='newsletter')),

    # ==================== CRITICAL: Wagtail CMS Catch-All Routing ====================
    #
    # IMPORTANT: Wagtail's URL pattern MUST be the LAST pattern in urlpatterns!
    #
    # Why Wagtail must be last:
    # ------------------------
    # Wagtail uses a catch-all URL pattern that attempts to match ANY URL that wasn't
    # matched by previous patterns. If placed earlier, it would intercept URLs meant
    # for other apps (careers, services, etc.), causing 500 errors.
    #
    # What this pattern does:
    # ----------------------
    # - Matches any URL path not handled by specific patterns above
    # - Searches Wagtail's Page tree for a matching page
    # - Serves the page if found, or passes to Django's 404 handler
    #
    # If you see 'ContentType' object has no attribute 'route' errors:
    # ----------------------------------------------------------------
    # This means Wagtail's Site.root_page is corrupted (pointing to ContentType
    # instead of a Page object). Fix it by running:
    #
    #     python manage.py fix_wagtail_site
    #
    # This command ensures Site.root_page points to a valid Page object.
    #
    # ==================================================================================

    # Wagtail CMS page routing - MUST BE LAST!
    path('', include(wagtail_urls)),
)

# Custom error handlers
handler400 = 'zumodra.views_errors.handler400'
handler403 = 'zumodra.views_errors.handler403'
handler404 = 'zumodra.views_errors.handler404'
handler500 = 'zumodra.views_errors.handler500'
