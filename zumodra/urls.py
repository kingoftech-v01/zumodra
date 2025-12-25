"""
URL configuration for zumodra project.
"""
from django.contrib import admin
from django.urls import path, include
from .views import *
from django.conf.urls.i18n import i18n_patterns
from django.conf.urls.static import static
from django.conf import settings

# Wagtail imports
from wagtail.admin import urls as wagtailadmin_urls
from wagtail import urls as wagtail_urls
from wagtail.documents import urls as wagtaildocs_urls

urlpatterns = i18n_patterns(
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

    # Internal features (hidden from public navigation)
    path('app/dashboard/', include('dashboard.urls')),          # Dashboard (hidden)
    path('app/appointment/', include('appointment.urls')),      # Appointments (hidden)
    path('app/messages/', include('messages_sys.urls')),        # Messages (hidden)

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

# Add url patterns without language prefix
urlpatterns += [
    path('i18n/', include('django.conf.urls.i18n')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Wagtail pages - must be last (catch-all routing)
urlpatterns += i18n_patterns(
    path('', include(wagtail_urls)),  # Wagtail page routing
)

