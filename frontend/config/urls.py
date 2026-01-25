"""
URL configuration for FreelanHub project.
Modular routing system using Django apps.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    # Core & public pages (home, about, contact, faqs, pricing)
    path('', include('apps.core.urls')),

    # Authentication (login, register)
    path('accounts/', include('apps.accounts.urls')),

    # Main features
    path('candidates/', include('apps.candidates.urls')),
    path('employers/', include('apps.employers.urls')),
    path('jobs/', include('apps.jobs.urls')),
    path('projects/', include('apps.projects.urls')),
    path('services/', include('apps.services.urls')),

    # Dashboard
    path('dashboard/', include('apps.dashboard.urls')),

    # Support features
    path('blog/', include('apps.blog.urls')),
    path('legal/', include('apps.legal.urls')),
]

# Serve static files in development
# Django's runserver automatically serves files from STATICFILES_DIRS when DEBUG=True
# No need to add static() here - it can cause conflicts

# Custom error handlers
handler404 = 'apps.core.views.handler404'
handler500 = 'apps.core.views.handler500'
