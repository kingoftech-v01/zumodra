"""
URL configuration for zumodra project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from .views import *
from django.conf.urls.i18n import i18n_patterns
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = i18n_patterns(
    path('admin-panel/', admin.site.urls),                      # admin panel
    path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),  # fake admin
    path('', home_view, name='home'),
    path('auth-test/', auth_test_view, name='auth_test'),
    path('authentication/', include('allauth_2fa.urls')),       # 2FA URLs
    path('accounts/two-factor/', include('allauth.mfa.urls')),  # MFA URLs
    path('accounts/', include('allauth.urls')),                 # allauth URLs
    path('appointment/', include('appointment.urls')),          # appointment management URLs
    path('messages/', include('messages_sys.urls')),
    path('newsletter/', include('newsletter.urls')),           # messaging system
    # path('campaign/', include('campaign.urls')),               # newsletter campaigns       # newsletters
    # path('leads/', include('leads.urls')),               # leads management
    path('static/js/dir/<str:file_name>', js_dir_view, name='js_dir'), # message json data
    path('dashboard/', include('dashboard.urls')),
    # path('services/', include('services.urls')),
    path('blog/', include('blog.urls')),
    path('term_of_use/', term_of_use_view, name='term_of_use'),
    path('privacy_policy/', privacy_policy_view, name='privacy_policy'),
    path('about_us/', about_us_view, name='about'),
)

# Add url patterns without language prefix, for example the language switcher
urlpatterns += [
    path('i18n/', include('django.conf.urls.i18n')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

