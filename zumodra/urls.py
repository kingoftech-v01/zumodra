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
from wagtail.admin import urls as wagtailadmin_urls
from wagtail import urls as wagtail_urls
from wagtail.documents import urls as wagtaildocs_urls
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = i18n_patterns(
    path('admin-panel/', admin.site.urls),
    path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),  # fake admin
    # path('secret-admin/', admin.site.urls),  # real admin URL, rename 'secret-admin' to your secret admin path
    path('', home_view, name='home'),
    path('auth-test/', auth_test_view, name='auth_test'),
    path('authentication/', include('allauth_2fa.urls')),       # 2FA URLs
    path('accounts/two-factor/', include('allauth.mfa.urls')),  # MFA URLs
    path('accounts/', include('allauth.urls')),                 # allauth URLs
    path('appointment/', include('appointment.urls')),          # appointment management URLs
    path('cms/', include(wagtailadmin_urls)),                   # CMS URLs
    path('documents/', include(wagtaildocs_urls)),
    path('pages/', include(wagtail_urls)),
    path('messages/', include('messages_sys.urls')),
    path('newsletter/', include('newsletter.urls')),           # messaging system
    # path('campaign/', include('campaign.urls')),               # newsletter campaigns       # newsletters
    # path('leads/', include('leads.urls')),               # leads management
    path('static/js/dir/<str:file_name>', js_dir_view, name='js_dir'), # message json data
<<<<<<< HEAD
]
=======
    path('service/', include('dashboard_service.urls')),
    path('project/', include('dashboard_project.urls')),
    path('blog/', include('blog.urls')),
)

# Add url patterns without language prefix, for example the language switcher
urlpatterns += [
    path('i18n/', include('django.conf.urls.i18n')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

>>>>>>> 5c8178b81147c1f40365b414172df210ed6b597d
