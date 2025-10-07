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

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home_view, name='home'),
    path('authentication/', include('allauth_2fa.urls')),       # 2FA URLs
    path('accounts/two-factor/', include('allauth.mfa.urls')),  # MFA URLs
    path('accounts/', include('allauth.urls')),                 # allauth URLs
    path('messages/', include('messages_sys.urls')),            # messaging system
    # path('campaigns/', include('campaign.urls')),               # newsletter campaigns  
    # path('newsletter/', include('django_newsletter.urls')),     # newsletters
    # path('leads/', include('leads.urls')),               # leads management
    path('assets/js/dir/<str:file_name>', js_dir_view, name='js_dir'), # message json data
]
