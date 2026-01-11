from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
from custom_account_u.api.views import PublicProfileViewSet, ProfileFieldSyncViewSet

# API Router
router = DefaultRouter()
router.register(r'profile/public', PublicProfileViewSet, basename='publicprofile')
router.register(r'profile/sync-settings', ProfileFieldSyncViewSet, basename='profilefieldsync')

urlpatterns = [
    # API endpoints
    path('api/', include(router.urls)),

    # KYC endpoints
    path('idenfy/kyc/', start_kyc, name='start_kyc'),
    path('webhooks/idenfy/verification-update', idenfy_webhook, name='idenfy_webhook'),
]
