from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    start_kyc,
    idenfy_webhook,
    public_profile_view,
    profile_sync_settings_list,
    profile_sync_settings_edit,
    trigger_manual_sync,
    view_other_public_profile,
    public_profile_search,
)
from custom_account_u.api.views import PublicProfileViewSet, ProfileFieldSyncViewSet

# API Router
router = DefaultRouter()
router.register(r'profile/public', PublicProfileViewSet, basename='publicprofile')
router.register(r'profile/sync-settings', ProfileFieldSyncViewSet, basename='profilefieldsync')

app_name = 'custom_account_u'

urlpatterns = [
    # API endpoints
    path('api/', include(router.urls)),

    # KYC endpoints
    path('idenfy/kyc/', start_kyc, name='start_kyc'),
    path('webhooks/idenfy/verification-update', idenfy_webhook, name='idenfy_webhook'),

    # PublicProfile views
    path('profile/', public_profile_view, name='public_profile'),
    path('profile/<uuid:profile_uuid>/', view_other_public_profile, name='view_public_profile'),
    path('profile/search/', public_profile_search, name='profile_search'),

    # Profile Sync Settings
    path('sync-settings/', profile_sync_settings_list, name='sync_settings_list'),
    path('sync-settings/<uuid:tenant_uuid>/', profile_sync_settings_edit, name='sync_settings_edit'),
    path('sync-settings/<uuid:tenant_uuid>/trigger/', trigger_manual_sync, name='trigger_sync'),
]
