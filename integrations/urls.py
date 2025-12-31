"""
URL configuration for integrations app.

Includes REST API endpoints for managing integrations, webhooks, OAuth flows,
and sync operations.
"""

from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter

from .views import (
    IntegrationViewSet,
    WebhookEndpointViewSet,
    WebhookDeliveryViewSet,
    IntegrationSyncLogViewSet,
    IntegrationEventViewSet,
    OAuthCallbackView,
    WebhookReceiverView,
)

app_name = 'integrations'

# REST API Router
router = DefaultRouter()
router.register(r'integrations', IntegrationViewSet, basename='integration')
router.register(r'webhooks', WebhookEndpointViewSet, basename='webhook-endpoint')
router.register(r'webhook-deliveries', WebhookDeliveryViewSet, basename='webhook-delivery')
router.register(r'sync-logs', IntegrationSyncLogViewSet, basename='sync-log')
router.register(r'integration-events', IntegrationEventViewSet, basename='integration-event')

urlpatterns = [
    # REST API routes
    path('api/', include(router.urls)),

    # OAuth callback routes
    path(
        'oauth/callback/',
        OAuthCallbackView.as_view(),
        name='oauth-callback'
    ),
    path(
        'oauth/callback/<str:provider>/',
        OAuthCallbackView.as_view(),
        name='oauth-callback-provider'
    ),

    # Webhook receiver (public endpoint for external services)
    # Note: Uses regex to capture the full endpoint path including provider/key format
    re_path(
        r'^webhooks/receive/(?P<endpoint_path>.+)/$',
        WebhookReceiverView.as_view(),
        name='webhook-receiver'
    ),

    # Legacy incoming webhook format (provider/key)
    path(
        'webhooks/<str:provider>/<str:endpoint_key>/',
        WebhookReceiverView.as_view(),
        name='incoming-webhook'
    ),
]
