"""
Finance Webhooks Frontend URLs
"""

from django.urls import path
from .template_views import (
    WebhookDashboardView,
    WebhookEventListView,
    WebhookEventDetailView,
    WebhookRetryListView,
    WebhookSignatureListView,
    WebhookEventTypeListView,
    WebhookEventTypeDetailView,
    HTMXWebhookStatsView,
)

app_name = 'finance_webhooks'

urlpatterns = [
    # Dashboard
    path('', WebhookDashboardView.as_view(), name='dashboard'),

    # Webhook Events
    path('events/', WebhookEventListView.as_view(), name='event-list'),
    path('events/<str:webhook_id>/', WebhookEventDetailView.as_view(), name='event-detail'),

    # Retries
    path('retries/', WebhookRetryListView.as_view(), name='retry-list'),

    # Signatures
    path('signatures/', WebhookSignatureListView.as_view(), name='signature-list'),

    # Event Types
    path('event-types/', WebhookEventTypeListView.as_view(), name='event-type-list'),
    path('event-types/<uuid:pk>/', WebhookEventTypeDetailView.as_view(), name='event-type-detail'),

    # HTMX Partials
    path('htmx/stats/', HTMXWebhookStatsView.as_view(), name='htmx-stats'),
]
