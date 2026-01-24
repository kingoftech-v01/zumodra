"""
Finance Webhooks API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    WebhookEventViewSet,
    WebhookRetryViewSet,
    WebhookSignatureViewSet,
    WebhookEventTypeViewSet,
)

app_name = 'finance_webhooks'

router = DefaultRouter()
router.register(r'events', WebhookEventViewSet, basename='event')
router.register(r'retries', WebhookRetryViewSet, basename='retry')
router.register(r'signatures', WebhookSignatureViewSet, basename='signature')
router.register(r'event-types', WebhookEventTypeViewSet, basename='event-type')

urlpatterns = router.urls
