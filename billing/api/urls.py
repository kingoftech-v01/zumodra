"""
Billing API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    SubscriptionPlanViewSet,
    TenantSubscriptionViewSet,
    PlatformInvoiceViewSet,
    BillingHistoryViewSet,
)

app_name = 'billing'

router = DefaultRouter()
router.register(r'plans', SubscriptionPlanViewSet, basename='plan')
router.register(r'subscriptions', TenantSubscriptionViewSet, basename='subscription')
router.register(r'invoices', PlatformInvoiceViewSet, basename='invoice')
router.register(r'history', BillingHistoryViewSet, basename='history')

urlpatterns = router.urls
