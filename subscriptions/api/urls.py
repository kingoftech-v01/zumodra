"""
Subscriptions API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    SubscriptionProductViewSet,
    SubscriptionTierViewSet,
    CustomerSubscriptionViewSet,
    SubscriptionInvoiceViewSet,
    UsageRecordViewSet,
)

app_name = 'subscriptions'

router = DefaultRouter()
router.register(r'products', SubscriptionProductViewSet, basename='product')
router.register(r'tiers', SubscriptionTierViewSet, basename='tier')
router.register(r'customer-subscriptions', CustomerSubscriptionViewSet, basename='customer-subscription')
router.register(r'invoices', SubscriptionInvoiceViewSet, basename='invoice')
router.register(r'usage', UsageRecordViewSet, basename='usage')

urlpatterns = router.urls
