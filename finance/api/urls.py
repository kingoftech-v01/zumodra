"""
Finance API URLs

Routes for payment, subscription, escrow, and Stripe Connect endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    PaymentTransactionViewSet,
    SubscriptionPlanViewSet,
    UserSubscriptionViewSet,
    InvoiceViewSet,
    PaymentMethodViewSet,
    RefundRequestViewSet,
    EscrowTransactionViewSet,
    DisputeViewSet,
    EscrowPayoutViewSet,
    ConnectedAccountViewSet,
    PayoutScheduleViewSet,
    PlatformFeeViewSet,
    StripeWebhookEventViewSet,
    FinanceAnalyticsViewSet,
)

app_name = 'finance_api'

router = DefaultRouter()

# Core payment endpoints
router.register(r'payments', PaymentTransactionViewSet, basename='payment')
router.register(r'subscriptions/plans', SubscriptionPlanViewSet, basename='subscription-plan')
router.register(r'subscriptions', UserSubscriptionViewSet, basename='subscription')
router.register(r'invoices', InvoiceViewSet, basename='invoice')
router.register(r'payment-methods', PaymentMethodViewSet, basename='payment-method')
router.register(r'refunds', RefundRequestViewSet, basename='refund')

# Escrow endpoints
router.register(r'escrow', EscrowTransactionViewSet, basename='escrow')
router.register(r'disputes', DisputeViewSet, basename='dispute')
router.register(r'payouts', EscrowPayoutViewSet, basename='payout')

# Stripe Connect endpoints
router.register(r'connect/accounts', ConnectedAccountViewSet, basename='connected-account')
router.register(r'connect/payout-schedules', PayoutScheduleViewSet, basename='payout-schedule')
router.register(r'connect/platform-fees', PlatformFeeViewSet, basename='platform-fee')
router.register(r'webhooks', StripeWebhookEventViewSet, basename='webhook-event')

# Analytics (uses ViewSet with only @action methods)
router.register(r'analytics', FinanceAnalyticsViewSet, basename='finance-analytics')

urlpatterns = [
    path('', include(router.urls)),
]
