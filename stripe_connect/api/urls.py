"""
Stripe Connect API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    ConnectedAccountViewSet,
    StripeConnectOnboardingViewSet,
    PlatformFeeViewSet,
    PayoutScheduleViewSet,
    TransferViewSet,
    BalanceTransactionViewSet,
)

app_name = 'stripe_connect'

router = DefaultRouter()
router.register(r'accounts', ConnectedAccountViewSet, basename='account')
router.register(r'onboarding', StripeConnectOnboardingViewSet, basename='onboarding')
router.register(r'fees', PlatformFeeViewSet, basename='fee')
router.register(r'payout-schedules', PayoutScheduleViewSet, basename='payout-schedule')
router.register(r'transfers', TransferViewSet, basename='transfer')
router.register(r'balance-transactions', BalanceTransactionViewSet, basename='balance-transaction')

urlpatterns = router.urls
