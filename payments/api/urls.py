"""
Payments API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    CurrencyViewSet,
    ExchangeRateViewSet,
    PaymentMethodViewSet,
    PaymentTransactionViewSet,
    RefundRequestViewSet,
    PaymentIntentViewSet,
)

app_name = 'payments'

router = DefaultRouter()
router.register(r'currencies', CurrencyViewSet, basename='currency')
router.register(r'exchange-rates', ExchangeRateViewSet, basename='exchange-rate')
router.register(r'payment-methods', PaymentMethodViewSet, basename='payment-method')
router.register(r'transactions', PaymentTransactionViewSet, basename='transaction')
router.register(r'refunds', RefundRequestViewSet, basename='refund')
router.register(r'payment-intents', PaymentIntentViewSet, basename='payment-intent')

urlpatterns = router.urls
