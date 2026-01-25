"""
Payments Frontend URLs
"""

from django.urls import path
from .template_views import (
    PaymentDashboardView,
    PaymentTransactionListView,
    PaymentTransactionDetailView,
    PaymentMethodListView,
    PaymentMethodDetailView,
    RefundRequestListView,
    RefundRequestDetailView,
    CurrencyListView,
    ExchangeRateListView,
    HTMXQuickStatsView,
    HTMXRecentTransactionsView,
)

app_name = 'payments'

urlpatterns = [
    # Dashboard
    path('', PaymentDashboardView.as_view(), name='dashboard'),

    # Transactions
    path('transactions/', PaymentTransactionListView.as_view(), name='transaction-list'),
    path('transactions/<uuid:pk>/', PaymentTransactionDetailView.as_view(), name='transaction-detail'),

    # Payment Methods
    path('methods/', PaymentMethodListView.as_view(), name='payment-method-list'),
    path('methods/<uuid:pk>/', PaymentMethodDetailView.as_view(), name='payment-method-detail'),

    # Refund Requests
    path('refunds/', RefundRequestListView.as_view(), name='refund-list'),
    path('refunds/<uuid:pk>/', RefundRequestDetailView.as_view(), name='refund-detail'),

    # Currencies
    path('currencies/', CurrencyListView.as_view(), name='currency-list'),

    # Exchange Rates
    path('exchange-rates/', ExchangeRateListView.as_view(), name='exchange-rate-list'),

    # HTMX Partials
    path('htmx/quick-stats/', HTMXQuickStatsView.as_view(), name='htmx-quick-stats'),
    path('htmx/recent-transactions/', HTMXRecentTransactionsView.as_view(), name='htmx-recent-transactions'),
]
