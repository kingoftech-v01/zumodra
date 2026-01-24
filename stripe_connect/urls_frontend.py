"""
Stripe Connect Frontend URLs
"""

from django.urls import path
from .template_views import (
    StripeConnectDashboardView,
    ConnectedAccountListView,
    ConnectedAccountDetailView,
    StripeConnectOnboardingListView,
    PlatformFeeListView,
    TransferListView,
    TransferDetailView,
    BalanceTransactionListView,
    HTMXStripeConnectStatsView,
)

app_name = 'stripe_connect'

urlpatterns = [
    # Dashboard
    path('', StripeConnectDashboardView.as_view(), name='dashboard'),

    # Connected Accounts
    path('accounts/', ConnectedAccountListView.as_view(), name='account-list'),
    path('accounts/<uuid:pk>/', ConnectedAccountDetailView.as_view(), name='account-detail'),

    # Onboarding
    path('onboarding/', StripeConnectOnboardingListView.as_view(), name='onboarding-list'),

    # Platform Fees
    path('fees/', PlatformFeeListView.as_view(), name='fee-list'),

    # Transfers
    path('transfers/', TransferListView.as_view(), name='transfer-list'),
    path('transfers/<uuid:pk>/', TransferDetailView.as_view(), name='transfer-detail'),

    # Balance Transactions
    path('balance/', BalanceTransactionListView.as_view(), name='balance-list'),

    # HTMX Partials
    path('htmx/stats/', HTMXStripeConnectStatsView.as_view(), name='htmx-stats'),
]
