"""
Billing Frontend URLs
"""

from django.urls import path
from .template_views import (
    PublicPricingView,
    TenantBillingDashboardView,
    SubscriptionPlanListView,
    SubscriptionPlanDetailView,
    TenantSubscriptionDetailView,
    PlatformInvoiceListView,
    PlatformInvoiceDetailView,
    BillingHistoryListView,
    HTMXBillingStatsView,
)

app_name = 'billing'

urlpatterns = [
    # Public Pricing (no auth required)
    path('pricing/', PublicPricingView.as_view(), name='pricing'),

    # Tenant Billing Dashboard (auth required)
    path('', TenantBillingDashboardView.as_view(), name='dashboard'),

    # Subscription Plans
    path('plans/', SubscriptionPlanListView.as_view(), name='plan-list'),
    path('plans/<slug:slug>/', SubscriptionPlanDetailView.as_view(), name='plan-detail'),

    # Tenant's Subscription
    path('subscription/<uuid:pk>/', TenantSubscriptionDetailView.as_view(), name='subscription-detail'),

    # Invoices
    path('invoices/', PlatformInvoiceListView.as_view(), name='invoice-list'),
    path('invoices/<uuid:pk>/', PlatformInvoiceDetailView.as_view(), name='invoice-detail'),

    # Billing History
    path('history/', BillingHistoryListView.as_view(), name='history-list'),

    # HTMX Partials
    path('htmx/stats/', HTMXBillingStatsView.as_view(), name='htmx-stats'),
]
