"""
Subscriptions Frontend URLs
"""

from django.urls import path
from .template_views import (
    SubscriptionDashboardView,
    SubscriptionProductListView,
    SubscriptionProductDetailView,
    CustomerSubscriptionListView,
    CustomerSubscriptionDetailView,
    SubscriptionInvoiceListView,
    SubscriptionInvoiceDetailView,
    UsageRecordListView,
    HTMXSubscriptionStatsView,
)

app_name = 'subscriptions'

urlpatterns = [
    # Dashboard
    path('', SubscriptionDashboardView.as_view(), name='dashboard'),

    # Products
    path('products/', SubscriptionProductListView.as_view(), name='product-list'),
    path('products/<uuid:pk>/', SubscriptionProductDetailView.as_view(), name='product-detail'),

    # Customer Subscriptions
    path('customers/', CustomerSubscriptionListView.as_view(), name='subscription-list'),
    path('customers/<uuid:pk>/', CustomerSubscriptionDetailView.as_view(), name='subscription-detail'),

    # Invoices
    path('invoices/', SubscriptionInvoiceListView.as_view(), name='invoice-list'),
    path('invoices/<uuid:pk>/', SubscriptionInvoiceDetailView.as_view(), name='invoice-detail'),

    # Usage Records
    path('usage/', UsageRecordListView.as_view(), name='usage-list'),

    # HTMX Partials
    path('htmx/stats/', HTMXSubscriptionStatsView.as_view(), name='htmx-stats'),
]
