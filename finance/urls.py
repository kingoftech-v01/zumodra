"""
Finance URL Configuration.

Routes for finance API views including:
- Payment transaction history
- Subscription management
- Invoice management
- Payment method management
- Stripe webhook handling
- Escrow transaction management
- Connected account management
"""

from django.urls import path
from django.views.generic import RedirectView

from .views import (
    # Payment views
    PaymentHistoryView,
    PaymentDetailView,

    # Subscription views
    SubscriptionPlanListView,
    SubscriptionView,
    SubscriptionCancelView,
    SubscriptionReactivateView,

    # Invoice views
    InvoiceListView,
    InvoiceDetailView,
    InvoicePayView,
    InvoiceDownloadView,

    # Payment method views
    PaymentMethodListView,
    PaymentMethodAddView,
    PaymentMethodDeleteView,
    PaymentMethodSetDefaultView,

    # Refund views
    RefundRequestCreateView,
    RefundRequestListView,

    # Escrow views
    EscrowTransactionListView,
    EscrowTransactionDetailView,
    EscrowActionView,

    # Connected account views
    ConnectedAccountView,
    ConnectedAccountDashboardView,

    # Stripe webhook
    StripeWebhookView,
)

app_name = 'finance'

urlpatterns = [
    # ==========================================================================
    # Dashboard (redirects to frontend finance dashboard)
    # ==========================================================================
    path('', RedirectView.as_view(pattern_name='frontend:finance:dashboard', permanent=False), name='dashboard'),

    # ==========================================================================
    # Payment Transaction URLs
    # ==========================================================================
    path('payments/', PaymentHistoryView.as_view(), name='payment-history'),
    path('payments/<uuid:pk>/', PaymentDetailView.as_view(), name='payment-detail'),

    # ==========================================================================
    # Subscription URLs
    # ==========================================================================
    path('subscription/', SubscriptionView.as_view(), name='subscription'),
    path('subscription/plans/', SubscriptionPlanListView.as_view(), name='subscription-plans'),
    path('subscription/cancel/', SubscriptionCancelView.as_view(), name='subscription-cancel'),
    path('subscription/reactivate/', SubscriptionReactivateView.as_view(), name='subscription-reactivate'),

    # ==========================================================================
    # Invoice URLs
    # ==========================================================================
    path('invoices/', InvoiceListView.as_view(), name='invoice-list'),
    path('invoices/<str:invoice_number>/', InvoiceDetailView.as_view(), name='invoice-detail'),
    path('invoices/<str:invoice_number>/pay/', InvoicePayView.as_view(), name='invoice-pay'),
    path('invoices/<str:invoice_number>/download/', InvoiceDownloadView.as_view(), name='invoice-download'),

    # ==========================================================================
    # Payment Method URLs
    # ==========================================================================
    path('payment-methods/', PaymentMethodListView.as_view(), name='payment-method-list'),
    path('payment-methods/add/', PaymentMethodAddView.as_view(), name='payment-method-add'),
    path('payment-methods/<int:pk>/delete/', PaymentMethodDeleteView.as_view(), name='payment-method-delete'),
    path('payment-methods/<int:pk>/set-default/', PaymentMethodSetDefaultView.as_view(), name='payment-method-set-default'),

    # ==========================================================================
    # Refund Request URLs
    # ==========================================================================
    path('refunds/', RefundRequestListView.as_view(), name='refund-list'),
    path('refunds/<uuid:payment_id>/request/', RefundRequestCreateView.as_view(), name='refund-request'),

    # ==========================================================================
    # Escrow Transaction URLs
    # ==========================================================================
    path('escrow/', EscrowTransactionListView.as_view(), name='escrow-list'),
    path('escrow/<uuid:pk>/', EscrowTransactionDetailView.as_view(), name='escrow-detail'),
    path('escrow/<uuid:pk>/<str:action>/', EscrowActionView.as_view(), name='escrow-action'),

    # ==========================================================================
    # Connected Account URLs (Stripe Connect)
    # ==========================================================================
    path('connect/', ConnectedAccountView.as_view(), name='connected-account'),
    path('connect/dashboard/', ConnectedAccountDashboardView.as_view(), name='connected-account-dashboard'),

    # ==========================================================================
    # Stripe Webhook
    # ==========================================================================
    path('webhook/stripe/', StripeWebhookView.as_view(), name='stripe-webhook'),
]
