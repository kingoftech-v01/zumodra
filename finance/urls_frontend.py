"""
Finance Frontend URL Configuration.

Routes for finance template views and HTMX endpoints.
Provides frontend pages for:
- Finance dashboard
- Payment history
- Subscription management
- Invoice management
- Payment method management
- Escrow transaction management
- Connected account management
- Financial analytics
"""

from django.urls import path

from .template_views import (
    # Dashboard
    FinanceDashboardView,
    FinanceQuickStatsView,
    RecentPaymentsView,
    PendingInvoicesView,
    EscrowSummaryView,

    # Payments
    PaymentHistoryTemplateView,
    PaymentListPartialView,
    PaymentDetailPartialView,

    # Subscriptions
    SubscriptionTemplateView,
    SubscriptionStatusPartialView,
    SubscriptionPlansPartialView,
    SubscriptionSuccessView,
    SubscriptionCancelView,

    # Invoices
    InvoiceListTemplateView,
    InvoiceListPartialView,
    InvoiceDetailTemplateView,
    InvoiceDetailPartialView,
    InvoicePaymentSuccessView,

    # Payment Methods
    PaymentMethodsTemplateView,
    PaymentMethodListPartialView,
    PaymentMethodCardPartialView,
    PaymentMethodFormPartialView,

    # Escrow
    EscrowListTemplateView,
    EscrowListPartialView,
    EscrowDetailTemplateView,
    EscrowDetailPartialView,
    EscrowTimelinePartialView,

    # Connected Account
    ConnectedAccountTemplateView,
    ConnectedAccountStatusPartialView,
    ConnectedAccountOnboardingPartialView,
    ConnectReturnView,
    ConnectRefreshView,

    # Analytics
    FinanceAnalyticsView,
    FinanceChartDataView,
)

app_name = 'finance-frontend'

urlpatterns = [
    # ==========================================================================
    # Main Dashboard
    # ==========================================================================
    path('', FinanceDashboardView.as_view(), name='dashboard'),

    # Dashboard HTMX endpoints
    path('htmx/quick-stats/', FinanceQuickStatsView.as_view(), name='htmx-quick-stats'),
    path('htmx/recent-payments/', RecentPaymentsView.as_view(), name='htmx-recent-payments'),
    path('htmx/pending-invoices/', PendingInvoicesView.as_view(), name='htmx-pending-invoices'),
    path('htmx/escrow-summary/', EscrowSummaryView.as_view(), name='htmx-escrow-summary'),

    # ==========================================================================
    # Payment History
    # ==========================================================================
    path('payments/', PaymentHistoryTemplateView.as_view(), name='payment-history'),
    path('htmx/payments/', PaymentListPartialView.as_view(), name='htmx-payment-list'),
    path('htmx/payments/<uuid:pk>/', PaymentDetailPartialView.as_view(), name='htmx-payment-detail'),

    # ==========================================================================
    # Subscriptions
    # ==========================================================================
    path('subscription/', SubscriptionTemplateView.as_view(), name='subscription'),
    path('subscription/success/', SubscriptionSuccessView.as_view(), name='subscription-success'),
    path('subscription/cancel/', SubscriptionCancelView.as_view(), name='subscription-cancel'),
    path('htmx/subscription/status/', SubscriptionStatusPartialView.as_view(), name='htmx-subscription-status'),
    path('htmx/subscription/plans/', SubscriptionPlansPartialView.as_view(), name='htmx-subscription-plans'),

    # ==========================================================================
    # Invoices
    # ==========================================================================
    path('invoices/', InvoiceListTemplateView.as_view(), name='invoice-list'),
    path('invoices/<str:invoice_number>/', InvoiceDetailTemplateView.as_view(), name='invoice-detail'),
    path('invoices/<str:invoice_number>/success/', InvoicePaymentSuccessView.as_view(), name='invoice-payment-success'),
    path('htmx/invoices/', InvoiceListPartialView.as_view(), name='htmx-invoice-list'),
    path('htmx/invoices/<str:invoice_number>/', InvoiceDetailPartialView.as_view(), name='htmx-invoice-detail'),

    # ==========================================================================
    # Payment Methods
    # ==========================================================================
    path('payment-methods/', PaymentMethodsTemplateView.as_view(), name='payment-methods'),
    path('htmx/payment-methods/', PaymentMethodListPartialView.as_view(), name='htmx-payment-method-list'),
    path('htmx/payment-methods/<int:pk>/', PaymentMethodCardPartialView.as_view(), name='htmx-payment-method-card'),
    path('htmx/payment-methods/form/', PaymentMethodFormPartialView.as_view(), name='htmx-payment-method-form'),

    # ==========================================================================
    # Escrow Transactions
    # ==========================================================================
    path('escrow/', EscrowListTemplateView.as_view(), name='escrow-list'),
    path('escrow/<uuid:pk>/', EscrowDetailTemplateView.as_view(), name='escrow-detail'),
    path('htmx/escrow/', EscrowListPartialView.as_view(), name='htmx-escrow-list'),
    path('htmx/escrow/<uuid:pk>/', EscrowDetailPartialView.as_view(), name='htmx-escrow-detail'),
    path('htmx/escrow/<uuid:pk>/timeline/', EscrowTimelinePartialView.as_view(), name='htmx-escrow-timeline'),

    # ==========================================================================
    # Connected Account (Stripe Connect)
    # ==========================================================================
    path('connect/', ConnectedAccountTemplateView.as_view(), name='connected-account'),
    path('connect/return/', ConnectReturnView.as_view(), name='connect-return'),
    path('connect/refresh/', ConnectRefreshView.as_view(), name='connect-refresh'),
    path('htmx/connect/status/', ConnectedAccountStatusPartialView.as_view(), name='htmx-connect-status'),
    path('htmx/connect/onboarding/', ConnectedAccountOnboardingPartialView.as_view(), name='htmx-connect-onboarding'),

    # ==========================================================================
    # Financial Analytics
    # ==========================================================================
    path('analytics/', FinanceAnalyticsView.as_view(), name='analytics'),
    path('htmx/analytics/chart/', FinanceChartDataView.as_view(), name='htmx-analytics-chart'),
]
