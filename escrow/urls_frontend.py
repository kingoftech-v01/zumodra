"""
Escrow Frontend URLs
"""

from django.urls import path
from .template_views import (
    EscrowDashboardView,
    EscrowTransactionListView,
    EscrowTransactionDetailView,
    MilestonePaymentListView,
    MilestonePaymentDetailView,
    EscrowReleaseListView,
    DisputeListView,
    DisputeDetailView,
    EscrowPayoutListView,
    EscrowAuditListView,
    HTMXEscrowStatsView,
)

app_name = 'escrow'

urlpatterns = [
    # Dashboard
    path('', EscrowDashboardView.as_view(), name='dashboard'),

    # Escrow Transactions
    path('transactions/', EscrowTransactionListView.as_view(), name='escrow-list'),
    path('transactions/<int:pk>/', EscrowTransactionDetailView.as_view(), name='escrow-detail'),

    # Milestones
    path('milestones/', MilestonePaymentListView.as_view(), name='milestone-list'),
    path('milestones/<int:pk>/', MilestonePaymentDetailView.as_view(), name='milestone-detail'),

    # Releases
    path('releases/', EscrowReleaseListView.as_view(), name='release-list'),

    # Disputes
    path('disputes/', DisputeListView.as_view(), name='dispute-list'),
    path('disputes/<int:pk>/', DisputeDetailView.as_view(), name='dispute-detail'),

    # Payouts
    path('payouts/', EscrowPayoutListView.as_view(), name='payout-list'),

    # Audit Logs
    path('audit/', EscrowAuditListView.as_view(), name='audit-list'),

    # HTMX Partials
    path('htmx/stats/', HTMXEscrowStatsView.as_view(), name='htmx-stats'),
]
