"""
Expenses Frontend URLs
"""

from django.urls import path
from .template_views import (
    ExpenseDashboardView,
    ExpenseReportListView,
    ExpenseReportDetailView,
    ExpenseCategoryListView,
    ExpenseApprovalListView,
    ReimbursementListView,
    MileageRateListView,
    HTMXExpenseStatsView,
)

app_name = 'expenses'

urlpatterns = [
    # Dashboard
    path('', ExpenseDashboardView.as_view(), name='dashboard'),

    # Expense Reports
    path('reports/', ExpenseReportListView.as_view(), name='report-list'),
    path('reports/<int:pk>/', ExpenseReportDetailView.as_view(), name='report-detail'),

    # Categories
    path('categories/', ExpenseCategoryListView.as_view(), name='category-list'),

    # Approvals
    path('approvals/', ExpenseApprovalListView.as_view(), name='approval-list'),

    # Reimbursements
    path('reimbursements/', ReimbursementListView.as_view(), name='reimbursement-list'),

    # Mileage Rates
    path('mileage-rates/', MileageRateListView.as_view(), name='mileage-rate-list'),

    # HTMX Partials
    path('htmx/stats/', HTMXExpenseStatsView.as_view(), name='htmx-stats'),
]
