"""
Accounting Frontend URLs
"""

from django.urls import path
from .template_views import (
    AccountingDashboardView,
    AccountingProviderListView,
    AccountingProviderDetailView,
    ChartOfAccountsListView,
    JournalEntryListView,
    JournalEntryDetailView,
    AccountingSyncLogListView,
    AccountingSyncLogDetailView,
    FinancialReportListView,
    FinancialReportDetailView,
    ReconciliationRecordListView,
    ReconciliationRecordDetailView,
    HTMXAccountingStatsView,
)

app_name = 'accounting'

urlpatterns = [
    # Dashboard
    path('', AccountingDashboardView.as_view(), name='dashboard'),

    # Accounting Providers
    path('providers/', AccountingProviderListView.as_view(), name='provider-list'),
    path('providers/<uuid:pk>/', AccountingProviderDetailView.as_view(), name='provider-detail'),

    # Chart of Accounts
    path('accounts/', ChartOfAccountsListView.as_view(), name='chart-of-accounts-list'),

    # Journal Entries
    path('journal-entries/', JournalEntryListView.as_view(), name='journal-entry-list'),
    path('journal-entries/<uuid:pk>/', JournalEntryDetailView.as_view(), name='journal-entry-detail'),

    # Sync Logs
    path('sync-logs/', AccountingSyncLogListView.as_view(), name='sync-log-list'),
    path('sync-logs/<uuid:pk>/', AccountingSyncLogDetailView.as_view(), name='sync-log-detail'),

    # Financial Reports
    path('reports/', FinancialReportListView.as_view(), name='financial-report-list'),
    path('reports/<uuid:pk>/', FinancialReportDetailView.as_view(), name='financial-report-detail'),

    # Reconciliation
    path('reconciliations/', ReconciliationRecordListView.as_view(), name='reconciliation-list'),
    path('reconciliations/<uuid:pk>/', ReconciliationRecordDetailView.as_view(), name='reconciliation-detail'),

    # HTMX Partials
    path('htmx/stats/', HTMXAccountingStatsView.as_view(), name='htmx-stats'),
]
