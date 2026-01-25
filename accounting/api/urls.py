"""
Accounting API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    AccountingProviderViewSet,
    ChartOfAccountsViewSet,
    JournalEntryViewSet,
    AccountingSyncLogViewSet,
    FinancialReportViewSet,
    ReconciliationRecordViewSet,
)

app_name = 'accounting'

router = DefaultRouter()
router.register(r'providers', AccountingProviderViewSet, basename='provider')
router.register(r'accounts', ChartOfAccountsViewSet, basename='account')
router.register(r'journal-entries', JournalEntryViewSet, basename='journal-entry')
router.register(r'sync-logs', AccountingSyncLogViewSet, basename='sync-log')
router.register(r'reports', FinancialReportViewSet, basename='report')
router.register(r'reconciliations', ReconciliationRecordViewSet, basename='reconciliation')

urlpatterns = router.urls
