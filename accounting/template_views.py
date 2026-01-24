"""
Accounting App Frontend Views - Accounting Integration Management
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import timedelta

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    AccountingProvider,
    ChartOfAccounts,
    JournalEntry,
    JournalEntryLine,
    AccountingSyncLog,
    FinancialReport,
    ReconciliationRecord,
)


class AccountingDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main accounting dashboard with integration status and recent activity"""
    template_name = 'accounting/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.request.tenant

        # Accounting provider status
        try:
            provider = AccountingProvider.objects.get(tenant=tenant, is_active=True)
            context['provider'] = provider
            context['is_connected'] = True
            context['last_sync'] = provider.last_sync
        except AccountingProvider.DoesNotExist:
            context['is_connected'] = False
            context['provider'] = None

        # Chart of accounts summary
        context['total_accounts'] = ChartOfAccounts.objects.count()

        # Recent journal entries
        thirty_days_ago = timezone.now() - timedelta(days=30)
        context['recent_entries_count'] = JournalEntry.objects.filter(
            date__gte=thirty_days_ago.date()
        ).count()

        # Sync history
        context['recent_syncs'] = AccountingSyncLog.objects.select_related(
            'provider'
        ).order_by('-sync_started_at')[:10]

        # Sync errors
        context['failed_syncs_count'] = AccountingSyncLog.objects.filter(
            status='failed'
        ).count()

        # Financial reports
        context['available_reports'] = FinancialReport.objects.filter(
            status='completed'
        ).order_by('-generated_at')[:5]

        # Pending reconciliations
        context['pending_reconciliations'] = ReconciliationRecord.objects.filter(
            status='pending'
        ).count()

        return context


class AccountingProviderListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all accounting provider connections"""
    model = AccountingProvider
    template_name = 'accounting/provider_list.html'
    partial_template_name = 'accounting/partials/_provider_list.html'
    context_object_name = 'providers'
    paginate_by = 20

    def get_queryset(self):
        queryset = AccountingProvider.objects.order_by('-created_at')

        # Filter by provider type
        provider_type = self.request.GET.get('provider')
        if provider_type:
            queryset = queryset.filter(provider=provider_type)

        # Filter by status
        status = self.request.GET.get('status')
        if status == 'active':
            queryset = queryset.filter(is_active=True)
        elif status == 'inactive':
            queryset = queryset.filter(is_active=False)

        return queryset


class AccountingProviderDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Provider detail with sync history and configuration"""
    model = AccountingProvider
    template_name = 'accounting/provider_detail.html'
    context_object_name = 'provider'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        provider = self.object

        # Sync history
        context['sync_logs'] = provider.sync_logs.order_by('-sync_started_at')[:50]

        # Sync statistics
        context['total_syncs'] = provider.sync_logs.count()
        context['successful_syncs'] = provider.sync_logs.filter(status='success').count()
        context['failed_syncs'] = provider.sync_logs.filter(status='failed').count()

        # Journal entries created by this provider
        context['journal_entries_count'] = JournalEntry.objects.filter(
            sync_log__provider=provider
        ).count()

        return context


class ChartOfAccountsListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all chart of accounts"""
    model = ChartOfAccounts
    template_name = 'accounting/chart_of_accounts_list.html'
    partial_template_name = 'accounting/partials/_chart_of_accounts_list.html'
    context_object_name = 'accounts'
    paginate_by = 50

    def get_queryset(self):
        queryset = ChartOfAccounts.objects.select_related('provider').order_by('account_code')

        # Filter by account type
        account_type = self.request.GET.get('account_type')
        if account_type:
            queryset = queryset.filter(account_type=account_type)

        # Filter by provider
        provider_id = self.request.GET.get('provider')
        if provider_id:
            queryset = queryset.filter(provider_id=provider_id)

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(account_code__icontains=search) |
                Q(account_name__icontains=search) |
                Q(description__icontains=search)
            )

        return queryset


class JournalEntryListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all journal entries"""
    model = JournalEntry
    template_name = 'accounting/journal_entry_list.html'
    partial_template_name = 'accounting/partials/_journal_entry_list.html'
    context_object_name = 'entries'
    paginate_by = 20

    def get_queryset(self):
        queryset = JournalEntry.objects.prefetch_related(
            'lines'
        ).order_by('-date', '-entry_number')

        # Filter by date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(date__gte=start_date)
        if end_date:
            queryset = queryset.filter(date__lte=end_date)

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Search by entry number or description
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(entry_number__icontains=search) |
                Q(description__icontains=search)
            )

        return queryset


class JournalEntryDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Journal entry detail with all lines"""
    model = JournalEntry
    template_name = 'accounting/journal_entry_detail.html'
    context_object_name = 'entry'

    def get_queryset(self):
        return JournalEntry.objects.prefetch_related('lines')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        entry = self.object

        # Calculate totals
        context['total_debits'] = entry.lines.aggregate(
            total=Sum('debit')
        )['total'] or 0

        context['total_credits'] = entry.lines.aggregate(
            total=Sum('credit')
        )['total'] or 0

        context['is_balanced'] = abs(context['total_debits'] - context['total_credits']) < 0.01

        return context


class AccountingSyncLogListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all sync logs"""
    model = AccountingSyncLog
    template_name = 'accounting/sync_log_list.html'
    partial_template_name = 'accounting/partials/_sync_log_list.html'
    context_object_name = 'logs'
    paginate_by = 20

    def get_queryset(self):
        queryset = AccountingSyncLog.objects.select_related(
            'provider'
        ).order_by('-sync_started_at')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by provider
        provider_id = self.request.GET.get('provider')
        if provider_id:
            queryset = queryset.filter(provider_id=provider_id)

        # Filter by sync type
        sync_type = self.request.GET.get('sync_type')
        if sync_type:
            queryset = queryset.filter(sync_type=sync_type)

        return queryset


class AccountingSyncLogDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Sync log detail with error information"""
    model = AccountingSyncLog
    template_name = 'accounting/sync_log_detail.html'
    context_object_name = 'log'

    def get_queryset(self):
        return AccountingSyncLog.objects.select_related('provider')


class FinancialReportListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all financial reports"""
    model = FinancialReport
    template_name = 'accounting/financial_report_list.html'
    partial_template_name = 'accounting/partials/_financial_report_list.html'
    context_object_name = 'reports'
    paginate_by = 20

    def get_queryset(self):
        queryset = FinancialReport.objects.select_related(
            'generated_by'
        ).order_by('-generated_at')

        # Filter by report type
        report_type = self.request.GET.get('report_type')
        if report_type:
            queryset = queryset.filter(report_type=report_type)

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(period_start__gte=start_date)
        if end_date:
            queryset = queryset.filter(period_end__lte=end_date)

        return queryset


class FinancialReportDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Financial report detail with download option"""
    model = FinancialReport
    template_name = 'accounting/financial_report_detail.html'
    context_object_name = 'report'

    def get_queryset(self):
        return FinancialReport.objects.select_related('generated_by')


class ReconciliationRecordListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all bank reconciliation records"""
    model = ReconciliationRecord
    template_name = 'accounting/reconciliation_list.html'
    partial_template_name = 'accounting/partials/_reconciliation_list.html'
    context_object_name = 'reconciliations'
    paginate_by = 20

    def get_queryset(self):
        queryset = ReconciliationRecord.objects.select_related(
            'reconciled_by'
        ).order_by('-reconciliation_date')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by account
        account_id = self.request.GET.get('account')
        if account_id:
            queryset = queryset.filter(account_id=account_id)

        # Filter by date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(reconciliation_date__gte=start_date)
        if end_date:
            queryset = queryset.filter(reconciliation_date__lte=end_date)

        return queryset


class ReconciliationRecordDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Reconciliation record detail"""
    model = ReconciliationRecord
    template_name = 'accounting/reconciliation_detail.html'
    context_object_name = 'reconciliation'

    def get_queryset(self):
        return ReconciliationRecord.objects.select_related('account', 'reconciled_by')


class HTMXAccountingStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for real-time accounting stats"""
    template_name = 'accounting/partials/_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Provider status
        try:
            provider = AccountingProvider.objects.get(is_active=True)
            context['is_connected'] = True
            context['provider_name'] = provider.get_provider_display()
        except AccountingProvider.DoesNotExist:
            context['is_connected'] = False

        # Recent sync status
        try:
            latest_sync = AccountingSyncLog.objects.latest('sync_started_at')
            context['last_sync_status'] = latest_sync.status
            context['last_sync_at'] = latest_sync.sync_started_at
        except AccountingSyncLog.DoesNotExist:
            context['last_sync_status'] = None

        # Unreconciled items
        context['unreconciled_count'] = ReconciliationRecord.objects.filter(
            status='pending'
        ).count()

        # Failed syncs (last 7 days)
        seven_days_ago = timezone.now() - timedelta(days=7)
        context['recent_failed_syncs'] = AccountingSyncLog.objects.filter(
            status='failed',
            sync_started_at__gte=seven_days_ago
        ).count()

        return context
