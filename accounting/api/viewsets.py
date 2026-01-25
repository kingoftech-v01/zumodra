"""
Accounting API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    AccountingProvider,
    ChartOfAccounts,
    JournalEntry,
    AccountingSyncLog,
    FinancialReport,
    ReconciliationRecord,
)
from .serializers import (
    AccountingProviderListSerializer,
    AccountingProviderDetailSerializer,
    AccountingProviderCreateSerializer,
    ChartOfAccountsListSerializer,
    ChartOfAccountsDetailSerializer,
    JournalEntryListSerializer,
    JournalEntryDetailSerializer,
    JournalEntryCreateSerializer,
    AccountingSyncLogListSerializer,
    AccountingSyncLogDetailSerializer,
    FinancialReportListSerializer,
    FinancialReportDetailSerializer,
    FinancialReportCreateSerializer,
    ReconciliationRecordListSerializer,
    ReconciliationRecordDetailSerializer,
    ReconciliationRecordCreateSerializer,
)


class AccountingProviderViewSet(SecureTenantViewSet):
    """
    Accounting provider management.
    Only accessible to tenant owner (PDG).
    """
    queryset = AccountingProvider.objects.select_related('tenant').order_by('-created_at')
    filterset_fields = ['provider', 'is_active']
    search_fields = ['company_id']
    ordering = ['-created_at']

    def get_queryset(self):
        """Only tenant owner can access accounting provider configuration"""
        queryset = super().get_queryset()

        # Only PDG (owner) can access
        if not (self.request.user.is_staff or
                hasattr(self.request.user, 'tenant_user') and
                self.request.user.tenant_user.role == 'pdg'):
            return AccountingProvider.objects.none()

        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return AccountingProviderListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return AccountingProviderCreateSerializer
        return AccountingProviderDetailSerializer

    @action(detail=True, methods=['post'])
    def connect(self, request, pk=None):
        """
        Initiate OAuth connection to accounting provider.
        Returns authorization URL.
        """
        provider = self.get_object()

        return Response({
            'detail': 'OAuth connection flow would be initiated here',
            'provider': provider.provider,
            'note': 'Requires QuickBooks/Xero OAuth implementation',
            'authorization_url': f'https://{provider.provider}.com/oauth/authorize'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)

    @action(detail=True, methods=['post'])
    def disconnect(self, request, pk=None):
        """Disconnect accounting provider integration"""
        provider = self.get_object()

        provider.is_active = False
        provider.save(update_fields=['is_active'])

        return Response({
            'detail': f'Disconnected from {provider.get_provider_display()}',
            'is_active': False
        })

    @action(detail=True, methods=['post'])
    def sync(self, request, pk=None):
        """
        Trigger manual sync from accounting provider.
        Creates AccountingSyncLog and syncs data.
        """
        provider = self.get_object()

        if not provider.is_active:
            return Response({
                'detail': 'Provider is not active'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Create sync log
        sync_log = AccountingSyncLog.objects.create(
            provider=provider,
            sync_type='manual',
            status='pending',
            sync_started_at=timezone.now()
        )

        return Response({
            'detail': 'Sync initiated',
            'sync_log_id': sync_log.id,
            'note': 'Sync would be performed by background task',
            'status': 'pending'
        }, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=['post'])
    def refresh_token(self, request, pk=None):
        """Refresh OAuth access token for provider"""
        provider = self.get_object()

        return Response({
            'detail': 'Token refresh would be performed here',
            'provider': provider.provider,
            'note': 'Requires OAuth token refresh implementation'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)


class ChartOfAccountsViewSet(SecureReadOnlyViewSet):
    """
    Chart of accounts - read-only.
    Synced from accounting provider.
    """
    queryset = ChartOfAccounts.objects.select_related('provider').order_by('account_number')
    filterset_fields = ['account_type', 'is_active', 'provider']
    search_fields = ['account_number', 'account_name', 'description']
    ordering = ['account_number']

    def get_serializer_class(self):
        if self.action == 'list':
            return ChartOfAccountsListSerializer
        return ChartOfAccountsDetailSerializer


class JournalEntryViewSet(SecureTenantViewSet):
    """
    Journal entry management.
    Only accessible to owner/supervisor/hr_manager.
    """
    queryset = JournalEntry.objects.prefetch_related('lines').order_by('-entry_date', '-entry_number')
    filterset_fields = ['status', 'entry_date']
    search_fields = ['entry_number', 'description']
    ordering = ['-entry_date', '-entry_number']

    def get_queryset(self):
        """Only admin roles can access journal entries"""
        queryset = super().get_queryset()

        # Only PDG, supervisor, or HR manager can access
        allowed_roles = ['pdg', 'supervisor', 'hr_manager']
        if not (self.request.user.is_staff or
                hasattr(self.request.user, 'tenant_user') and
                self.request.user.tenant_user.role in allowed_roles):
            return JournalEntry.objects.none()

        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return JournalEntryListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return JournalEntryCreateSerializer
        return JournalEntryDetailSerializer

    @action(detail=True, methods=['post'])
    def post(self, request, pk=None):
        """Post journal entry (change status to posted)"""
        entry = self.get_object()

        if entry.status == 'posted':
            return Response({
                'detail': 'Entry is already posted'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not entry.is_balanced:
            return Response({
                'detail': 'Cannot post unbalanced entry'
            }, status=status.HTTP_400_BAD_REQUEST)

        entry.status = 'posted'
        entry.save(update_fields=['status'])

        return Response({
            'detail': 'Journal entry posted successfully',
            'status': entry.status
        })

    @action(detail=True, methods=['post'])
    def reverse(self, request, pk=None):
        """Create reversal entry for this journal entry"""
        original_entry = self.get_object()

        if original_entry.status != 'posted':
            return Response({
                'detail': 'Can only reverse posted entries'
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'detail': 'Reversal entry creation would be implemented here',
            'original_entry_id': original_entry.id,
            'note': 'Would create mirror entry with debits/credits swapped'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)


class AccountingSyncLogViewSet(SecureReadOnlyViewSet):
    """
    Accounting sync log - read-only.
    View sync history and status.
    """
    queryset = AccountingSyncLog.objects.select_related('provider').order_by('-started_at')
    filterset_fields = ['status', 'sync_type', 'provider']
    search_fields = ['error_message']
    ordering = ['-started_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return AccountingSyncLogListSerializer
        return AccountingSyncLogDetailSerializer

    @action(detail=True, methods=['post'])
    def retry(self, request, pk=None):
        """Retry failed sync"""
        log = self.get_object()

        if log.status != 'failed':
            return Response({
                'detail': 'Can only retry failed syncs'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Create new sync log
        new_log = AccountingSyncLog.objects.create(
            provider=log.provider,
            sync_type='manual',
            status='pending',
            sync_started_at=timezone.now()
        )

        return Response({
            'detail': 'Sync retry initiated',
            'new_sync_log_id': new_log.id,
            'status': 'pending'
        }, status=status.HTTP_202_ACCEPTED)


class FinancialReportViewSet(SecureTenantViewSet):
    """
    Financial report management.
    Only accessible to owner/supervisor/hr_manager.
    """
    queryset = FinancialReport.objects.select_related('generated_by').order_by('-generated_at')
    filterset_fields = ['report_type', 'status']
    search_fields = []
    ordering = ['-generated_at']

    def get_queryset(self):
        """Only admin roles can access financial reports"""
        queryset = super().get_queryset()

        # Only PDG, supervisor, or HR manager can access
        allowed_roles = ['pdg', 'supervisor', 'hr_manager']
        if not (self.request.user.is_staff or
                hasattr(self.request.user, 'tenant_user') and
                self.request.user.tenant_user.role in allowed_roles):
            return FinancialReport.objects.none()

        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return FinancialReportListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return FinancialReportCreateSerializer
        return FinancialReportDetailSerializer

    def perform_create(self, serializer):
        """Set generated_by to current user"""
        serializer.save(
            generated_by=self.request.user,
            status='pending',
            generated_at=timezone.now()
        )

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Download financial report file"""
        report = self.get_object()

        if report.status != 'completed':
            return Response({
                'detail': 'Report is not ready for download'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not report.file_path:
            return Response({
                'detail': 'Report file not available'
            }, status=status.HTTP_404_NOT_FOUND)

        return Response({
            'detail': 'File download would be served here',
            'file_path': report.file_path,
            'report_type': report.get_report_type_display(),
            'note': 'Requires file serving implementation'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)

    @action(detail=False, methods=['post'])
    def generate(self, request):
        """Generate financial report on demand"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        report = serializer.save(
            generated_by=request.user,
            status='pending',
            generated_at=timezone.now()
        )

        return Response({
            'detail': 'Report generation initiated',
            'report_id': report.id,
            'status': 'pending',
            'note': 'Report would be generated by background task'
        }, status=status.HTTP_202_ACCEPTED)


class ReconciliationRecordViewSet(SecureTenantViewSet):
    """
    Bank reconciliation record management.
    Only accessible to owner/supervisor/hr_manager.
    """
    queryset = ReconciliationRecord.objects.select_related(
        'account', 'reconciled_by'
    ).order_by('-statement_date')
    filterset_fields = ['status', 'account']
    search_fields = ['notes']
    ordering = ['-statement_date']

    def get_queryset(self):
        """Only admin roles can access reconciliation records"""
        queryset = super().get_queryset()

        # Only PDG, supervisor, or HR manager can access
        allowed_roles = ['pdg', 'supervisor', 'hr_manager']
        if not (self.request.user.is_staff or
                hasattr(self.request.user, 'tenant_user') and
                self.request.user.tenant_user.role in allowed_roles):
            return ReconciliationRecord.objects.none()

        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return ReconciliationRecordListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return ReconciliationRecordCreateSerializer
        return ReconciliationRecordDetailSerializer

    @action(detail=True, methods=['post'])
    def reconcile(self, request, pk=None):
        """Mark reconciliation as completed"""
        record = self.get_object()

        if record.status == 'reconciled':
            return Response({
                'detail': 'Record is already reconciled'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if balanced
        difference = abs(record.book_balance - record.bank_balance)
        adjustments = request.data.get('adjustments', {})

        # If there's a difference, adjustments are required
        if difference > 0.01 and not adjustments:
            return Response({
                'detail': f'Adjustments required for difference: ${difference}',
                'book_balance': record.book_balance,
                'bank_balance': record.bank_balance,
                'difference': difference
            }, status=status.HTTP_400_BAD_REQUEST)

        record.status = 'reconciled'
        record.reconciled_by = request.user
        record.reconciled_at = timezone.now()
        if adjustments:
            record.adjustments = adjustments
        record.save()

        return Response({
            'detail': 'Reconciliation completed successfully',
            'status': record.status,
            'reconciled_at': record.reconciled_at
        })
