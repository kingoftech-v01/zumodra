"""
Tax API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Sum, Count, Q
from django.utils import timezone

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    AvalaraConfig,
    TaxRate,
    TaxCalculation,
    TaxExemption,
    TaxRemittance,
    TaxReport,
)
from .serializers import (
    AvalaraConfigSerializer,
    TaxRateListSerializer,
    TaxRateDetailSerializer,
    TaxCalculationListSerializer,
    TaxCalculationDetailSerializer,
    TaxExemptionListSerializer,
    TaxExemptionDetailSerializer,
    TaxRemittanceListSerializer,
    TaxRemittanceDetailSerializer,
    TaxReportListSerializer,
    TaxReportDetailSerializer,
)


class AvalaraConfigViewSet(SecureTenantViewSet):
    """
    ViewSet for Avalara configuration (owner only).
    Only tenant owner can manage tax configuration.
    """
    queryset = AvalaraConfig.objects.all()
    serializer_class = AvalaraConfigSerializer

    def get_queryset(self):
        """Only tenant owner can access Avalara config"""
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role == 'pdg'):
            return AvalaraConfig.objects.none()
        return super().get_queryset()

    @action(detail=False, methods=['post'])
    def test_connection(self, request):
        """Test Avalara API connection"""
        try:
            config = AvalaraConfig.objects.first()
            if not config:
                return Response(
                    {'detail': 'Avalara not configured'},
                    status=status.HTTP_404_NOT_FOUND
                )

            # This would call Avalara API to test connection
            return Response({
                'detail': 'Avalara connection test would be performed here',
                'note': 'Requires Avalara API integration'
            }, status=status.HTTP_501_NOT_IMPLEMENTED)

        except Exception as e:
            return Response(
                {'detail': f'Connection test failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def sync_tax_codes(self, request):
        """Sync tax codes from Avalara"""
        try:
            config = AvalaraConfig.objects.first()
            if not config or not config.is_active:
                return Response(
                    {'detail': 'Avalara not configured or inactive'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # This would call Avalara API to sync tax codes
            return Response({
                'detail': 'Tax code sync would be performed here',
                'note': 'Requires Avalara API integration'
            }, status=status.HTTP_501_NOT_IMPLEMENTED)

        except Exception as e:
            return Response(
                {'detail': f'Sync failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TaxRateViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for tax rates.
    Tax rates are managed automatically or by admins.
    """
    queryset = TaxRate.objects.filter(is_active=True).order_by(
        'country', 'state_province', 'city'
    )
    filterset_fields = ['country', 'state_province', 'tax_type', 'is_active']
    search_fields = ['country', 'state_province', 'city']
    ordering = ['country', 'state_province', 'city']

    def get_serializer_class(self):
        if self.action == 'list':
            return TaxRateListSerializer
        return TaxRateDetailSerializer


class TaxCalculationViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for tax calculations.
    Tax calculations are created automatically during transactions.
    """
    queryset = TaxCalculation.objects.select_related(
        'payment_transaction', 'subscription_invoice'
    ).order_by('-calculated_at')
    filterset_fields = ['source']
    ordering = ['-calculated_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return TaxCalculationListSerializer
        return TaxCalculationDetailSerializer

    @action(detail=False, methods=['post'])
    def calculate(self, request):
        """
        Calculate tax for a transaction (preview).
        Does not save the calculation.
        """
        amount = request.data.get('amount')
        address = request.data.get('address', {})

        if not amount:
            return Response(
                {'detail': 'Amount is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # This would call Avalara API or use local tax rates
        return Response({
            'detail': 'Tax calculation would be performed here',
            'note': 'Requires Avalara API integration or local rate lookup'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)


class TaxExemptionViewSet(SecureTenantViewSet):
    """
    ViewSet for tax exemptions (admin only).
    Manage customer tax exemption certificates.
    """
    queryset = TaxExemption.objects.select_related('customer').order_by('-issue_date')
    filterset_fields = ['status', 'exemption_type', 'customer']
    search_fields = [
        'customer__email',
        'customer__first_name',
        'customer__last_name',
        'exemption_number',
    ]
    ordering = ['-issue_date']

    def get_serializer_class(self):
        if self.action == 'list':
            return TaxExemptionListSerializer
        return TaxExemptionDetailSerializer

    def get_queryset(self):
        """Only admins can manage tax exemptions"""
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            return TaxExemption.objects.none()
        return super().get_queryset()


class TaxRemittanceViewSet(SecureTenantViewSet):
    """
    ViewSet for tax remittances (admin only).
    Track tax payments to authorities.
    """
    queryset = TaxRemittance.objects.select_related(
        'payment_transaction'
    ).order_by('-due_date')
    filterset_fields = ['status', 'country', 'state_province', 'filing_frequency']
    search_fields = ['remittance_id', 'authority_name']
    ordering = ['-due_date']

    def get_serializer_class(self):
        if self.action == 'list':
            return TaxRemittanceListSerializer
        return TaxRemittanceDetailSerializer

    def get_queryset(self):
        """Only admins can manage tax remittances"""
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            return TaxRemittance.objects.none()
        return super().get_queryset()

    @action(detail=True, methods=['post'])
    def file(self, request, pk=None):
        """Mark remittance as filed"""
        remittance = self.get_object()

        if remittance.status == 'paid':
            return Response(
                {'detail': 'Remittance already filed'},
                status=status.HTTP_400_BAD_REQUEST
            )

        filing_reference = request.data.get('filing_reference', '')

        remittance.status = 'paid'
        remittance.paid_at = timezone.now()
        remittance.filing_reference = filing_reference
        remittance.save(update_fields=[
            'status', 'paid_at', 'filing_reference', 'updated_at'
        ])

        serializer = self.get_serializer(remittance)
        return Response(serializer.data)


class TaxReportViewSet(SecureTenantViewSet):
    """
    ViewSet for tax reports (admin only).
    Generate and view tax reports.
    """
    queryset = TaxReport.objects.select_related('generated_by').order_by('-period_end')
    filterset_fields = ['report_type']
    search_fields = ['report_number']
    ordering = ['-period_end']

    def get_serializer_class(self):
        if self.action == 'list':
            return TaxReportListSerializer
        return TaxReportDetailSerializer

    def get_queryset(self):
        """Only admins can access tax reports"""
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            return TaxReport.objects.none()
        return super().get_queryset()

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Download tax report PDF"""
        report = self.get_object()

        if report.pdf_file:
            return Response({
                'pdf_url': report.pdf_file.url
            })
        else:
            return Response(
                {'detail': 'PDF not yet generated'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=['post'])
    def generate(self, request):
        """Generate new tax report for a period"""
        report_type = request.data.get('report_type')
        period_start = request.data.get('period_start')
        period_end = request.data.get('period_end')

        if not all([report_type, period_start, period_end]):
            return Response(
                {'detail': 'report_type, period_start, and period_end are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # This would generate the report
        return Response({
            'detail': 'Tax report generation would be performed here',
            'note': 'Requires implementation of report generation logic'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)
