"""
Stripe Connect API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Sum, Count, Q
from django.utils import timezone

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    ConnectedAccount,
    StripeConnectOnboarding,
    PlatformFee,
    PayoutSchedule,
    Transfer,
    BalanceTransaction,
)
from .serializers import (
    ConnectedAccountListSerializer,
    ConnectedAccountDetailSerializer,
    StripeConnectOnboardingSerializer,
    PlatformFeeSerializer,
    PayoutScheduleSerializer,
    TransferListSerializer,
    TransferDetailSerializer,
    BalanceTransactionListSerializer,
    BalanceTransactionDetailSerializer,
)


class ConnectedAccountViewSet(SecureTenantViewSet):
    """
    ViewSet for Stripe Connect accounts.
    Provider account management for marketplace.
    """
    queryset = ConnectedAccount.objects.select_related('provider').order_by('-created_at')
    filterset_fields = ['status', 'charges_enabled', 'payouts_enabled', 'country']
    search_fields = [
        'provider__email',
        'provider__first_name',
        'provider__last_name',
        'stripe_account_id',
    ]
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ConnectedAccountListSerializer
        return ConnectedAccountDetailSerializer

    @action(detail=True, methods=['post'])
    def create_account(self, request, pk=None):
        """
        Create Stripe Connect account for provider.
        This would typically call Stripe API to create account.
        """
        # This is a placeholder - actual implementation would call Stripe API
        return Response({
            'detail': 'Stripe account creation would be handled here',
            'note': 'Requires Stripe API integration'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)

    @action(detail=True, methods=['get'])
    def dashboard_link(self, request, pk=None):
        """
        Get Stripe Dashboard login link for provider.
        """
        account = self.get_object()

        # Check if existing link is still valid
        if account.dashboard_link_expires and account.dashboard_link_expires > timezone.now():
            return Response({
                'detail': 'Dashboard link is still valid',
                'expires_at': account.dashboard_link_expires,
            })

        # This would call Stripe API to generate new login link
        return Response({
            'detail': 'Dashboard link generation would be handled here',
            'note': 'Requires Stripe API integration'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)

    @action(detail=True, methods=['post'])
    def refresh_requirements(self, request, pk=None):
        """
        Refresh account requirements from Stripe.
        """
        account = self.get_object()

        # This would call Stripe API to fetch latest requirements
        return Response({
            'detail': 'Requirements refresh would be handled here',
            'note': 'Requires Stripe API integration'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)


class StripeConnectOnboardingViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for Stripe Connect onboarding.
    Onboarding is managed by the system.
    """
    queryset = StripeConnectOnboarding.objects.select_related(
        'connected_account__provider'
    ).order_by('-created_at')
    serializer_class = StripeConnectOnboardingSerializer
    filterset_fields = ['status', 'connected_account']
    ordering = ['-created_at']

    @action(detail=True, methods=['post'])
    def create_onboarding_link(self, request, pk=None):
        """
        Create new onboarding link for incomplete onboarding.
        """
        onboarding = self.get_object()

        if onboarding.status == 'completed':
            return Response(
                {'detail': 'Onboarding already completed'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # This would call Stripe API to create account link
        return Response({
            'detail': 'Onboarding link creation would be handled here',
            'note': 'Requires Stripe API integration'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)


class PlatformFeeViewSet(SecureTenantViewSet):
    """
    ViewSet for platform fees (admin only).
    Configure marketplace fees.
    """
    queryset = PlatformFee.objects.order_by('name')
    serializer_class = PlatformFeeSerializer
    filterset_fields = ['is_active', 'applies_to']
    search_fields = ['name', 'description']
    ordering = ['name']

    def get_queryset(self):
        """Only admins can manage platform fees"""
        queryset = super().get_queryset()

        # Check if user is admin
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            return PlatformFee.objects.none()

        return queryset

    @action(detail=True, methods=['post'])
    def calculate(self, request, pk=None):
        """Calculate fee for a given amount"""
        fee = self.get_object()
        amount = request.data.get('amount')

        if not amount:
            return Response(
                {'detail': 'Amount is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            amount = float(amount)
        except ValueError:
            return Response(
                {'detail': 'Invalid amount'},
                status=status.HTTP_400_BAD_REQUEST
            )

        calculated_fee = fee.calculate_fee(amount)

        return Response({
            'amount': amount,
            'fee': float(calculated_fee),
            'net_amount': amount - float(calculated_fee),
            'currency': fee.currency,
        })


class PayoutScheduleViewSet(SecureTenantViewSet):
    """
    ViewSet for payout schedules.
    """
    queryset = PayoutSchedule.objects.select_related(
        'connected_account__provider'
    ).order_by('-created_at')
    serializer_class = PayoutScheduleSerializer
    filterset_fields = ['interval', 'is_active', 'connected_account']
    ordering = ['-created_at']


class TransferViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for transfers.
    Transfers are created automatically by the system.
    """
    queryset = Transfer.objects.select_related(
        'connected_account__provider', 'source_transaction'
    ).order_by('-created_at')
    filterset_fields = ['status', 'connected_account', 'reversed']
    search_fields = [
        'transfer_id',
        'stripe_transfer_id',
        'connected_account__provider__email',
    ]
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return TransferListSerializer
        return TransferDetailSerializer

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get transfer summary statistics"""
        queryset = self.filter_queryset(self.get_queryset())

        # Filter by date range
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        if start_date:
            queryset = queryset.filter(created_at__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__date__lte=end_date)

        # Calculate summary
        summary = {
            'total_transfers': queryset.count(),
            'total_volume': float(queryset.aggregate(total=Sum('amount'))['total'] or 0),
            'by_status': {}
        }

        # Group by status
        status_counts = queryset.values('status').annotate(
            count=Count('id'),
            volume=Sum('amount')
        ).order_by('status')

        for item in status_counts:
            summary['by_status'][item['status']] = {
                'count': item['count'],
                'volume': float(item['volume'] or 0)
            }

        return Response(summary)


class BalanceTransactionViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for balance transactions.
    Balance transactions are synced from Stripe.
    """
    queryset = BalanceTransaction.objects.select_related(
        'connected_account__provider', 'transfer'
    ).order_by('-created_at_stripe')
    filterset_fields = ['transaction_type', 'connected_account']
    search_fields = [
        'stripe_balance_transaction_id',
        'connected_account__provider__email',
    ]
    ordering = ['-created_at_stripe']

    def get_serializer_class(self):
        if self.action == 'list':
            return BalanceTransactionListSerializer
        return BalanceTransactionDetailSerializer

    @action(detail=False, methods=['get'])
    def balance_summary(self, request):
        """Get balance summary for an account"""
        account_id = request.query_params.get('account')

        if not account_id:
            return Response(
                {'detail': 'Account ID is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.filter_queryset(self.get_queryset()).filter(
            connected_account_id=account_id
        )

        # Calculate balance
        balance = queryset.aggregate(total=Sum('net'))['total'] or 0

        # Group by transaction type
        by_type = queryset.values('transaction_type').annotate(
            total=Sum('net'),
            count=Count('id')
        ).order_by('transaction_type')

        return Response({
            'account_id': account_id,
            'current_balance': float(balance),
            'by_transaction_type': [
                {
                    'type': item['transaction_type'],
                    'total': float(item['total'] or 0),
                    'count': item['count']
                }
                for item in by_type
            ]
        })
