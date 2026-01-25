"""
Stripe Connect App Frontend Views - Marketplace Payment Management
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.db.models import Sum, Count, Q, Avg
from django.utils import timezone
from datetime import timedelta

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    ConnectedAccount,
    StripeConnectOnboarding,
    PlatformFee,
    PayoutSchedule,
    Transfer,
    BalanceTransaction,
)


class StripeConnectDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main Stripe Connect dashboard with overview stats"""
    template_name = 'stripe_connect/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        today = timezone.now().date()
        thirty_days_ago = today - timedelta(days=30)

        # Connected accounts stats
        context['total_accounts'] = ConnectedAccount.objects.count()
        context['enabled_accounts'] = ConnectedAccount.objects.filter(status='enabled').count()
        context['pending_accounts'] = ConnectedAccount.objects.filter(
            status__in=['incomplete', 'pending']
        ).count()

        # Transfers (last 30 days)
        recent_transfers = Transfer.objects.filter(created_at__date__gte=thirty_days_ago)
        context['transfers_count_30d'] = recent_transfers.count()
        context['transfers_volume_30d'] = recent_transfers.filter(
            status='paid'
        ).aggregate(total=Sum('amount'))['total'] or 0

        # Platform fees collected
        context['platform_fees_collected'] = BalanceTransaction.objects.filter(
            transaction_type='fee',
            created_at__date__gte=thirty_days_ago
        ).aggregate(total=Sum('net'))['total'] or 0

        # Pending payouts
        pending_transfers = Transfer.objects.filter(status__in=['pending', 'in_transit'])
        context['pending_payouts_count'] = pending_transfers.count()
        context['pending_payouts_amount'] = pending_transfers.aggregate(
            total=Sum('amount')
        )['total'] or 0

        # Recent activity
        context['recent_accounts'] = ConnectedAccount.objects.select_related(
            'provider'
        ).order_by('-created_at')[:10]

        context['recent_transfers'] = Transfer.objects.select_related(
            'connected_account__provider'
        ).order_by('-created_at')[:10]

        return context


class ConnectedAccountListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all connected accounts"""
    model = ConnectedAccount
    template_name = 'stripe_connect/account_list.html'
    partial_template_name = 'stripe_connect/partials/_account_list.html'
    context_object_name = 'accounts'
    paginate_by = 20

    def get_queryset(self):
        queryset = ConnectedAccount.objects.select_related('provider').order_by('-created_at')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by capabilities
        if self.request.GET.get('payouts_enabled') == 'true':
            queryset = queryset.filter(payouts_enabled=True)
        if self.request.GET.get('charges_enabled') == 'true':
            queryset = queryset.filter(charges_enabled=True)

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(provider__email__icontains=search) |
                Q(provider__first_name__icontains=search) |
                Q(provider__last_name__icontains=search) |
                Q(stripe_account_id__icontains=search)
            )

        return queryset


class ConnectedAccountDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Connected account detail with transfers and balance"""
    model = ConnectedAccount
    template_name = 'stripe_connect/account_detail.html'
    context_object_name = 'account'

    def get_queryset(self):
        return ConnectedAccount.objects.select_related('provider')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        account = self.object

        # Transfers
        context['transfers'] = account.transfers.order_by('-created_at')[:20]
        context['total_transferred'] = account.transfers.filter(
            status='paid'
        ).aggregate(total=Sum('amount'))['total'] or 0

        # Balance transactions
        context['balance_transactions'] = account.balance_transactions.order_by(
            '-created_at_stripe'
        )[:30]

        # Current balance
        balance_sum = account.balance_transactions.aggregate(total=Sum('net'))['total'] or 0
        context['current_balance'] = balance_sum

        # Onboarding status
        try:
            context['onboarding'] = account.onboarding
        except StripeConnectOnboarding.DoesNotExist:
            context['onboarding'] = None

        # Payout schedule
        try:
            context['payout_schedule'] = account.payout_schedule
        except PayoutSchedule.DoesNotExist:
            context['payout_schedule'] = None

        return context


class StripeConnectOnboardingListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all onboarding flows"""
    model = StripeConnectOnboarding
    template_name = 'stripe_connect/onboarding_list.html'
    partial_template_name = 'stripe_connect/partials/_onboarding_list.html'
    context_object_name = 'onboardings'
    paginate_by = 20

    def get_queryset(self):
        return StripeConnectOnboarding.objects.select_related(
            'connected_account__provider'
        ).order_by('-created_at')


class PlatformFeeListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all platform fees (admin only)"""
    model = PlatformFee
    template_name = 'stripe_connect/fee_list.html'
    partial_template_name = 'stripe_connect/partials/_fee_list.html'
    context_object_name = 'fees'
    paginate_by = 20

    def get_queryset(self):
        queryset = PlatformFee.objects.order_by('name')

        # Filter by status
        if self.request.GET.get('active') == 'true':
            queryset = queryset.filter(is_active=True)
        elif self.request.GET.get('active') == 'false':
            queryset = queryset.filter(is_active=False)

        return queryset


class TransferListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all transfers"""
    model = Transfer
    template_name = 'stripe_connect/transfer_list.html'
    partial_template_name = 'stripe_connect/partials/_transfer_list.html'
    context_object_name = 'transfers'
    paginate_by = 20

    def get_queryset(self):
        queryset = Transfer.objects.select_related(
            'connected_account__provider'
        ).order_by('-created_at')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by account
        account_id = self.request.GET.get('account')
        if account_id:
            queryset = queryset.filter(connected_account_id=account_id)

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(transfer_id__icontains=search) |
                Q(stripe_transfer_id__icontains=search) |
                Q(connected_account__provider__email__icontains=search)
            )

        return queryset


class TransferDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Transfer detail view"""
    model = Transfer
    template_name = 'stripe_connect/transfer_detail.html'
    context_object_name = 'transfer'

    def get_queryset(self):
        return Transfer.objects.select_related(
            'connected_account__provider', 'source_transaction'
        )


class BalanceTransactionListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List balance transactions"""
    model = BalanceTransaction
    template_name = 'stripe_connect/balance_list.html'
    partial_template_name = 'stripe_connect/partials/_balance_list.html'
    context_object_name = 'transactions'
    paginate_by = 50

    def get_queryset(self):
        queryset = BalanceTransaction.objects.select_related(
            'connected_account__provider', 'transfer'
        ).order_by('-created_at_stripe')

        # Filter by account
        account_id = self.request.GET.get('account')
        if account_id:
            queryset = queryset.filter(connected_account_id=account_id)

        # Filter by type
        transaction_type = self.request.GET.get('type')
        if transaction_type:
            queryset = queryset.filter(transaction_type=transaction_type)

        return queryset


class HTMXStripeConnectStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for real-time Stripe Connect stats"""
    template_name = 'stripe_connect/partials/_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Quick stats
        context['enabled_accounts'] = ConnectedAccount.objects.filter(status='enabled').count()
        context['pending_accounts'] = ConnectedAccount.objects.filter(
            status__in=['incomplete', 'pending']
        ).count()

        pending_transfers = Transfer.objects.filter(status__in=['pending', 'in_transit'])
        context['pending_transfers'] = pending_transfers.count()
        context['pending_amount'] = pending_transfers.aggregate(
            total=Sum('amount')
        )['total'] or 0

        return context
