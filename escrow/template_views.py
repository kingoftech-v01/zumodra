"""
Escrow Template Views - Frontend HTML Views
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import timedelta

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    EscrowTransaction,
    MilestonePayment,
    EscrowRelease,
    Dispute,
    EscrowPayout,
    EscrowAudit,
)


class EscrowDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main escrow dashboard with overview stats"""
    template_name = 'escrow/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Filter based on user role
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor']:
            # Admins see all escrow transactions
            escrow_queryset = EscrowTransaction.objects.filter(tenant=self.request.tenant)
        else:
            # Regular users see only their own
            escrow_queryset = EscrowTransaction.objects.filter(
                tenant=self.request.tenant
            ).filter(
                Q(client=self.request.user) | Q(provider=self.request.user)
            )

        # Escrow stats
        context['total_in_escrow'] = escrow_queryset.filter(
            status='funded'
        ).aggregate(total=Sum('amount'))['total'] or 0

        context['pending_releases'] = escrow_queryset.filter(
            status='funded',
            work_completed_at__isnull=False
        ).count()

        context['active_disputes'] = Dispute.objects.filter(
            tenant=self.request.tenant,
            status__in=['open', 'under_review']
        ).count()

        context['pending_payouts'] = EscrowPayout.objects.filter(
            tenant=self.request.tenant,
            status='pending'
        ).count()

        # Recent escrow transactions
        context['recent_escrows'] = escrow_queryset.select_related(
            'client',
            'provider',
            'payment_transaction'
        ).order_by('-created_at')[:10]

        # Milestone stats
        context['active_milestones'] = MilestonePayment.objects.filter(
            status__in=['in_progress', 'completed']
        ).count()

        return context


class EscrowTransactionListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all escrow transactions"""
    model = EscrowTransaction
    template_name = 'escrow/escrow_list.html'
    partial_template_name = 'escrow/partials/_escrow_list.html'
    context_object_name = 'escrows'
    paginate_by = 20

    def get_queryset(self):
        queryset = EscrowTransaction.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'client',
            'provider',
            'payment_transaction',
            'content_type'
        ).order_by('-created_at')

        # Filter based on user role
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            # Regular users see only their own
            queryset = queryset.filter(
                Q(client=self.request.user) | Q(provider=self.request.user)
            )

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by role (as client or provider)
        role = self.request.GET.get('role')
        if role == 'client':
            queryset = queryset.filter(client=self.request.user)
        elif role == 'provider':
            queryset = queryset.filter(provider=self.request.user)

        # Search
        search = self.request.GET.get('q')
        if search:
            queryset = queryset.filter(
                Q(escrow_id__icontains=search) |
                Q(description__icontains=search) |
                Q(client__email__icontains=search) |
                Q(provider__email__icontains=search)
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = EscrowTransaction.EscrowStatus.choices
        return context


class EscrowTransactionDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Escrow transaction detail view"""
    model = EscrowTransaction
    template_name = 'escrow/escrow_detail.html'
    context_object_name = 'escrow'

    def get_queryset(self):
        queryset = EscrowTransaction.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'client',
            'provider',
            'payment_transaction',
            'content_type'
        ).prefetch_related(
            'releases',
            'disputes',
            'payouts',
            'audit_logs__actor'
        )

        # Filter based on user role
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            # Regular users see only their own
            queryset = queryset.filter(
                Q(client=self.request.user) | Q(provider=self.request.user)
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Check if user is client or provider
        context['is_client'] = self.object.client == self.request.user
        context['is_provider'] = self.object.provider == self.request.user

        return context


class MilestonePaymentListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List milestone payments"""
    model = MilestonePayment
    template_name = 'escrow/milestone_list.html'
    partial_template_name = 'escrow/partials/_milestone_list.html'
    context_object_name = 'milestones'
    paginate_by = 20

    def get_queryset(self):
        queryset = MilestonePayment.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'escrow_transaction',
            'escrow_transaction__client',
            'escrow_transaction__provider',
            'content_type'
        ).order_by('-created_at')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = MilestonePayment.MilestoneStatus.choices
        return context


class MilestonePaymentDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Milestone payment detail view"""
    model = MilestonePayment
    template_name = 'escrow/milestone_detail.html'
    context_object_name = 'milestone'

    def get_queryset(self):
        return MilestonePayment.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'escrow_transaction',
            'escrow_transaction__client',
            'escrow_transaction__provider',
            'content_type'
        )


class EscrowReleaseListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List escrow releases (read-only)"""
    model = EscrowRelease
    template_name = 'escrow/release_list.html'
    context_object_name = 'releases'
    paginate_by = 20

    def get_queryset(self):
        return EscrowRelease.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'escrow_transaction',
            'escrow_transaction__client',
            'escrow_transaction__provider',
            'approved_by',
            'payout_transaction'
        ).order_by('-released_at')


class DisputeListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List disputes"""
    model = Dispute
    template_name = 'escrow/dispute_list.html'
    partial_template_name = 'escrow/partials/_dispute_list.html'
    context_object_name = 'disputes'
    paginate_by = 20

    def get_queryset(self):
        queryset = Dispute.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'escrow_transaction',
            'escrow_transaction__client',
            'escrow_transaction__provider',
            'initiated_by',
            'resolved_by'
        ).order_by('-opened_at')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = Dispute.DisputeStatus.choices
        return context


class DisputeDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Dispute detail view"""
    model = Dispute
    template_name = 'escrow/dispute_detail.html'
    context_object_name = 'dispute'

    def get_queryset(self):
        return Dispute.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'escrow_transaction',
            'escrow_transaction__client',
            'escrow_transaction__provider',
            'initiated_by',
            'resolved_by'
        )


class EscrowPayoutListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List escrow payouts (read-only)"""
    model = EscrowPayout
    template_name = 'escrow/payout_list.html'
    context_object_name = 'payouts'
    paginate_by = 20

    def get_queryset(self):
        queryset = EscrowPayout.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'escrow_transaction',
            'provider',
            'payment_transaction'
        ).order_by('-initiated_at')

        # Filter based on user role
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            # Regular users see only their own payouts
            queryset = queryset.filter(provider=self.request.user)

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = EscrowPayout.PayoutStatus.choices
        return context


class EscrowAuditListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List escrow audit logs (enterprise only)"""
    model = EscrowAudit
    template_name = 'escrow/audit_list.html'
    context_object_name = 'audit_logs'
    paginate_by = 50

    def dispatch(self, request, *args, **kwargs):
        """Only admins can view audit logs"""
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor']):
            messages.error(request, 'You do not have permission to view audit logs.')
            return redirect('frontend:escrow:dashboard')
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        queryset = EscrowAudit.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'escrow_transaction',
            'actor'
        ).order_by('-created_at')

        # Filter by action
        action = self.request.GET.get('action')
        if action:
            queryset = queryset.filter(action=action)

        # Filter by escrow
        escrow_id = self.request.GET.get('escrow_id')
        if escrow_id:
            queryset = queryset.filter(escrow_transaction__escrow_id=escrow_id)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['action_choices'] = EscrowAudit.AuditAction.choices
        return context


class HTMXEscrowStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for escrow stats"""
    template_name = 'escrow/partials/_quick_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Filter based on user role
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor']:
            escrow_queryset = EscrowTransaction.objects.filter(tenant=self.request.tenant)
        else:
            escrow_queryset = EscrowTransaction.objects.filter(
                tenant=self.request.tenant
            ).filter(
                Q(client=self.request.user) | Q(provider=self.request.user)
            )

        context['total_in_escrow'] = escrow_queryset.filter(
            status='funded'
        ).aggregate(total=Sum('amount'))['total'] or 0

        context['pending_releases'] = escrow_queryset.filter(
            status='funded',
            work_completed_at__isnull=False
        ).count()

        context['active_disputes'] = Dispute.objects.filter(
            tenant=self.request.tenant,
            status__in=['open', 'under_review']
        ).count()

        return context
