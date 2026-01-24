"""
Billing App Frontend Views - Platform Subscription Management (PUBLIC Schema)
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import timedelta

from core.mixins import HTMXMixin
from .models import (
    SubscriptionPlan,
    TenantSubscription,
    PlatformInvoice,
    BillingHistory,
)


class PublicPricingView(TemplateView):
    """
    Public pricing page - NO authentication required.
    Shows all active subscription plans.
    """
    template_name = 'billing/pricing.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get all public, active plans
        context['plans'] = SubscriptionPlan.objects.filter(
            is_active=True,
            is_public=True
        ).order_by('sort_order', 'price_monthly')

        return context


class TenantBillingDashboardView(LoginRequiredMixin, TemplateView):
    """
    Tenant's billing dashboard.
    Shows current subscription, usage, and invoices for the user's tenant.
    """
    template_name = 'billing/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get user's tenant
        try:
            tenant = self.request.user.tenant  # Assumes user has tenant relationship
        except AttributeError:
            context['no_tenant'] = True
            return context

        # Current subscription
        try:
            context['subscription'] = TenantSubscription.objects.get(
                tenant=tenant,
                status__in=['active', 'trialing']
            )
        except TenantSubscription.DoesNotExist:
            context['subscription'] = None

        # Recent invoices
        context['recent_invoices'] = PlatformInvoice.objects.filter(
            tenant=tenant
        ).order_by('-invoice_date')[:10]

        # Unpaid invoices
        unpaid = PlatformInvoice.objects.filter(
            tenant=tenant,
            status__in=['open', 'past_due']
        )
        context['unpaid_invoices_count'] = unpaid.count()
        context['unpaid_amount'] = unpaid.aggregate(
            total=Sum('amount_due')
        )['total'] or 0

        # Billing history
        context['recent_history'] = BillingHistory.objects.filter(
            tenant=tenant
        ).select_related('old_plan', 'new_plan').order_by('-created_at')[:10]

        return context


class SubscriptionPlanListView(HTMXMixin, ListView):
    """
    List all available subscription plans (public or authenticated).
    """
    model = SubscriptionPlan
    template_name = 'billing/plan_list.html'
    partial_template_name = 'billing/partials/_plan_list.html'
    context_object_name = 'plans'
    paginate_by = 20

    def get_queryset(self):
        queryset = SubscriptionPlan.objects.filter(is_active=True).order_by(
            'sort_order', 'price_monthly'
        )

        # For public access, only show public plans
        if not self.request.user.is_authenticated:
            queryset = queryset.filter(is_public=True)

        return queryset


class SubscriptionPlanDetailView(DetailView):
    """
    Plan detail page (public).
    """
    model = SubscriptionPlan
    template_name = 'billing/plan_detail.html'
    context_object_name = 'plan'

    def get_queryset(self):
        queryset = SubscriptionPlan.objects.filter(is_active=True)

        # For public access, only show public plans
        if not self.request.user.is_authenticated:
            queryset = queryset.filter(is_public=True)

        return queryset


class TenantSubscriptionDetailView(LoginRequiredMixin, DetailView):
    """
    View tenant's own subscription.
    Users can only view their own tenant's subscription.
    """
    model = TenantSubscription
    template_name = 'billing/subscription_detail.html'
    context_object_name = 'subscription'

    def get_queryset(self):
        # Get user's tenant
        try:
            tenant = self.request.user.tenant
            return TenantSubscription.objects.filter(tenant=tenant).select_related('plan')
        except AttributeError:
            return TenantSubscription.objects.none()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Invoices for this subscription
        context['invoices'] = PlatformInvoice.objects.filter(
            subscription=self.object
        ).order_by('-invoice_date')[:20]

        # History for this subscription
        context['history'] = BillingHistory.objects.filter(
            subscription=self.object
        ).select_related('old_plan', 'new_plan').order_by('-created_at')[:20]

        return context


class PlatformInvoiceListView(LoginRequiredMixin, HTMXMixin, ListView):
    """
    List tenant's platform invoices.
    Users can only view their own tenant's invoices.
    """
    model = PlatformInvoice
    template_name = 'billing/invoice_list.html'
    partial_template_name = 'billing/partials/_invoice_list.html'
    context_object_name = 'invoices'
    paginate_by = 20

    def get_queryset(self):
        # Get user's tenant
        try:
            tenant = self.request.user.tenant
            queryset = PlatformInvoice.objects.filter(tenant=tenant).select_related(
                'subscription__plan'
            ).order_by('-invoice_date')
        except AttributeError:
            return PlatformInvoice.objects.none()

        # Filter by status
        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Filter overdue
        if self.request.GET.get('overdue') == 'true':
            queryset = queryset.filter(
                status='open',
                due_date__lt=timezone.now().date()
            )

        return queryset


class PlatformInvoiceDetailView(LoginRequiredMixin, DetailView):
    """
    View invoice detail.
    Users can only view their own tenant's invoices.
    """
    model = PlatformInvoice
    template_name = 'billing/invoice_detail.html'
    context_object_name = 'invoice'

    def get_queryset(self):
        # Get user's tenant
        try:
            tenant = self.request.user.tenant
            return PlatformInvoice.objects.filter(tenant=tenant).select_related(
                'subscription__plan'
            )
        except AttributeError:
            return PlatformInvoice.objects.none()


class BillingHistoryListView(LoginRequiredMixin, HTMXMixin, ListView):
    """
    View billing history for tenant.
    """
    model = BillingHistory
    template_name = 'billing/history_list.html'
    partial_template_name = 'billing/partials/_history_list.html'
    context_object_name = 'history'
    paginate_by = 50

    def get_queryset(self):
        # Get user's tenant
        try:
            tenant = self.request.user.tenant
            return BillingHistory.objects.filter(tenant=tenant).select_related(
                'subscription', 'old_plan', 'new_plan', 'changed_by'
            ).order_by('-created_at')
        except AttributeError:
            return BillingHistory.objects.none()


class HTMXBillingStatsView(LoginRequiredMixin, TemplateView):
    """HTMX partial for billing stats"""
    template_name = 'billing/partials/_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get user's tenant
        try:
            tenant = self.request.user.tenant
        except AttributeError:
            return context

        # Current subscription status
        try:
            subscription = TenantSubscription.objects.get(
                tenant=tenant,
                status__in=['active', 'trialing']
            )
            context['subscription_status'] = subscription.get_status_display()
            context['plan_name'] = subscription.plan.name
            context['days_until_renewal'] = subscription.days_until_renewal
        except TenantSubscription.DoesNotExist:
            context['subscription_status'] = 'No Active Subscription'

        # Unpaid invoices
        unpaid = PlatformInvoice.objects.filter(
            tenant=tenant,
            status__in=['open', 'past_due']
        )
        context['unpaid_count'] = unpaid.count()
        context['unpaid_amount'] = unpaid.aggregate(total=Sum('amount_due'))['total'] or 0

        return context
