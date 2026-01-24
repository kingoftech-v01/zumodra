"""
Subscriptions App Frontend Views - Tenant's Subscription Product Management
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.db.models import Sum, Count, Q, Avg
from django.utils import timezone
from datetime import timedelta

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    SubscriptionProduct,
    SubscriptionTier,
    CustomerSubscription,
    SubscriptionInvoice,
    UsageRecord,
)


class SubscriptionDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main subscriptions dashboard with overview stats"""
    template_name = 'subscriptions/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.request.tenant
        today = timezone.now().date()

        # Active subscriptions
        active_subscriptions = CustomerSubscription.objects.filter(
            status__in=['active', 'trialing']
        )
        context['total_active_subscriptions'] = active_subscriptions.count()

        # Monthly Recurring Revenue (MRR)
        monthly_subscriptions = active_subscriptions.filter(billing_cycle='monthly')
        yearly_subscriptions = active_subscriptions.filter(billing_cycle='yearly')

        monthly_mrr = monthly_subscriptions.aggregate(
            total=Sum('total_price')
        )['total'] or 0

        yearly_mrr = (yearly_subscriptions.aggregate(
            total=Sum('total_price')
        )['total'] or 0) / 12

        context['mrr'] = monthly_mrr + yearly_mrr

        # Annual Recurring Revenue (ARR)
        context['arr'] = context['mrr'] * 12

        # Trial conversions
        trial_subs = CustomerSubscription.objects.filter(status='trialing')
        context['trial_subscriptions'] = trial_subs.count()

        # Recent subscriptions (last 30 days)
        thirty_days_ago = today - timedelta(days=30)
        context['new_subscriptions_30d'] = CustomerSubscription.objects.filter(
            created_at__date__gte=thirty_days_ago
        ).count()

        # Churn (canceled in last 30 days)
        context['churned_subscriptions_30d'] = CustomerSubscription.objects.filter(
            status='canceled',
            canceled_at__date__gte=thirty_days_ago
        ).count()

        # Overdue invoices
        overdue_invoices = SubscriptionInvoice.objects.filter(
            status='open',
            due_date__lt=today
        )
        context['overdue_invoices_count'] = overdue_invoices.count()
        context['overdue_amount'] = overdue_invoices.aggregate(
            total=Sum('amount_due')
        )['total'] or 0

        # Products
        context['total_products'] = SubscriptionProduct.objects.filter(is_active=True).count()

        # Recent activity
        context['recent_subscriptions'] = CustomerSubscription.objects.select_related(
            'customer', 'product'
        ).order_by('-created_at')[:10]

        context['recent_invoices'] = SubscriptionInvoice.objects.select_related(
            'customer', 'subscription__product'
        ).order_by('-created_at')[:10]

        return context


class SubscriptionProductListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all subscription products"""
    model = SubscriptionProduct
    template_name = 'subscriptions/product_list.html'
    partial_template_name = 'subscriptions/partials/_product_list.html'
    context_object_name = 'products'
    paginate_by = 20

    def get_queryset(self):
        queryset = SubscriptionProduct.objects.prefetch_related('tiers').order_by('sort_order', 'name')

        # Filter by status
        status = self.request.GET.get('status')
        if status == 'active':
            queryset = queryset.filter(is_active=True)
        elif status == 'inactive':
            queryset = queryset.filter(is_active=False)

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) |
                Q(description__icontains=search)
            )

        return queryset


class SubscriptionProductDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Product detail with subscribers and revenue"""
    model = SubscriptionProduct
    template_name = 'subscriptions/product_detail.html'
    context_object_name = 'product'

    def get_queryset(self):
        return SubscriptionProduct.objects.prefetch_related('tiers', 'customer_subscriptions')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        product = self.object

        # Active subscribers
        active_subs = product.customer_subscriptions.filter(status__in=['active', 'trialing'])
        context['active_subscribers'] = active_subs.count()

        # Revenue
        context['monthly_revenue'] = active_subs.filter(billing_cycle='monthly').aggregate(
            total=Sum('total_price')
        )['total'] or 0

        yearly_revenue = active_subs.filter(billing_cycle='yearly').aggregate(
            total=Sum('total_price')
        )['total'] or 0
        context['monthly_revenue'] += yearly_revenue / 12

        # Recent subscriptions
        context['recent_subscriptions'] = product.customer_subscriptions.select_related(
            'customer'
        ).order_by('-created_at')[:20]

        return context


class CustomerSubscriptionListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all customer subscriptions"""
    model = CustomerSubscription
    template_name = 'subscriptions/subscription_list.html'
    partial_template_name = 'subscriptions/partials/_subscription_list.html'
    context_object_name = 'subscriptions'
    paginate_by = 20

    def get_queryset(self):
        queryset = CustomerSubscription.objects.select_related(
            'customer', 'product', 'tier'
        ).order_by('-created_at')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by product
        product_id = self.request.GET.get('product')
        if product_id:
            queryset = queryset.filter(product_id=product_id)

        # Search by customer
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(customer__email__icontains=search) |
                Q(customer__first_name__icontains=search) |
                Q(customer__last_name__icontains=search)
            )

        return queryset


class CustomerSubscriptionDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Subscription detail with billing history and usage"""
    model = CustomerSubscription
    template_name = 'subscriptions/subscription_detail.html'
    context_object_name = 'subscription'

    def get_queryset(self):
        return CustomerSubscription.objects.select_related('customer', 'product', 'tier')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        subscription = self.object

        # Invoices
        context['invoices'] = subscription.invoices.order_by('-invoice_date')[:20]

        # Total paid
        context['total_paid'] = subscription.invoices.filter(
            status='paid'
        ).aggregate(total=Sum('amount_paid'))['total'] or 0

        # Usage records (for metered products)
        if subscription.product.product_type == 'metered':
            context['usage_records'] = subscription.usage_records.order_by('-usage_date')[:30]
            context['total_usage_cost'] = subscription.usage_records.aggregate(
                total=Sum('total_amount')
            )['total'] or 0

        return context


class SubscriptionInvoiceListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all subscription invoices"""
    model = SubscriptionInvoice
    template_name = 'subscriptions/invoice_list.html'
    partial_template_name = 'subscriptions/partials/_invoice_list.html'
    context_object_name = 'invoices'
    paginate_by = 20

    def get_queryset(self):
        queryset = SubscriptionInvoice.objects.select_related(
            'customer', 'subscription__product'
        ).order_by('-invoice_date')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter overdue
        if self.request.GET.get('overdue') == 'true':
            queryset = queryset.filter(
                status='open',
                due_date__lt=timezone.now().date()
            )

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(invoice_number__icontains=search) |
                Q(customer__email__icontains=search)
            )

        return queryset


class SubscriptionInvoiceDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Invoice detail view"""
    model = SubscriptionInvoice
    template_name = 'subscriptions/invoice_detail.html'
    context_object_name = 'invoice'

    def get_queryset(self):
        return SubscriptionInvoice.objects.select_related(
            'customer', 'subscription__product'
        )


class UsageRecordListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List usage records for metered subscriptions"""
    model = UsageRecord
    template_name = 'subscriptions/usage_list.html'
    partial_template_name = 'subscriptions/partials/_usage_list.html'
    context_object_name = 'usage_records'
    paginate_by = 50

    def get_queryset(self):
        queryset = UsageRecord.objects.select_related(
            'subscription__customer', 'subscription__product'
        ).order_by('-usage_date')

        # Filter by subscription
        subscription_id = self.request.GET.get('subscription')
        if subscription_id:
            queryset = queryset.filter(subscription_id=subscription_id)

        # Filter by usage type
        usage_type = self.request.GET.get('usage_type')
        if usage_type:
            queryset = queryset.filter(usage_type=usage_type)

        # Date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(usage_date__gte=start_date)
        if end_date:
            queryset = queryset.filter(usage_date__lte=end_date)

        return queryset


class HTMXSubscriptionStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for real-time subscription stats"""
    template_name = 'subscriptions/partials/_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Quick stats
        active_subs = CustomerSubscription.objects.filter(status__in=['active', 'trialing'])
        context['active_count'] = active_subs.count()

        monthly_mrr = active_subs.filter(billing_cycle='monthly').aggregate(
            total=Sum('total_price')
        )['total'] or 0
        yearly_mrr = (active_subs.filter(billing_cycle='yearly').aggregate(
            total=Sum('total_price')
        )['total'] or 0) / 12
        context['mrr'] = monthly_mrr + yearly_mrr

        context['trial_count'] = CustomerSubscription.objects.filter(status='trialing').count()

        overdue = SubscriptionInvoice.objects.filter(
            status='open',
            due_date__lt=timezone.now().date()
        )
        context['overdue_count'] = overdue.count()
        context['overdue_amount'] = overdue.aggregate(total=Sum('amount_due'))['total'] or 0

        return context
