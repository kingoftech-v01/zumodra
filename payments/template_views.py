"""
Payments Template Views - Frontend HTML Views
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView, CreateView, UpdateView
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.urls import reverse_lazy
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import timedelta

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    Currency,
    ExchangeRate,
    PaymentTransaction,
    PaymentMethod,
    RefundRequest,
    PaymentIntent,
)


class PaymentDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main payments dashboard with overview stats"""
    template_name = 'payments/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Date ranges
        today = timezone.now().date()
        thirty_days_ago = today - timedelta(days=30)

        # Payment stats
        recent_payments = PaymentTransaction.objects.filter(
            tenant=self.request.tenant,
            created_at__gte=thirty_days_ago
        )

        context['total_revenue'] = recent_payments.filter(
            status='succeeded'
        ).aggregate(total=Sum('amount_usd'))['total'] or 0

        context['pending_payments'] = recent_payments.filter(
            status='pending'
        ).count()

        context['failed_payments'] = recent_payments.filter(
            status='failed'
        ).count()

        context['refund_requests'] = RefundRequest.objects.filter(
            tenant=self.request.tenant,
            status='pending'
        ).count()

        # Recent transactions
        context['recent_transactions'] = PaymentTransaction.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'currency',
            'payer',
            'payee',
            'payment_method'
        ).order_by('-created_at')[:10]

        # Payment methods
        context['payment_methods_count'] = PaymentMethod.objects.filter(
            tenant=self.request.tenant,
            is_active=True
        ).count()

        return context


class PaymentTransactionListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all payment transactions"""
    model = PaymentTransaction
    template_name = 'payments/transaction_list.html'
    partial_template_name = 'payments/partials/_transaction_list.html'
    context_object_name = 'transactions'
    paginate_by = 20

    def get_queryset(self):
        queryset = PaymentTransaction.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'currency',
            'payer',
            'payee',
            'payment_method',
            'content_type'
        ).order_by('-created_at')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by currency
        currency = self.request.GET.get('currency')
        if currency:
            queryset = queryset.filter(currency__code=currency)

        # Search
        search = self.request.GET.get('q')
        if search:
            queryset = queryset.filter(
                Q(transaction_id__icontains=search) |
                Q(payer__email__icontains=search) |
                Q(payee__email__icontains=search)
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['currencies'] = Currency.objects.filter(is_active=True)
        context['status_choices'] = PaymentTransaction._meta.get_field('status').choices
        return context


class PaymentTransactionDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Payment transaction detail view"""
    model = PaymentTransaction
    template_name = 'payments/transaction_detail.html'
    context_object_name = 'transaction'

    def get_queryset(self):
        return PaymentTransaction.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'currency',
            'exchange_rate',
            'payer',
            'payee',
            'payment_method',
            'content_type'
        ).prefetch_related(
            'refund_requests'
        )


class PaymentMethodListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List payment methods"""
    model = PaymentMethod
    template_name = 'payments/payment_method_list.html'
    partial_template_name = 'payments/partials/_payment_method_list.html'
    context_object_name = 'payment_methods'
    paginate_by = 20

    def get_queryset(self):
        queryset = PaymentMethod.objects.filter(
            tenant=self.request.tenant
        ).select_related('user').order_by('-is_default', '-created_at')

        # Filter by type
        method_type = self.request.GET.get('type')
        if method_type:
            queryset = queryset.filter(method_type=method_type)

        # Filter by status
        is_active = self.request.GET.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active == 'true')

        return queryset


class PaymentMethodDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Payment method detail view"""
    model = PaymentMethod
    template_name = 'payments/payment_method_detail.html'
    context_object_name = 'payment_method'

    def get_queryset(self):
        return PaymentMethod.objects.filter(
            tenant=self.request.tenant
        ).select_related('user')


class RefundRequestListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List refund requests"""
    model = RefundRequest
    template_name = 'payments/refund_request_list.html'
    partial_template_name = 'payments/partials/_refund_request_list.html'
    context_object_name = 'refund_requests'
    paginate_by = 20

    def get_queryset(self):
        queryset = RefundRequest.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'payment_transaction',
            'payment_transaction__currency',
            'requested_by',
            'processed_by'
        ).order_by('-created_at')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = RefundRequest._meta.get_field('status').choices
        return context


class RefundRequestDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Refund request detail view"""
    model = RefundRequest
    template_name = 'payments/refund_request_detail.html'
    context_object_name = 'refund_request'

    def get_queryset(self):
        return RefundRequest.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'payment_transaction',
            'payment_transaction__currency',
            'payment_transaction__payer',
            'payment_transaction__payee',
            'requested_by',
            'processed_by'
        )


class CurrencyListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List supported currencies (read-only)"""
    model = Currency
    template_name = 'payments/currency_list.html'
    context_object_name = 'currencies'
    paginate_by = 50

    def get_queryset(self):
        return Currency.objects.filter(is_active=True).order_by('code')


class ExchangeRateListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List exchange rates (read-only)"""
    model = ExchangeRate
    template_name = 'payments/exchange_rate_list.html'
    context_object_name = 'exchange_rates'
    paginate_by = 50

    def get_queryset(self):
        queryset = ExchangeRate.objects.select_related(
            'from_currency',
            'to_currency'
        ).order_by('-date', 'from_currency__code')

        # Filter by currency
        from_currency = self.request.GET.get('from_currency')
        if from_currency:
            queryset = queryset.filter(from_currency__code=from_currency)

        to_currency = self.request.GET.get('to_currency')
        if to_currency:
            queryset = queryset.filter(to_currency__code=to_currency)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['currencies'] = Currency.objects.filter(is_active=True).order_by('code')
        return context


class HTMXQuickStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for quick payment stats"""
    template_name = 'payments/partials/_quick_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        today = timezone.now().date()
        thirty_days_ago = today - timedelta(days=30)

        recent_payments = PaymentTransaction.objects.filter(
            tenant=self.request.tenant,
            created_at__gte=thirty_days_ago
        )

        context['total_revenue'] = recent_payments.filter(
            status='succeeded'
        ).aggregate(total=Sum('amount_usd'))['total'] or 0

        context['pending_count'] = recent_payments.filter(status='pending').count()
        context['failed_count'] = recent_payments.filter(status='failed').count()
        context['refund_count'] = RefundRequest.objects.filter(
            tenant=self.request.tenant,
            status='pending'
        ).count()

        return context


class HTMXRecentTransactionsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for recent transactions"""
    template_name = 'payments/partials/_recent_transactions.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context['transactions'] = PaymentTransaction.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'currency',
            'payer',
            'payee'
        ).order_by('-created_at')[:10]

        return context
