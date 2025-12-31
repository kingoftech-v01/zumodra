"""
Finance Template Views - Frontend views for finance operations with HTMX support.

This module implements template-based views for:
- Finance dashboard with overview
- Payment history with filtering
- Subscription management
- Invoice management
- Payment method management
- Escrow transaction management
- Financial analytics and reporting

All views use HTMX for seamless partial page updates.
"""

import logging
from decimal import Decimal
from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Sum, Count, Q, Avg
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView, ListView, DetailView

from tenants.mixins import TenantViewMixin

from .models import (
    PaymentTransaction,
    SubscriptionPlan,
    UserSubscription,
    Invoice,
    RefundRequest,
    PaymentMethod,
    EscrowTransaction,
    Dispute,
    ConnectedAccount,
)

logger = logging.getLogger(__name__)


# =============================================================================
# FINANCE DASHBOARD VIEW
# =============================================================================

class FinanceDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Main finance dashboard with overview of all financial activities.

    Displays:
    - Quick stats (total spent, outstanding invoices, active subscription)
    - Recent payments
    - Pending invoices
    - Escrow summary
    - Payment methods overview
    """
    template_name = 'finance/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        now = timezone.now()
        month_ago = now - timedelta(days=30)

        # Payment statistics
        payments = PaymentTransaction.objects.filter(user=user)
        context['total_spent'] = payments.filter(succeeded=True).aggregate(
            total=Sum('amount')
        )['total'] or Decimal('0.00')
        context['total_spent_month'] = payments.filter(
            succeeded=True,
            created_at__gte=month_ago
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        context['payment_count'] = payments.filter(succeeded=True).count()

        # Invoice statistics
        invoices = Invoice.objects.filter(user=user)
        context['outstanding_invoices'] = invoices.filter(paid=False).count()
        context['outstanding_amount'] = invoices.filter(paid=False).aggregate(
            total=Sum('amount_due')
        )['total'] or Decimal('0.00')

        # Subscription status
        try:
            context['subscription'] = UserSubscription.objects.get(user=user)
        except UserSubscription.DoesNotExist:
            context['subscription'] = None

        # Escrow summary
        escrow_as_buyer = EscrowTransaction.objects.filter(buyer=user)
        escrow_as_seller = EscrowTransaction.objects.filter(seller=user)

        context['escrow_pending_buyer'] = escrow_as_buyer.filter(
            status__in=['initialized', 'funded', 'service_delivered']
        ).count()
        context['escrow_pending_seller'] = escrow_as_seller.filter(
            status__in=['initialized', 'funded', 'service_delivered']
        ).count()
        context['escrow_pending_amount'] = escrow_as_buyer.filter(
            status__in=['initialized', 'funded', 'service_delivered']
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

        # Recent payments
        context['recent_payments'] = payments.order_by('-created_at')[:5]

        # Pending invoices
        context['pending_invoices'] = invoices.filter(
            paid=False
        ).order_by('due_date')[:5]

        # Payment methods count
        context['payment_methods_count'] = PaymentMethod.objects.filter(
            user=user
        ).count()

        # Connected account status
        try:
            context['connected_account'] = ConnectedAccount.objects.get(user=user)
        except ConnectedAccount.DoesNotExist:
            context['connected_account'] = None

        return context


# =============================================================================
# HTMX PARTIAL VIEWS
# =============================================================================

class FinanceQuickStatsView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for refreshing finance quick stats.
    """

    def get(self, request):
        user = request.user
        now = timezone.now()
        month_ago = now - timedelta(days=30)

        payments = PaymentTransaction.objects.filter(user=user)
        invoices = Invoice.objects.filter(user=user)

        stats = {
            'total_spent': payments.filter(succeeded=True).aggregate(
                total=Sum('amount')
            )['total'] or Decimal('0.00'),
            'total_spent_month': payments.filter(
                succeeded=True,
                created_at__gte=month_ago
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            'outstanding_invoices': invoices.filter(paid=False).count(),
            'outstanding_amount': invoices.filter(paid=False).aggregate(
                total=Sum('amount_due')
            )['total'] or Decimal('0.00'),
        }

        return render(request, 'finance/partials/_quick_stats.html', {'stats': stats})


class RecentPaymentsView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for recent payments list.
    """

    def get(self, request):
        payments = PaymentTransaction.objects.filter(
            user=request.user
        ).order_by('-created_at')[:5]

        return render(request, 'finance/partials/_recent_payments.html', {
            'recent_payments': payments
        })


class PendingInvoicesView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for pending invoices list.
    """

    def get(self, request):
        invoices = Invoice.objects.filter(
            user=request.user,
            paid=False
        ).order_by('due_date')[:5]

        return render(request, 'finance/partials/_pending_invoices.html', {
            'pending_invoices': invoices
        })


class EscrowSummaryView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for escrow summary.
    """

    def get(self, request):
        user = request.user

        escrow_as_buyer = EscrowTransaction.objects.filter(buyer=user)
        escrow_as_seller = EscrowTransaction.objects.filter(seller=user)

        context = {
            'escrow_pending_buyer': escrow_as_buyer.filter(
                status__in=['initialized', 'funded', 'service_delivered']
            ).count(),
            'escrow_pending_seller': escrow_as_seller.filter(
                status__in=['initialized', 'funded', 'service_delivered']
            ).count(),
            'escrow_pending_amount': escrow_as_buyer.filter(
                status__in=['initialized', 'funded', 'service_delivered']
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
        }

        return render(request, 'finance/partials/_escrow_summary.html', context)


# =============================================================================
# PAYMENT HISTORY VIEWS (HTMX Enhanced)
# =============================================================================

class PaymentHistoryTemplateView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Payment history page with filtering and HTMX support.
    """
    template_name = 'finance/payments/history.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        # Get all payments
        payments = PaymentTransaction.objects.filter(user=user)

        # Summary stats
        context['total_spent'] = payments.filter(succeeded=True).aggregate(
            total=Sum('amount')
        )['total'] or Decimal('0.00')
        context['successful_count'] = payments.filter(succeeded=True).count()
        context['failed_count'] = payments.filter(succeeded=False).count()

        # Filter options
        context['current_filters'] = {
            'status': self.request.GET.get('status', ''),
            'start_date': self.request.GET.get('start_date', ''),
            'end_date': self.request.GET.get('end_date', ''),
        }

        return context


class PaymentListPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for payment list with filtering.
    """

    def get(self, request):
        payments = PaymentTransaction.objects.filter(
            user=request.user
        ).order_by('-created_at')

        # Apply filters
        status = request.GET.get('status')
        if status == 'succeeded':
            payments = payments.filter(succeeded=True)
        elif status == 'failed':
            payments = payments.filter(succeeded=False)

        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        if start_date:
            payments = payments.filter(created_at__date__gte=start_date)
        if end_date:
            payments = payments.filter(created_at__date__lte=end_date)

        min_amount = request.GET.get('min_amount')
        max_amount = request.GET.get('max_amount')
        if min_amount:
            payments = payments.filter(amount__gte=Decimal(min_amount))
        if max_amount:
            payments = payments.filter(amount__lte=Decimal(max_amount))

        # Pagination
        page = int(request.GET.get('page', 1))
        per_page = 20
        start = (page - 1) * per_page
        end = start + per_page

        total_count = payments.count()
        payments = payments[start:end]

        context = {
            'payments': payments,
            'page': page,
            'total_pages': (total_count + per_page - 1) // per_page,
            'has_next': end < total_count,
            'has_prev': page > 1,
        }

        return render(request, 'finance/partials/_payment_list.html', context)


class PaymentDetailPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for payment detail modal.
    """

    def get(self, request, pk):
        payment = get_object_or_404(
            PaymentTransaction,
            user=request.user,
            pk=pk
        )

        # Check if refund request exists
        refund_request = getattr(payment, 'refund_request', None)

        return render(request, 'finance/partials/_payment_detail_modal.html', {
            'payment': payment,
            'refund_request': refund_request,
        })


# =============================================================================
# SUBSCRIPTION VIEWS (HTMX Enhanced)
# =============================================================================

class SubscriptionTemplateView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Subscription management page.
    """
    template_name = 'finance/subscription/index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        # Current subscription
        try:
            context['subscription'] = UserSubscription.objects.get(user=user)
        except UserSubscription.DoesNotExist:
            context['subscription'] = None

        # Available plans
        context['plans'] = SubscriptionPlan.objects.all()

        return context


class SubscriptionStatusPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for subscription status.
    """

    def get(self, request):
        try:
            subscription = UserSubscription.objects.get(user=request.user)
        except UserSubscription.DoesNotExist:
            subscription = None

        return render(request, 'finance/partials/_subscription_status.html', {
            'subscription': subscription
        })


class SubscriptionPlansPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for subscription plans list.
    """

    def get(self, request):
        plans = SubscriptionPlan.objects.all()

        try:
            current_subscription = UserSubscription.objects.get(user=request.user)
        except UserSubscription.DoesNotExist:
            current_subscription = None

        return render(request, 'finance/partials/_subscription_plans.html', {
            'plans': plans,
            'current_subscription': current_subscription,
        })


# =============================================================================
# INVOICE VIEWS (HTMX Enhanced)
# =============================================================================

class InvoiceListTemplateView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Invoice list page with filtering and HTMX support.
    """
    template_name = 'finance/invoices/list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        invoices = Invoice.objects.filter(user=user)

        # Summary stats
        context['total_invoiced'] = invoices.aggregate(
            total=Sum('amount_due')
        )['total'] or Decimal('0.00')
        context['total_paid'] = invoices.filter(paid=True).aggregate(
            total=Sum('amount_paid')
        )['total'] or Decimal('0.00')
        context['outstanding'] = invoices.filter(paid=False).aggregate(
            total=Sum('amount_due')
        )['total'] or Decimal('0.00')

        # Filter options
        context['current_filters'] = {
            'paid': self.request.GET.get('paid', ''),
            'start_date': self.request.GET.get('start_date', ''),
            'end_date': self.request.GET.get('end_date', ''),
        }

        return context


class InvoiceListPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for invoice list with filtering.
    """

    def get(self, request):
        invoices = Invoice.objects.filter(
            user=request.user
        ).order_by('-created_at')

        # Apply filters
        paid = request.GET.get('paid')
        if paid == 'true':
            invoices = invoices.filter(paid=True)
        elif paid == 'false':
            invoices = invoices.filter(paid=False)

        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        if start_date:
            invoices = invoices.filter(created_at__date__gte=start_date)
        if end_date:
            invoices = invoices.filter(created_at__date__lte=end_date)

        # Pagination
        page = int(request.GET.get('page', 1))
        per_page = 20
        start = (page - 1) * per_page
        end = start + per_page

        total_count = invoices.count()
        invoices = invoices[start:end]

        context = {
            'invoices': invoices,
            'page': page,
            'total_pages': (total_count + per_page - 1) // per_page,
            'has_next': end < total_count,
            'has_prev': page > 1,
        }

        return render(request, 'finance/partials/_invoice_list.html', context)


class InvoiceDetailTemplateView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """
    Invoice detail page.
    """
    model = Invoice
    template_name = 'finance/invoices/detail.html'
    context_object_name = 'invoice'
    slug_field = 'invoice_number'
    slug_url_kwarg = 'invoice_number'

    def get_queryset(self):
        return Invoice.objects.filter(user=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Payment methods for pay form
        context['payment_methods'] = PaymentMethod.objects.filter(
            user=self.request.user
        ).order_by('-is_default')

        return context


class InvoiceDetailPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for invoice detail modal.
    """

    def get(self, request, invoice_number):
        invoice = get_object_or_404(
            Invoice,
            user=request.user,
            invoice_number=invoice_number
        )

        payment_methods = PaymentMethod.objects.filter(
            user=request.user
        ).order_by('-is_default')

        return render(request, 'finance/partials/_invoice_detail_modal.html', {
            'invoice': invoice,
            'payment_methods': payment_methods,
        })


# =============================================================================
# PAYMENT METHOD VIEWS (HTMX Enhanced)
# =============================================================================

class PaymentMethodsTemplateView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Payment methods management page.
    """
    template_name = 'finance/payment_methods/index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context['payment_methods'] = PaymentMethod.objects.filter(
            user=self.request.user
        ).order_by('-is_default', '-added_at')

        return context


class PaymentMethodListPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for payment method list.
    """

    def get(self, request):
        payment_methods = PaymentMethod.objects.filter(
            user=request.user
        ).order_by('-is_default', '-added_at')

        return render(request, 'finance/partials/_payment_method_list.html', {
            'payment_methods': payment_methods
        })


class PaymentMethodCardPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for single payment method card.
    """

    def get(self, request, pk):
        payment_method = get_object_or_404(
            PaymentMethod,
            user=request.user,
            pk=pk
        )

        return render(request, 'finance/partials/_payment_method_card.html', {
            'method': payment_method
        })


class PaymentMethodFormPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for add payment method form.
    """

    def get(self, request):
        from django.conf import settings
        import stripe

        stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', '')

        try:
            # Get or create Stripe customer
            customer = self._get_or_create_customer(request.user)

            setup_intent = stripe.SetupIntent.create(
                customer=customer.id,
                metadata={
                    'user_id': str(request.user.id),
                },
            )

            return render(request, 'finance/partials/_payment_method_form.html', {
                'client_secret': setup_intent.client_secret,
                'stripe_publishable_key': getattr(settings, 'STRIPE_PUBLISHABLE_KEY', ''),
            })

        except Exception as e:
            logger.error(f"Error creating setup intent: {e}")
            return render(request, 'finance/partials/_payment_method_form.html', {
                'error': 'Unable to load payment form. Please try again.',
            })

    def _get_or_create_customer(self, user):
        """Get or create Stripe customer for user."""
        import stripe

        stripe_customer_id = getattr(user, 'stripe_customer_id', None)

        if stripe_customer_id:
            try:
                return stripe.Customer.retrieve(stripe_customer_id)
            except stripe.error.StripeError:
                pass

        customer = stripe.Customer.create(
            email=user.email,
            name=user.get_full_name() or user.email,
            metadata={
                'user_id': str(user.id),
            },
        )

        if hasattr(user, 'stripe_customer_id'):
            user.stripe_customer_id = customer.id
            user.save(update_fields=['stripe_customer_id'])

        return customer


# =============================================================================
# ESCROW VIEWS (HTMX Enhanced)
# =============================================================================

class EscrowListTemplateView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Escrow transactions list page.
    """
    template_name = 'finance/escrow/list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        escrow_as_buyer = EscrowTransaction.objects.filter(buyer=user)
        escrow_as_seller = EscrowTransaction.objects.filter(seller=user)

        # Summary stats
        context['total_as_buyer'] = escrow_as_buyer.aggregate(
            total=Sum('amount')
        )['total'] or Decimal('0.00')
        context['total_as_seller'] = escrow_as_seller.aggregate(
            total=Sum('amount')
        )['total'] or Decimal('0.00')
        context['pending_count'] = EscrowTransaction.objects.filter(
            Q(buyer=user) | Q(seller=user),
            status__in=['initialized', 'funded', 'service_delivered']
        ).count()

        # Filter options
        context['current_filters'] = {
            'role': self.request.GET.get('role', ''),
            'status': self.request.GET.get('status', ''),
        }

        return context


class EscrowListPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for escrow list with filtering.
    """

    def get(self, request):
        user = request.user

        # Base queryset
        escrows = EscrowTransaction.objects.filter(
            Q(buyer=user) | Q(seller=user)
        ).order_by('-created_at')

        # Apply filters
        role = request.GET.get('role')
        if role == 'buyer':
            escrows = escrows.filter(buyer=user)
        elif role == 'seller':
            escrows = escrows.filter(seller=user)

        status = request.GET.get('status')
        if status:
            escrows = escrows.filter(status=status)

        # Pagination
        page = int(request.GET.get('page', 1))
        per_page = 20
        start = (page - 1) * per_page
        end = start + per_page

        total_count = escrows.count()
        escrows = escrows[start:end]

        # Add role info to each escrow
        escrow_list = []
        for escrow in escrows:
            escrow_list.append({
                'escrow': escrow,
                'is_buyer': escrow.buyer == user,
                'is_seller': escrow.seller == user,
            })

        context = {
            'escrow_list': escrow_list,
            'page': page,
            'total_pages': (total_count + per_page - 1) // per_page,
            'has_next': end < total_count,
            'has_prev': page > 1,
        }

        return render(request, 'finance/partials/_escrow_list.html', context)


class EscrowDetailTemplateView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """
    Escrow transaction detail page.
    """
    model = EscrowTransaction
    template_name = 'finance/escrow/detail.html'
    context_object_name = 'escrow'

    def get_queryset(self):
        user = self.request.user
        return EscrowTransaction.objects.filter(
            Q(buyer=user) | Q(seller=user)
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        escrow = self.object
        user = self.request.user

        context['is_buyer'] = escrow.buyer == user
        context['is_seller'] = escrow.seller == user
        context['disputes'] = escrow.disputes.all()
        context['audit_logs'] = escrow.audit_logs.all().order_by('-timestamp')[:10]

        return context


class EscrowDetailPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for escrow detail modal.
    """

    def get(self, request, pk):
        user = request.user
        escrow = get_object_or_404(
            EscrowTransaction,
            Q(buyer=user) | Q(seller=user),
            pk=pk
        )

        context = {
            'escrow': escrow,
            'is_buyer': escrow.buyer == user,
            'is_seller': escrow.seller == user,
            'disputes': escrow.disputes.all(),
            'audit_logs': escrow.audit_logs.all().order_by('-timestamp')[:5],
        }

        return render(request, 'finance/partials/_escrow_detail_modal.html', context)


class EscrowTimelinePartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for escrow timeline/audit log.
    """

    def get(self, request, pk):
        user = request.user
        escrow = get_object_or_404(
            EscrowTransaction,
            Q(buyer=user) | Q(seller=user),
            pk=pk
        )

        audit_logs = escrow.audit_logs.all().order_by('-timestamp')

        return render(request, 'finance/partials/_escrow_timeline.html', {
            'audit_logs': audit_logs,
            'escrow': escrow,
        })


# =============================================================================
# CONNECTED ACCOUNT VIEWS (HTMX Enhanced)
# =============================================================================

class ConnectedAccountTemplateView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Connected account (Stripe Connect) management page.
    """
    template_name = 'finance/connect/index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        try:
            context['connected_account'] = ConnectedAccount.objects.get(
                user=self.request.user
            )
        except ConnectedAccount.DoesNotExist:
            context['connected_account'] = None

        return context


class ConnectedAccountStatusPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for connected account status.
    """

    def get(self, request):
        try:
            connected_account = ConnectedAccount.objects.get(user=request.user)
        except ConnectedAccount.DoesNotExist:
            connected_account = None

        return render(request, 'finance/partials/_connected_account_status.html', {
            'connected_account': connected_account
        })


class ConnectedAccountOnboardingPartialView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for connected account onboarding form.
    """

    def get(self, request):
        try:
            connected_account = ConnectedAccount.objects.get(user=request.user)
            has_account = True
        except ConnectedAccount.DoesNotExist:
            connected_account = None
            has_account = False

        return render(request, 'finance/partials/_connected_account_onboarding.html', {
            'connected_account': connected_account,
            'has_account': has_account,
        })


# =============================================================================
# FINANCIAL ANALYTICS VIEWS
# =============================================================================

class FinanceAnalyticsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Financial analytics and reporting page.
    """
    template_name = 'finance/analytics/index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        now = timezone.now()

        # Time periods
        periods = {
            '7d': now - timedelta(days=7),
            '30d': now - timedelta(days=30),
            '90d': now - timedelta(days=90),
            '365d': now - timedelta(days=365),
        }

        # Payment trends
        payments = PaymentTransaction.objects.filter(user=user, succeeded=True)
        context['payment_trends'] = {
            period: payments.filter(created_at__gte=start).aggregate(
                total=Sum('amount'),
                count=Count('id')
            ) for period, start in periods.items()
        }

        # Invoice statistics
        invoices = Invoice.objects.filter(user=user)
        context['invoice_stats'] = {
            'total': invoices.count(),
            'paid': invoices.filter(paid=True).count(),
            'unpaid': invoices.filter(paid=False).count(),
            'overdue': invoices.filter(
                paid=False,
                due_date__lt=now
            ).count(),
        }

        # Escrow statistics
        escrows_buyer = EscrowTransaction.objects.filter(buyer=user)
        escrows_seller = EscrowTransaction.objects.filter(seller=user)

        context['escrow_stats'] = {
            'as_buyer': {
                'total': escrows_buyer.count(),
                'completed': escrows_buyer.filter(status='released').count(),
                'amount': escrows_buyer.filter(status='released').aggregate(
                    total=Sum('amount')
                )['total'] or Decimal('0.00'),
            },
            'as_seller': {
                'total': escrows_seller.count(),
                'completed': escrows_seller.filter(status='released').count(),
                'amount': escrows_seller.filter(status='released').aggregate(
                    total=Sum('amount')
                )['total'] or Decimal('0.00'),
            },
        }

        return context


class FinanceChartDataView(LoginRequiredMixin, TenantViewMixin, View):
    """
    HTMX endpoint for finance chart data.
    """

    def get(self, request):
        user = request.user
        chart_type = request.GET.get('type', 'payments')
        period = request.GET.get('period', '30d')

        now = timezone.now()
        periods_map = {
            '7d': 7,
            '30d': 30,
            '90d': 90,
            '365d': 365,
        }
        days = periods_map.get(period, 30)
        start_date = now - timedelta(days=days)

        if chart_type == 'payments':
            # Daily payment totals
            from django.db.models.functions import TruncDate
            data = PaymentTransaction.objects.filter(
                user=user,
                succeeded=True,
                created_at__gte=start_date
            ).annotate(
                date=TruncDate('created_at')
            ).values('date').annotate(
                total=Sum('amount'),
                count=Count('id')
            ).order_by('date')

            return JsonResponse({
                'labels': [d['date'].isoformat() for d in data],
                'amounts': [float(d['total']) for d in data],
                'counts': [d['count'] for d in data],
            })

        elif chart_type == 'invoices':
            # Invoice status breakdown
            invoices = Invoice.objects.filter(user=user)
            data = {
                'paid': invoices.filter(paid=True).count(),
                'unpaid': invoices.filter(paid=False, due_date__gte=now).count(),
                'overdue': invoices.filter(paid=False, due_date__lt=now).count(),
            }

            return JsonResponse(data)

        elif chart_type == 'escrow':
            # Escrow status breakdown
            escrows = EscrowTransaction.objects.filter(
                Q(buyer=user) | Q(seller=user)
            )
            data = {
                status: escrows.filter(status=status).count()
                for status, _ in EscrowTransaction.ESCROW_STATUS_CHOICES
            }

            return JsonResponse(data)

        return JsonResponse({'error': 'Invalid chart type'}, status=400)


# =============================================================================
# SUCCESS/CANCEL VIEWS
# =============================================================================

class SubscriptionSuccessView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Subscription success page after checkout.
    """
    template_name = 'finance/subscription/success.html'


class SubscriptionCancelView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """
    Subscription cancel page when user cancels checkout.
    """
    template_name = 'finance/subscription/cancel.html'


class InvoicePaymentSuccessView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Invoice payment success page.
    """

    def get(self, request, invoice_number):
        invoice = get_object_or_404(
            Invoice,
            user=request.user,
            invoice_number=invoice_number
        )

        return render(request, 'finance/invoices/payment_success.html', {
            'invoice': invoice
        })


class ConnectReturnView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Return view after Stripe Connect onboarding.
    """

    def get(self, request):
        try:
            connected_account = ConnectedAccount.objects.get(user=request.user)
            # Refresh account status from Stripe
            connected_account.refresh_account_status()
        except ConnectedAccount.DoesNotExist:
            pass

        return redirect('finance-frontend:connected-account')


class ConnectRefreshView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Refresh view when Stripe Connect onboarding link expires.
    """

    def get(self, request):
        try:
            connected_account = ConnectedAccount.objects.get(user=request.user)

            # Generate new onboarding link
            from .models import StripeConnectOnboarding

            onboarding, _ = StripeConnectOnboarding.objects.get_or_create(
                connected_account=connected_account
            )

            return_url = request.build_absolute_uri(
                reverse('finance-frontend:connect-return')
            )
            refresh_url = request.build_absolute_uri(
                reverse('finance-frontend:connect-refresh')
            )

            onboarding_url = onboarding.generate_onboarding_link(
                return_url=return_url,
                refresh_url=refresh_url,
            )

            return redirect(onboarding_url)

        except ConnectedAccount.DoesNotExist:
            return redirect('finance-frontend:connected-account')
