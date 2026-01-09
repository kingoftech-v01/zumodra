"""
Finance API Views - REST API endpoints for finance operations.

This module implements API views for:
- Payment transaction history
- Subscription management
- Invoice management
- Payment method management
- Stripe webhook handling
- Escrow transaction management
- Connected account management

Security Features:
- Tenant isolation via TenantViewMixin
- Role-based access control for financial operations
- Participant validation for escrow transactions
- Audit logging for all financial actions
- Stripe webhook signature verification
"""

import json
import logging
from decimal import Decimal
from datetime import timedelta

import stripe
from django.conf import settings

# Security logger for financial operations
security_logger = logging.getLogger('security.finance')
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.db.models import Sum, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import ListView, DetailView, CreateView, UpdateView

from rest_framework import status, viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from tenants.mixins import TenantViewMixin

from .models import (
    PaymentTransaction,
    SubscriptionPlan,
    UserSubscription,
    Invoice,
    RefundRequest,
    PaymentMethod,
    StripeWebhookEvent,
    EscrowTransaction,
    Dispute,
    EscrowPayout,
    EscrowAudit,
    ConnectedAccount,
    PayoutSchedule,
    PlatformFee,
    StripeConnectOnboarding,
)

logger = logging.getLogger(__name__)

# Initialize Stripe API key
stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', '')


# =============================================================================
# PAYMENT TRANSACTION VIEWS
# =============================================================================

class PaymentHistoryView(LoginRequiredMixin, TenantViewMixin, ListView):
    """
    View to list user's payment transaction history.

    Displays all payments made by the user with filtering options
    for status, date range, and amount.
    """
    model = PaymentTransaction
    template_name = 'finance/payment_history.html'
    context_object_name = 'payments'
    paginate_by = 20

    def get_queryset(self):
        """Filter payments by current user."""
        queryset = PaymentTransaction.objects.filter(
            user=self.request.user
        ).order_by('-created_at')

        # Filter by status
        status_filter = self.request.GET.get('status')
        if status_filter == 'succeeded':
            queryset = queryset.filter(succeeded=True)
        elif status_filter == 'failed':
            queryset = queryset.filter(succeeded=False)

        # Filter by date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(created_at__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__date__lte=end_date)

        # Filter by amount range
        min_amount = self.request.GET.get('min_amount')
        max_amount = self.request.GET.get('max_amount')
        if min_amount:
            queryset = queryset.filter(amount__gte=Decimal(min_amount))
        if max_amount:
            queryset = queryset.filter(amount__lte=Decimal(max_amount))

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Add summary statistics
        user_payments = PaymentTransaction.objects.filter(user=self.request.user)
        context['total_spent'] = user_payments.filter(succeeded=True).aggregate(
            total=Sum('amount')
        )['total'] or Decimal('0.00')
        context['successful_payments'] = user_payments.filter(succeeded=True).count()
        context['failed_payments'] = user_payments.filter(succeeded=False).count()

        # Pass current filters to template
        context['current_filters'] = {
            'status': self.request.GET.get('status', ''),
            'start_date': self.request.GET.get('start_date', ''),
            'end_date': self.request.GET.get('end_date', ''),
            'min_amount': self.request.GET.get('min_amount', ''),
            'max_amount': self.request.GET.get('max_amount', ''),
        }

        return context


class PaymentDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """
    View to display details of a single payment transaction.
    """
    model = PaymentTransaction
    template_name = 'finance/payment_detail.html'
    context_object_name = 'payment'

    def get_queryset(self):
        """Ensure user can only view their own payments."""
        return PaymentTransaction.objects.filter(user=self.request.user)


# =============================================================================
# SUBSCRIPTION VIEWS
# =============================================================================

class SubscriptionPlanListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """
    View to list all available subscription plans.
    """
    model = SubscriptionPlan
    template_name = 'finance/subscription_plans.html'
    context_object_name = 'plans'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get user's current subscription if exists
        try:
            context['current_subscription'] = UserSubscription.objects.get(
                user=self.request.user
            )
        except UserSubscription.DoesNotExist:
            context['current_subscription'] = None

        return context


class SubscriptionView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to manage user's subscription.

    GET: Display current subscription status
    POST: Create or update subscription
    """
    template_name = 'finance/subscription.html'

    def get(self, request):
        """Display current subscription status."""
        try:
            subscription = UserSubscription.objects.get(user=request.user)
        except UserSubscription.DoesNotExist:
            subscription = None

        plans = SubscriptionPlan.objects.all()

        context = {
            'subscription': subscription,
            'plans': plans,
        }

        from django.shortcuts import render
        return render(request, self.template_name, context)

    def post(self, request):
        """Create or update subscription."""
        plan_id = request.POST.get('plan_id')

        if not plan_id:
            return JsonResponse({'error': 'Plan ID is required'}, status=400)

        try:
            plan = SubscriptionPlan.objects.get(pk=plan_id)
        except SubscriptionPlan.DoesNotExist:
            return JsonResponse({'error': 'Plan not found'}, status=404)

        # Create Stripe checkout session for subscription
        try:
            checkout_session = stripe.checkout.Session.create(
                customer_email=request.user.email,
                payment_method_types=['card'],
                line_items=[{
                    'price': plan.stripe_price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=request.build_absolute_uri('/finance/subscription/success/'),
                cancel_url=request.build_absolute_uri('/finance/subscription/cancel/'),
                metadata={
                    'user_id': str(request.user.id),
                    'plan_id': str(plan.id),
                },
            )

            return JsonResponse({
                'checkout_url': checkout_session.url,
                'session_id': checkout_session.id,
            })

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating subscription: {e}")
            return JsonResponse({'error': str(e)}, status=400)


class SubscriptionCancelView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to cancel user's subscription.
    """

    def post(self, request):
        """Cancel the user's subscription."""
        try:
            subscription = UserSubscription.objects.get(user=request.user)
        except UserSubscription.DoesNotExist:
            return JsonResponse({'error': 'No active subscription found'}, status=404)

        try:
            # Cancel subscription in Stripe
            stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                cancel_at_period_end=True
            )

            # Update local status
            subscription.status = 'canceling'
            subscription.save()

            return JsonResponse({
                'success': True,
                'message': 'Subscription will be canceled at end of billing period',
                'cancel_date': subscription.current_period_end.isoformat(),
            })

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error canceling subscription: {e}")
            return JsonResponse({'error': str(e)}, status=400)


class SubscriptionReactivateView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to reactivate a canceled subscription.
    """

    def post(self, request):
        """Reactivate the user's subscription."""
        try:
            subscription = UserSubscription.objects.get(user=request.user)
        except UserSubscription.DoesNotExist:
            return JsonResponse({'error': 'No subscription found'}, status=404)

        if subscription.status not in ['canceling', 'canceled']:
            return JsonResponse({'error': 'Subscription is not canceled'}, status=400)

        try:
            # Reactivate subscription in Stripe
            stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                cancel_at_period_end=False
            )

            # Update local status
            subscription.status = 'active'
            subscription.save()

            return JsonResponse({
                'success': True,
                'message': 'Subscription reactivated successfully',
            })

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error reactivating subscription: {e}")
            return JsonResponse({'error': str(e)}, status=400)


# =============================================================================
# INVOICE VIEWS
# =============================================================================

class InvoiceListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """
    View to list user's invoices.
    """
    model = Invoice
    template_name = 'finance/invoice_list.html'
    context_object_name = 'invoices'
    paginate_by = 20

    def get_queryset(self):
        """Filter invoices by current user."""
        queryset = Invoice.objects.filter(
            user=self.request.user
        ).order_by('-created_at')

        # Filter by payment status
        paid_filter = self.request.GET.get('paid')
        if paid_filter == 'true':
            queryset = queryset.filter(paid=True)
        elif paid_filter == 'false':
            queryset = queryset.filter(paid=False)

        # Filter by date range
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        if start_date:
            queryset = queryset.filter(created_at__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__date__lte=end_date)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Add summary statistics
        user_invoices = Invoice.objects.filter(user=self.request.user)
        context['total_invoiced'] = user_invoices.aggregate(
            total=Sum('amount_due')
        )['total'] or Decimal('0.00')
        context['total_paid'] = user_invoices.filter(paid=True).aggregate(
            total=Sum('amount_paid')
        )['total'] or Decimal('0.00')
        context['outstanding_amount'] = user_invoices.filter(paid=False).aggregate(
            total=Sum('amount_due')
        )['total'] or Decimal('0.00')

        return context


class InvoiceDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """
    View to display details of a single invoice.
    """
    model = Invoice
    template_name = 'finance/invoice_detail.html'
    context_object_name = 'invoice'
    slug_field = 'invoice_number'
    slug_url_kwarg = 'invoice_number'

    def get_queryset(self):
        """Ensure user can only view their own invoices."""
        return Invoice.objects.filter(user=self.request.user)


class InvoicePayView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to pay an outstanding invoice.
    """

    def post(self, request, invoice_number):
        """Process invoice payment."""
        invoice = get_object_or_404(
            Invoice,
            user=request.user,
            invoice_number=invoice_number,
            paid=False
        )

        payment_method_id = request.POST.get('payment_method_id')

        if not payment_method_id:
            # Create Stripe checkout session
            try:
                checkout_session = stripe.checkout.Session.create(
                    customer_email=request.user.email,
                    payment_method_types=['card'],
                    line_items=[{
                        'price_data': {
                            'currency': invoice.currency.lower(),
                            'unit_amount': int(invoice.amount_due * 100),
                            'product_data': {
                                'name': f'Invoice {invoice.invoice_number}',
                            },
                        },
                        'quantity': 1,
                    }],
                    mode='payment',
                    success_url=request.build_absolute_uri(
                        f'/finance/invoices/{invoice.invoice_number}/success/'
                    ),
                    cancel_url=request.build_absolute_uri(
                        f'/finance/invoices/{invoice.invoice_number}/'
                    ),
                    metadata={
                        'user_id': str(request.user.id),
                        'invoice_id': str(invoice.id),
                        'invoice_number': invoice.invoice_number,
                    },
                )

                return JsonResponse({
                    'checkout_url': checkout_session.url,
                    'session_id': checkout_session.id,
                })

            except stripe.error.StripeError as e:
                logger.error(f"Stripe error creating invoice payment: {e}")
                return JsonResponse({'error': str(e)}, status=400)

        else:
            # Use existing payment method
            try:
                payment_method = PaymentMethod.objects.get(
                    user=request.user,
                    id=payment_method_id
                )

                # Create payment intent
                payment_intent = stripe.PaymentIntent.create(
                    amount=int(invoice.amount_due * 100),
                    currency=invoice.currency.lower(),
                    payment_method=payment_method.stripe_payment_method_id,
                    confirm=True,
                    metadata={
                        'user_id': str(request.user.id),
                        'invoice_id': str(invoice.id),
                        'invoice_number': invoice.invoice_number,
                    },
                )

                if payment_intent.status == 'succeeded':
                    # Record payment transaction
                    PaymentTransaction.objects.create(
                        user=request.user,
                        amount=invoice.amount_due,
                        currency=invoice.currency,
                        stripe_payment_intent_id=payment_intent.id,
                        description=f'Payment for invoice {invoice.invoice_number}',
                        succeeded=True,
                    )

                    # Update invoice
                    invoice.paid = True
                    invoice.amount_paid = invoice.amount_due
                    invoice.paid_at = timezone.now()
                    invoice.save()

                    return JsonResponse({
                        'success': True,
                        'message': 'Invoice paid successfully',
                    })
                else:
                    return JsonResponse({
                        'error': 'Payment requires additional action',
                        'client_secret': payment_intent.client_secret,
                    }, status=402)

            except PaymentMethod.DoesNotExist:
                return JsonResponse({'error': 'Payment method not found'}, status=404)
            except stripe.error.StripeError as e:
                logger.error(f"Stripe error processing invoice payment: {e}")
                return JsonResponse({'error': str(e)}, status=400)


class InvoiceDownloadView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to download invoice as PDF.
    """

    def get(self, request, invoice_number):
        """Download invoice PDF."""
        invoice = get_object_or_404(
            Invoice,
            user=request.user,
            invoice_number=invoice_number
        )

        # If invoice has Stripe ID, fetch PDF from Stripe
        if invoice.stripe_invoice_id:
            try:
                stripe_invoice = stripe.Invoice.retrieve(invoice.stripe_invoice_id)
                if stripe_invoice.invoice_pdf:
                    return JsonResponse({
                        'pdf_url': stripe_invoice.invoice_pdf,
                    })
            except stripe.error.StripeError as e:
                logger.error(f"Stripe error retrieving invoice PDF: {e}")

        # Otherwise, generate PDF locally (placeholder)
        # In production, use weasyprint or reportlab to generate PDF
        return JsonResponse({
            'error': 'PDF generation not available',
        }, status=501)


# =============================================================================
# PAYMENT METHOD VIEWS
# =============================================================================

class PaymentMethodListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """
    View to list user's saved payment methods.
    """
    model = PaymentMethod
    template_name = 'finance/payment_methods.html'
    context_object_name = 'payment_methods'

    def get_queryset(self):
        """Filter payment methods by current user."""
        return PaymentMethod.objects.filter(
            user=self.request.user
        ).order_by('-is_default', '-added_at')


class PaymentMethodAddView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to add a new payment method.
    """

    def get(self, request):
        """Display form to add payment method."""
        # Create Stripe SetupIntent for securely collecting card info
        try:
            # Get or create Stripe customer
            customer = self._get_or_create_customer(request.user)

            setup_intent = stripe.SetupIntent.create(
                customer=customer.id,
                metadata={
                    'user_id': str(request.user.id),
                },
            )

            from django.shortcuts import render
            return render(request, 'finance/payment_method_add.html', {
                'client_secret': setup_intent.client_secret,
                'stripe_publishable_key': getattr(settings, 'STRIPE_PUBLISHABLE_KEY', ''),
            })

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating setup intent: {e}")
            return JsonResponse({'error': str(e)}, status=400)

    def post(self, request):
        """Save new payment method after Stripe setup."""
        payment_method_id = request.POST.get('payment_method_id')

        if not payment_method_id:
            return JsonResponse({'error': 'Payment method ID is required'}, status=400)

        try:
            # Retrieve payment method from Stripe
            pm = stripe.PaymentMethod.retrieve(payment_method_id)

            # Check if this payment method already exists
            if PaymentMethod.objects.filter(
                stripe_payment_method_id=payment_method_id
            ).exists():
                return JsonResponse({'error': 'Payment method already saved'}, status=400)

            # Determine if this should be default
            is_default = not PaymentMethod.objects.filter(user=request.user).exists()

            # Create local record
            payment_method = PaymentMethod.objects.create(
                user=request.user,
                stripe_payment_method_id=payment_method_id,
                card_brand=pm.card.brand,
                card_last4=pm.card.last4,
                card_exp_month=pm.card.exp_month,
                card_exp_year=pm.card.exp_year,
                is_default=is_default,
            )

            return JsonResponse({
                'success': True,
                'payment_method': {
                    'id': payment_method.id,
                    'brand': payment_method.card_brand,
                    'last4': payment_method.card_last4,
                    'exp_month': payment_method.card_exp_month,
                    'exp_year': payment_method.card_exp_year,
                    'is_default': payment_method.is_default,
                },
            })

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error adding payment method: {e}")
            return JsonResponse({'error': str(e)}, status=400)

    def _get_or_create_customer(self, user):
        """Get or create Stripe customer for user."""
        # Check if user has existing Stripe customer ID stored
        stripe_customer_id = getattr(user, 'stripe_customer_id', None)

        if stripe_customer_id:
            try:
                return stripe.Customer.retrieve(stripe_customer_id)
            except stripe.error.StripeError:
                pass

        # Create new customer
        customer = stripe.Customer.create(
            email=user.email,
            name=user.get_full_name() or user.email,
            metadata={
                'user_id': str(user.id),
            },
        )

        # Store customer ID on user if possible
        if hasattr(user, 'stripe_customer_id'):
            user.stripe_customer_id = customer.id
            user.save(update_fields=['stripe_customer_id'])

        return customer


class PaymentMethodDeleteView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to delete a payment method.
    """

    def post(self, request, pk):
        """Delete the payment method."""
        payment_method = get_object_or_404(
            PaymentMethod,
            user=request.user,
            pk=pk
        )

        try:
            # Detach payment method from Stripe
            stripe.PaymentMethod.detach(payment_method.stripe_payment_method_id)

            was_default = payment_method.is_default
            payment_method.delete()

            # If this was the default, set another as default
            if was_default:
                other_method = PaymentMethod.objects.filter(
                    user=request.user
                ).first()
                if other_method:
                    other_method.is_default = True
                    other_method.save()

            return JsonResponse({
                'success': True,
                'message': 'Payment method deleted',
            })

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error deleting payment method: {e}")
            return JsonResponse({'error': str(e)}, status=400)


class PaymentMethodSetDefaultView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to set a payment method as default.
    """

    def post(self, request, pk):
        """Set the payment method as default."""
        payment_method = get_object_or_404(
            PaymentMethod,
            user=request.user,
            pk=pk
        )

        # Remove default from all other payment methods
        PaymentMethod.objects.filter(
            user=request.user,
            is_default=True
        ).update(is_default=False)

        # Set this one as default
        payment_method.is_default = True
        payment_method.save()

        return JsonResponse({
            'success': True,
            'message': 'Default payment method updated',
        })


# =============================================================================
# REFUND REQUEST VIEWS
# =============================================================================

class RefundRequestCreateView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to create a refund request for a payment.
    """

    def post(self, request, payment_id):
        """Create a refund request."""
        payment = get_object_or_404(
            PaymentTransaction,
            user=request.user,
            id=payment_id,
            succeeded=True
        )

        # Check if refund already requested
        if hasattr(payment, 'refund_request'):
            return JsonResponse({
                'error': 'Refund already requested for this payment'
            }, status=400)

        reason = request.POST.get('reason', '')

        if not reason:
            return JsonResponse({'error': 'Reason is required'}, status=400)

        # Create refund request
        refund_request = RefundRequest.objects.create(
            payment=payment,
            reason=reason,
        )

        return JsonResponse({
            'success': True,
            'message': 'Refund request submitted successfully',
            'request_id': str(refund_request.id),
        })


class RefundRequestListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """
    View to list user's refund requests.
    """
    model = RefundRequest
    template_name = 'finance/refund_requests.html'
    context_object_name = 'refund_requests'
    paginate_by = 20

    def get_queryset(self):
        """Filter refund requests by current user."""
        return RefundRequest.objects.filter(
            payment__user=self.request.user
        ).select_related('payment').order_by('-requested_at')


# =============================================================================
# ESCROW TRANSACTION VIEWS
# =============================================================================

class EscrowTransactionListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """
    View to list user's escrow transactions.
    """
    model = EscrowTransaction
    template_name = 'finance/escrow_list.html'
    context_object_name = 'escrow_transactions'
    paginate_by = 20

    def get_queryset(self):
        """Filter escrow transactions by current user (as buyer or seller)."""
        user = self.request.user
        return EscrowTransaction.objects.filter(
            Q(buyer=user) | Q(seller=user)
        ).order_by('-created_at')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        # Summary statistics
        context['as_buyer_total'] = EscrowTransaction.objects.filter(
            buyer=user
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

        context['as_seller_total'] = EscrowTransaction.objects.filter(
            seller=user
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

        context['pending_as_buyer'] = EscrowTransaction.objects.filter(
            buyer=user,
            status__in=['initialized', 'funded', 'service_delivered']
        ).count()

        context['pending_as_seller'] = EscrowTransaction.objects.filter(
            seller=user,
            status__in=['initialized', 'funded', 'service_delivered']
        ).count()

        return context


class EscrowTransactionDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """
    View to display details of an escrow transaction.
    """
    model = EscrowTransaction
    template_name = 'finance/escrow_detail.html'
    context_object_name = 'escrow'

    def get_queryset(self):
        """Ensure user can only view their own escrow transactions."""
        user = self.request.user
        return EscrowTransaction.objects.filter(
            Q(buyer=user) | Q(seller=user)
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        escrow = self.object

        # Determine user role in this transaction
        context['is_buyer'] = escrow.buyer == self.request.user
        context['is_seller'] = escrow.seller == self.request.user

        # Get related data
        context['disputes'] = escrow.disputes.all()
        context['audit_logs'] = escrow.audit_logs.all().order_by('-timestamp')[:10]

        return context


class EscrowActionView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to perform actions on escrow transactions.
    """

    def post(self, request, pk, action):
        """Perform the specified action on the escrow."""
        user = request.user
        escrow = get_object_or_404(
            EscrowTransaction,
            Q(buyer=user) | Q(seller=user),
            pk=pk
        )

        is_buyer = escrow.buyer == user
        is_seller = escrow.seller == user

        # Validate action based on user role and escrow status
        if action == 'mark_delivered':
            if not is_seller:
                return JsonResponse({
                    'error': 'Only seller can mark as delivered'
                }, status=403)
            if escrow.status != 'funded':
                return JsonResponse({
                    'error': 'Escrow must be funded to mark as delivered'
                }, status=400)

            escrow.mark_service_delivered()
            self._create_audit_log(escrow, user, 'service_delivered')

            return JsonResponse({
                'success': True,
                'message': 'Service marked as delivered',
            })

        elif action == 'release':
            if not is_buyer:
                return JsonResponse({
                    'error': 'Only buyer can release funds'
                }, status=403)
            if escrow.status != 'service_delivered':
                return JsonResponse({
                    'error': 'Service must be delivered before releasing funds'
                }, status=400)

            # Process release via Stripe
            # In production, this would transfer funds to seller
            escrow.mark_released()
            self._create_audit_log(escrow, user, 'funds_released')

            return JsonResponse({
                'success': True,
                'message': 'Funds released to seller',
            })

        elif action == 'dispute':
            if escrow.status in ['released', 'refunded', 'cancelled']:
                return JsonResponse({
                    'error': 'Cannot dispute completed transactions'
                }, status=400)

            reason = request.POST.get('reason', '')
            details = request.POST.get('details', '')

            if not reason:
                return JsonResponse({'error': 'Reason is required'}, status=400)

            escrow.raise_dispute()

            Dispute.objects.create(
                escrow=escrow,
                raised_by=user,
                reason=reason,
                details=details,
            )

            self._create_audit_log(escrow, user, 'dispute_raised', notes=reason)

            return JsonResponse({
                'success': True,
                'message': 'Dispute raised successfully',
            })

        elif action == 'cancel':
            if escrow.status not in ['initialized']:
                return JsonResponse({
                    'error': 'Can only cancel initialized transactions'
                }, status=400)

            escrow.cancel()
            self._create_audit_log(escrow, user, 'cancelled')

            return JsonResponse({
                'success': True,
                'message': 'Escrow transaction cancelled',
            })

        return JsonResponse({'error': 'Invalid action'}, status=400)

    def _create_audit_log(self, escrow, user, action, notes=''):
        """Create audit log entry for escrow action."""
        EscrowAudit.objects.create(
            escrow=escrow,
            user=user,
            action=action,
            notes=notes,
        )


# =============================================================================
# CONNECTED ACCOUNT VIEWS
# =============================================================================

class ConnectedAccountView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to manage user's Stripe Connect account.
    """
    template_name = 'finance/connected_account.html'

    def get(self, request):
        """Display connected account status."""
        try:
            connected_account = ConnectedAccount.objects.get(user=request.user)
        except ConnectedAccount.DoesNotExist:
            connected_account = None

        from django.shortcuts import render
        return render(request, self.template_name, {
            'connected_account': connected_account,
        })

    def post(self, request):
        """Create or update connected account."""
        action = request.POST.get('action')

        if action == 'create':
            # Create new connected account
            try:
                connected_account, created = ConnectedAccount.objects.get_or_create(
                    user=request.user,
                    defaults={
                        'country': request.POST.get('country', 'US'),
                        'business_type': request.POST.get('business_type', 'individual'),
                    }
                )

                if not connected_account.account_id:
                    connected_account.create_connect_account()

                # Create onboarding link
                return_url = request.build_absolute_uri('/finance/connect/return/')
                refresh_url = request.build_absolute_uri('/finance/connect/refresh/')

                onboarding, _ = StripeConnectOnboarding.objects.get_or_create(
                    connected_account=connected_account
                )

                onboarding_url = onboarding.generate_onboarding_link(
                    return_url=return_url,
                    refresh_url=refresh_url,
                )

                return JsonResponse({
                    'success': True,
                    'onboarding_url': onboarding_url,
                })

            except stripe.error.StripeError as e:
                logger.error(f"Stripe error creating connected account: {e}")
                return JsonResponse({'error': str(e)}, status=400)

        elif action == 'refresh':
            # Refresh account status
            try:
                connected_account = ConnectedAccount.objects.get(user=request.user)
                connected_account.refresh_account_status()

                return JsonResponse({
                    'success': True,
                    'status': connected_account.account_status,
                    'charges_enabled': connected_account.charges_enabled,
                    'payouts_enabled': connected_account.payouts_enabled,
                })

            except ConnectedAccount.DoesNotExist:
                return JsonResponse({'error': 'No connected account found'}, status=404)
            except stripe.error.StripeError as e:
                logger.error(f"Stripe error refreshing account: {e}")
                return JsonResponse({'error': str(e)}, status=400)

        return JsonResponse({'error': 'Invalid action'}, status=400)


class ConnectedAccountDashboardView(LoginRequiredMixin, TenantViewMixin, View):
    """
    View to access Stripe Express Dashboard.
    """

    def get(self, request):
        """Generate Stripe Express Dashboard login link."""
        try:
            connected_account = ConnectedAccount.objects.get(user=request.user)

            if not connected_account.account_id:
                return JsonResponse({
                    'error': 'Connected account not set up'
                }, status=400)

            login_link = stripe.Account.create_login_link(
                connected_account.account_id
            )

            return JsonResponse({
                'success': True,
                'dashboard_url': login_link.url,
            })

        except ConnectedAccount.DoesNotExist:
            return JsonResponse({'error': 'No connected account found'}, status=404)
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating dashboard link: {e}")
            return JsonResponse({'error': str(e)}, status=400)


# =============================================================================
# STRIPE WEBHOOK HANDLER
# =============================================================================

@method_decorator(csrf_exempt, name='dispatch')
class StripeWebhookView(View):
    """
    View to handle Stripe webhook events.

    Processes various Stripe events including:
    - Payment events (succeeded, failed)
    - Subscription events (created, updated, canceled)
    - Invoice events (paid, payment_failed)
    - Connect events (account updates)
    """

    def post(self, request):
        """Handle incoming Stripe webhook."""
        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE', '')
        webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', '')

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        except ValueError as e:
            logger.error(f"Invalid webhook payload: {e}")
            return HttpResponse(status=400)
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid webhook signature: {e}")
            return HttpResponse(status=400)

        # Log the webhook event
        webhook_event, created = StripeWebhookEvent.objects.get_or_create(
            event_id=event.id,
            defaults={'json_payload': event.to_dict()}
        )

        if not created:
            # Already processed this event
            return HttpResponse(status=200)

        try:
            # Process the event
            self._process_event(event)

            # Mark as processed
            webhook_event.processed = True
            webhook_event.processed_at = timezone.now()
            webhook_event.save()

        except Exception as e:
            logger.error(f"Error processing webhook event {event.id}: {e}")
            webhook_event.error_message = str(e)
            webhook_event.save()
            return HttpResponse(status=500)

        return HttpResponse(status=200)

    def _process_event(self, event):
        """Route event to appropriate handler."""
        event_type = event.type

        handlers = {
            # Payment events
            'payment_intent.succeeded': self._handle_payment_succeeded,
            'payment_intent.payment_failed': self._handle_payment_failed,

            # Subscription events
            'customer.subscription.created': self._handle_subscription_created,
            'customer.subscription.updated': self._handle_subscription_updated,
            'customer.subscription.deleted': self._handle_subscription_deleted,

            # Invoice events
            'invoice.paid': self._handle_invoice_paid,
            'invoice.payment_failed': self._handle_invoice_payment_failed,

            # Checkout events
            'checkout.session.completed': self._handle_checkout_completed,

            # Connect events
            'account.updated': self._handle_account_updated,
            'capability.updated': self._handle_capability_updated,
        }

        handler = handlers.get(event_type)
        if handler:
            handler(event.data.object)
        else:
            logger.info(f"Unhandled webhook event type: {event_type}")

    def _handle_payment_succeeded(self, payment_intent):
        """Handle successful payment."""
        logger.info(f"Payment succeeded: {payment_intent.id}")

        # Update payment transaction if exists
        try:
            payment = PaymentTransaction.objects.get(
                stripe_payment_intent_id=payment_intent.id
            )
            payment.succeeded = True
            payment.save()
        except PaymentTransaction.DoesNotExist:
            # Create new payment record from webhook
            user_id = payment_intent.metadata.get('user_id')
            if user_id:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                try:
                    user = User.objects.get(pk=user_id)
                    PaymentTransaction.objects.create(
                        user=user,
                        amount=Decimal(payment_intent.amount) / 100,
                        currency=payment_intent.currency.upper(),
                        stripe_payment_intent_id=payment_intent.id,
                        description=payment_intent.description or '',
                        succeeded=True,
                    )
                except User.DoesNotExist:
                    logger.warning(f"User not found for payment: {user_id}")

    def _handle_payment_failed(self, payment_intent):
        """Handle failed payment."""
        logger.info(f"Payment failed: {payment_intent.id}")

        try:
            payment = PaymentTransaction.objects.get(
                stripe_payment_intent_id=payment_intent.id
            )
            payment.succeeded = False
            if payment_intent.last_payment_error:
                payment.failure_code = payment_intent.last_payment_error.code
                payment.failure_message = payment_intent.last_payment_error.message
            payment.save()
        except PaymentTransaction.DoesNotExist:
            pass

    def _handle_subscription_created(self, subscription):
        """Handle new subscription."""
        logger.info(f"Subscription created: {subscription.id}")

        # Get user from metadata or customer
        user_id = subscription.metadata.get('user_id')
        if not user_id:
            return

        from django.contrib.auth import get_user_model
        User = get_user_model()

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            logger.warning(f"User not found for subscription: {user_id}")
            return

        # Find matching plan
        try:
            plan = SubscriptionPlan.objects.get(
                stripe_price_id=subscription.items.data[0].price.id
            )
        except SubscriptionPlan.DoesNotExist:
            logger.warning(f"Plan not found for subscription: {subscription.id}")
            plan = None

        # Create or update user subscription
        UserSubscription.objects.update_or_create(
            user=user,
            defaults={
                'plan': plan,
                'stripe_subscription_id': subscription.id,
                'status': subscription.status,
                'current_period_start': timezone.datetime.fromtimestamp(
                    subscription.current_period_start,
                    tz=timezone.utc
                ),
                'current_period_end': timezone.datetime.fromtimestamp(
                    subscription.current_period_end,
                    tz=timezone.utc
                ),
            }
        )

    def _handle_subscription_updated(self, subscription):
        """Handle subscription update."""
        logger.info(f"Subscription updated: {subscription.id}")

        try:
            user_subscription = UserSubscription.objects.get(
                stripe_subscription_id=subscription.id
            )
            user_subscription.status = subscription.status
            user_subscription.current_period_start = timezone.datetime.fromtimestamp(
                subscription.current_period_start,
                tz=timezone.utc
            )
            user_subscription.current_period_end = timezone.datetime.fromtimestamp(
                subscription.current_period_end,
                tz=timezone.utc
            )
            user_subscription.save()
        except UserSubscription.DoesNotExist:
            logger.warning(f"Subscription not found: {subscription.id}")

    def _handle_subscription_deleted(self, subscription):
        """Handle subscription cancellation."""
        logger.info(f"Subscription deleted: {subscription.id}")

        try:
            user_subscription = UserSubscription.objects.get(
                stripe_subscription_id=subscription.id
            )
            user_subscription.status = 'canceled'
            user_subscription.save()
        except UserSubscription.DoesNotExist:
            pass

    def _handle_invoice_paid(self, invoice):
        """Handle paid invoice."""
        logger.info(f"Invoice paid: {invoice.id}")

        try:
            local_invoice = Invoice.objects.get(stripe_invoice_id=invoice.id)
            local_invoice.paid = True
            local_invoice.amount_paid = Decimal(invoice.amount_paid) / 100
            local_invoice.paid_at = timezone.now()
            local_invoice.save()
        except Invoice.DoesNotExist:
            pass

    def _handle_invoice_payment_failed(self, invoice):
        """Handle failed invoice payment."""
        logger.info(f"Invoice payment failed: {invoice.id}")
        # Could trigger notification to user here

    def _handle_checkout_completed(self, session):
        """Handle completed checkout session."""
        logger.info(f"Checkout completed: {session.id}")

        metadata = session.metadata or {}
        user_id = metadata.get('user_id')

        if session.mode == 'subscription':
            # Subscription checkout - handled by subscription events
            pass
        elif session.mode == 'payment':
            # One-time payment checkout
            invoice_id = metadata.get('invoice_id')
            if invoice_id:
                try:
                    invoice = Invoice.objects.get(pk=invoice_id)
                    invoice.paid = True
                    invoice.amount_paid = Decimal(session.amount_total) / 100
                    invoice.paid_at = timezone.now()
                    invoice.save()
                except Invoice.DoesNotExist:
                    pass

    def _handle_account_updated(self, account):
        """Handle Connect account update."""
        logger.info(f"Connected account updated: {account.id}")

        try:
            connected_account = ConnectedAccount.objects.get(account_id=account.id)
            connected_account.charges_enabled = account.charges_enabled
            connected_account.payouts_enabled = account.payouts_enabled
            connected_account.details_submitted = account.details_submitted

            if hasattr(account, 'capabilities'):
                connected_account.capabilities = dict(account.capabilities)

            # Update status
            if account.charges_enabled and account.payouts_enabled:
                connected_account.account_status = 'active'
                if not connected_account.activated_at:
                    connected_account.activated_at = timezone.now()
            elif account.details_submitted:
                connected_account.account_status = 'restricted'
            else:
                connected_account.account_status = 'onboarding'

            connected_account.stripe_metadata = dict(account)
            connected_account.save()

            # Update onboarding requirements
            if hasattr(account, 'requirements'):
                try:
                    onboarding = connected_account.onboarding
                    onboarding.update_requirements(dict(account.requirements))
                except StripeConnectOnboarding.DoesNotExist:
                    pass

        except ConnectedAccount.DoesNotExist:
            logger.warning(f"Connected account not found: {account.id}")

    def _handle_capability_updated(self, capability):
        """Handle capability update for Connect account."""
        logger.info(f"Capability updated: {capability.id}")

        account_id = capability.account
        capability_name = capability.id.split('_')[0]  # e.g., 'transfers' from 'transfers_xxx'
        status = capability.status

        try:
            connected_account = ConnectedAccount.objects.get(account_id=account_id)
            connected_account.handle_capability_updated(capability_name, status)
        except ConnectedAccount.DoesNotExist:
            logger.warning(f"Connected account not found: {account_id}")
