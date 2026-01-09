"""
Finance API ViewSets - Payment, Subscription, and Stripe Connect REST API Endpoints

This module provides DRF ViewSets for:
- Payment transactions and history
- Subscription management with actions (cancel, upgrade)
- Invoices with actions (pay, download)
- Payment methods with actions (set_default)
- Refund requests with actions (approve, reject)
- Escrow transactions with actions (fund, release, dispute)
- Stripe Connect marketplace (connected accounts, payouts, platform fees)
"""

import logging
from decimal import Decimal
from django.db.models import Sum, Count, Avg, Q
from django.utils import timezone
from django.shortcuts import get_object_or_404

from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response

from core.viewsets import (
    SecureTenantViewSet,
    SecureReadOnlyViewSet,
    AdminOnlyViewSet,
    OwnerOnlyViewSet,
    ParticipantViewSet,
    RoleBasedViewSet,
)
from api.base import APIResponse

from ..models import (
    PaymentTransaction, SubscriptionPlan, UserSubscription,
    Invoice, RefundRequest, PaymentMethod, StripeWebhookEvent,
    EscrowTransaction, Dispute, EscrowPayout, EscrowAudit,
    ConnectedAccount, PayoutSchedule, PlatformFee, StripeConnectOnboarding
)
from ..serializers import (
    # Payment serializers
    PaymentTransactionListSerializer,
    PaymentTransactionDetailSerializer,
    PaymentTransactionCreateSerializer,
    # Subscription serializers
    SubscriptionPlanSerializer,
    SubscriptionPlanAdminSerializer,
    UserSubscriptionSerializer,
    UserSubscriptionCreateSerializer,
    SubscriptionCancelSerializer,
    SubscriptionUpgradeSerializer,
    # Invoice serializers
    InvoiceListSerializer,
    InvoiceDetailSerializer,
    InvoiceCreateSerializer,
    InvoicePaySerializer,
    # Payment method serializers
    PaymentMethodSerializer,
    PaymentMethodCreateSerializer,
    SetDefaultPaymentMethodSerializer,
    # Refund serializers
    RefundRequestSerializer,
    RefundRequestCreateSerializer,
    RefundApproveSerializer,
    # Escrow serializers
    EscrowTransactionListSerializer,
    EscrowTransactionDetailSerializer,
    EscrowTransactionCreateSerializer,
    EscrowActionSerializer,
    # Dispute serializers
    DisputeListSerializer,
    DisputeDetailSerializer,
    DisputeCreateSerializer,
    DisputeResponseSerializer,
    DisputeResolveSerializer,
    # Escrow payout/audit serializers
    EscrowPayoutSerializer,
    EscrowAuditSerializer,
    # Stripe Connect serializers
    ConnectedAccountListSerializer,
    ConnectedAccountDetailSerializer,
    ConnectedAccountCreateSerializer,
    ConnectedAccountOnboardingSerializer,
    ConnectedAccountRefreshSerializer,
    ConnectedAccountDashboardLinkSerializer,
    PayoutScheduleSerializer,
    PayoutScheduleCreateSerializer,
    PayoutSchedulePauseSerializer,
    PlatformFeeListSerializer,
    PlatformFeeDetailSerializer,
    PlatformFeeCalculationSerializer,
    PlatformFeeCalculationResponseSerializer,
    PlatformFeeRefundSerializer,
    StripeConnectOnboardingSerializer,
    StripeConnectOnboardingCreateSerializer,
    TransferListSerializer,
    TransferCreateSerializer,
    TransferReverseSerializer,
    BalanceSerializer,
    BalanceTransactionSerializer,
    # Webhook serializer
    StripeWebhookEventSerializer,
    # Analytics serializers
    PaymentStatsSerializer,
    RevenueChartDataSerializer,
    SubscriptionStatsSerializer,
    EscrowStatsSerializer,
    ConnectStatsSerializer,
)

logger = logging.getLogger('finance.api')


# =============================================================================
# PAYMENT TRANSACTION VIEWSETS
# =============================================================================

class PaymentTransactionViewSet(SecureTenantViewSet):
    """
    ViewSet for payment transactions.

    Provides:
    - List payment history (own transactions or all for admins)
    - Retrieve transaction details
    - Create new transactions (admin only)
    """
    queryset = PaymentTransaction.objects.all()
    serializer_class = PaymentTransactionListSerializer
    tenant_field = None  # Filter by user instead

    action_permissions = {
        'create': [permissions.IsAuthenticated],
    }

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return PaymentTransactionDetailSerializer
        if self.action == 'create':
            return PaymentTransactionCreateSerializer
        return PaymentTransactionListSerializer

    def get_queryset(self):
        queryset = PaymentTransaction.objects.all()
        user = self.request.user

        # Non-staff users can only see their own transactions
        if not user.is_staff and not user.is_superuser:
            queryset = queryset.filter(user=user)

        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter == 'succeeded':
            queryset = queryset.filter(succeeded=True)
        elif status_filter == 'failed':
            queryset = queryset.filter(succeeded=False, failure_code__isnull=False)

        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date:
            queryset = queryset.filter(created_at__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__date__lte=end_date)

        return queryset.select_related('user').order_by('-created_at')

    @action(detail=False, methods=['get'])
    def my_transactions(self, request):
        """Get current user's transactions only."""
        queryset = self.get_queryset().filter(user=request.user)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get payment statistics (admin only)."""
        if not request.user.is_staff:
            return APIResponse.forbidden("Admin access required")

        queryset = self.get_queryset()

        stats = {
            'total_transactions': queryset.count(),
            'successful_transactions': queryset.filter(succeeded=True).count(),
            'failed_transactions': queryset.filter(succeeded=False).count(),
            'total_amount': queryset.filter(succeeded=True).aggregate(
                total=Sum('amount')
            )['total'] or Decimal('0.00'),
            'average_transaction': queryset.filter(succeeded=True).aggregate(
                avg=Avg('amount')
            )['avg'] or Decimal('0.00'),
        }

        if stats['total_transactions'] > 0:
            stats['success_rate'] = (
                stats['successful_transactions'] / stats['total_transactions'] * 100
            )
        else:
            stats['success_rate'] = 0

        return APIResponse.success(data=stats)


# =============================================================================
# SUBSCRIPTION VIEWSETS
# =============================================================================

class SubscriptionPlanViewSet(SecureReadOnlyViewSet):
    """
    ViewSet for subscription plans (read-only for users).

    List and retrieve available subscription plans.
    Admin can manage plans via admin panel.
    """
    queryset = SubscriptionPlan.objects.all()
    serializer_class = SubscriptionPlanSerializer
    tenant_field = None  # Plans are global

    def get_queryset(self):
        return SubscriptionPlan.objects.all().order_by('price')


class UserSubscriptionViewSet(SecureTenantViewSet):
    """
    ViewSet for user subscriptions.

    Actions:
    - cancel: Cancel subscription
    - reactivate: Reactivate cancelled subscription
    - upgrade: Upgrade to a different plan
    """
    queryset = UserSubscription.objects.all()
    serializer_class = UserSubscriptionSerializer
    tenant_field = None  # Filter by user

    def get_queryset(self):
        queryset = UserSubscription.objects.all()
        user = self.request.user

        if not user.is_staff:
            queryset = queryset.filter(user=user)

        return queryset.select_related('user', 'plan')

    def get_serializer_class(self):
        if self.action == 'create':
            return UserSubscriptionCreateSerializer
        return UserSubscriptionSerializer

    @action(detail=False, methods=['get'])
    def my_subscription(self, request):
        """Get current user's subscription."""
        try:
            subscription = UserSubscription.objects.select_related('plan').get(
                user=request.user
            )
            serializer = self.get_serializer(subscription)
            return Response(serializer.data)
        except UserSubscription.DoesNotExist:
            return APIResponse.not_found("No active subscription found")

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel subscription."""
        subscription = self.get_object()

        # Validate user owns subscription
        if subscription.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot cancel another user's subscription")

        serializer = SubscriptionCancelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # In production, this would call Stripe API
        # stripe.Subscription.modify(
        #     subscription.stripe_subscription_id,
        #     cancel_at_period_end=serializer.validated_data['cancel_at_period_end']
        # )

        if serializer.validated_data.get('cancel_at_period_end', True):
            subscription.status = 'canceling'
        else:
            subscription.status = 'canceled'
        subscription.save()

        logger.info(
            f"Subscription cancelled: user={subscription.user.id} "
            f"plan={subscription.plan.name}"
        )

        return APIResponse.success(
            data=UserSubscriptionSerializer(subscription, context=self.get_serializer_context()).data,
            message="Subscription cancelled successfully"
        )

    @action(detail=True, methods=['post'])
    def reactivate(self, request, pk=None):
        """Reactivate a cancelled subscription."""
        subscription = self.get_object()

        if subscription.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot reactivate another user's subscription")

        if subscription.status not in ['canceling', 'canceled']:
            return APIResponse.error(
                message="Subscription is not cancelled",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        subscription.status = 'active'
        subscription.save()

        return APIResponse.success(
            data=UserSubscriptionSerializer(subscription, context=self.get_serializer_context()).data,
            message="Subscription reactivated successfully"
        )

    @action(detail=True, methods=['post'])
    def upgrade(self, request, pk=None):
        """Upgrade subscription to a different plan."""
        subscription = self.get_object()

        if subscription.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot upgrade another user's subscription")

        serializer = SubscriptionUpgradeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_plan = serializer.validated_data['new_plan_id']

        if new_plan == subscription.plan:
            return APIResponse.error(
                message="Already subscribed to this plan",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        # In production, this would call Stripe API to prorate
        subscription.plan = new_plan
        subscription.save()

        logger.info(
            f"Subscription upgraded: user={subscription.user.id} "
            f"new_plan={new_plan.name}"
        )

        return APIResponse.success(
            data=UserSubscriptionSerializer(subscription, context=self.get_serializer_context()).data,
            message=f"Subscription upgraded to {new_plan.name}"
        )


# =============================================================================
# INVOICE VIEWSETS
# =============================================================================

class InvoiceViewSet(SecureTenantViewSet):
    """
    ViewSet for invoices.

    Actions:
    - pay: Pay an invoice
    - download: Download invoice PDF
    - send: Send invoice to email
    """
    queryset = Invoice.objects.all()
    serializer_class = InvoiceListSerializer
    tenant_field = None  # Filter by user

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return InvoiceDetailSerializer
        if self.action == 'create':
            return InvoiceCreateSerializer
        return InvoiceListSerializer

    def get_queryset(self):
        queryset = Invoice.objects.all()
        user = self.request.user

        if not user.is_staff:
            queryset = queryset.filter(user=user)

        # Filter by status
        paid = self.request.query_params.get('paid')
        if paid is not None:
            queryset = queryset.filter(paid=paid.lower() == 'true')

        return queryset.select_related('user').order_by('-created_at')

    @action(detail=True, methods=['post'])
    def pay(self, request, pk=None):
        """Pay an invoice."""
        invoice = self.get_object()

        if invoice.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot pay another user's invoice")

        if invoice.paid:
            return APIResponse.error(
                message="Invoice already paid",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        serializer = InvoicePaySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # In production, this would process payment via Stripe
        payment_method_id = serializer.validated_data['payment_method_id']
        amount = serializer.validated_data.get('amount') or (
            invoice.amount_due - invoice.amount_paid
        )

        # Simulate successful payment
        invoice.amount_paid += amount
        if invoice.amount_paid >= invoice.amount_due:
            invoice.paid = True
            invoice.paid_at = timezone.now()
        invoice.save()

        return APIResponse.success(
            data=InvoiceDetailSerializer(invoice, context=self.get_serializer_context()).data,
            message="Payment processed successfully"
        )

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Download invoice as PDF."""
        invoice = self.get_object()

        if invoice.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot download another user's invoice")

        # In production, this would generate and return PDF
        return APIResponse.success(
            data={'download_url': f'/api/v1/finance/invoices/{invoice.id}/pdf/'},
            message="Download link generated"
        )

    @action(detail=True, methods=['post'])
    def send(self, request, pk=None):
        """Send invoice to user's email."""
        invoice = self.get_object()

        if not request.user.is_staff:
            return APIResponse.forbidden("Admin access required")

        # In production, this would send email
        logger.info(f"Invoice {invoice.invoice_number} sent to {invoice.user.email}")

        return APIResponse.success(
            message=f"Invoice sent to {invoice.user.email}"
        )


# =============================================================================
# PAYMENT METHOD VIEWSETS
# =============================================================================

class PaymentMethodViewSet(SecureTenantViewSet):
    """
    ViewSet for payment methods.

    Actions:
    - set_default: Set a payment method as default
    """
    queryset = PaymentMethod.objects.all()
    serializer_class = PaymentMethodSerializer
    tenant_field = None  # Filter by user

    def get_serializer_class(self):
        if self.action == 'create':
            return PaymentMethodCreateSerializer
        return PaymentMethodSerializer

    def get_queryset(self):
        queryset = PaymentMethod.objects.all()
        user = self.request.user

        if not user.is_staff:
            queryset = queryset.filter(user=user)

        return queryset.order_by('-is_default', '-added_at')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'])
    def set_default(self, request, pk=None):
        """Set payment method as default."""
        payment_method = self.get_object()

        if payment_method.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot modify another user's payment method")

        # Unset current default
        PaymentMethod.objects.filter(
            user=payment_method.user,
            is_default=True
        ).update(is_default=False)

        # Set new default
        payment_method.is_default = True
        payment_method.save()

        return APIResponse.success(
            data=PaymentMethodSerializer(payment_method, context=self.get_serializer_context()).data,
            message="Default payment method updated"
        )


# =============================================================================
# REFUND VIEWSETS
# =============================================================================

class RefundRequestViewSet(SecureTenantViewSet):
    """
    ViewSet for refund requests.

    Actions:
    - approve: Approve refund (admin)
    - reject: Reject refund (admin)
    """
    queryset = RefundRequest.objects.all()
    serializer_class = RefundRequestSerializer
    tenant_field = None

    action_permissions = {
        'approve': [permissions.IsAdminUser],
        'reject': [permissions.IsAdminUser],
    }

    def get_serializer_class(self):
        if self.action == 'create':
            return RefundRequestCreateSerializer
        return RefundRequestSerializer

    def get_queryset(self):
        queryset = RefundRequest.objects.all()
        user = self.request.user

        if not user.is_staff:
            queryset = queryset.filter(payment__user=user)

        return queryset.select_related('payment', 'payment__user', 'processed_by')

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve refund request (admin only)."""
        refund = self.get_object()

        if refund.processed_at:
            return APIResponse.error(
                message="Refund already processed",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        refund.approved = True
        refund.processed_at = timezone.now()
        refund.processed_by = request.user
        refund.save()

        logger.info(
            f"Refund approved: id={refund.id} payment={refund.payment.id} "
            f"by={request.user.id}"
        )

        return APIResponse.success(
            data=RefundRequestSerializer(refund, context=self.get_serializer_context()).data,
            message="Refund approved"
        )

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject refund request (admin only)."""
        refund = self.get_object()

        if refund.processed_at:
            return APIResponse.error(
                message="Refund already processed",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        refund.approved = False
        refund.processed_at = timezone.now()
        refund.processed_by = request.user
        refund.save()

        return APIResponse.success(
            data=RefundRequestSerializer(refund, context=self.get_serializer_context()).data,
            message="Refund rejected"
        )


# =============================================================================
# ESCROW VIEWSETS
# =============================================================================

class EscrowTransactionViewSet(ParticipantViewSet):
    """
    ViewSet for escrow transactions.

    Only participants (buyer/seller) can access their escrow transactions.
    Admins can view all.

    Actions:
    - fund: Fund the escrow (buyer)
    - mark_delivered: Mark service as delivered (seller)
    - release: Release funds to seller (buyer)
    - dispute: Raise a dispute (participant)
    - cancel: Cancel escrow (buyer, before funding)
    """
    queryset = EscrowTransaction.objects.all()
    serializer_class = EscrowTransactionListSerializer
    participant_fields = ['buyer', 'seller']
    tenant_field = None

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return EscrowTransactionDetailSerializer
        if self.action == 'create':
            return EscrowTransactionCreateSerializer
        return EscrowTransactionListSerializer

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Filter by role
        role = self.request.query_params.get('role')
        if role == 'buyer':
            queryset = queryset.filter(buyer=self.request.user)
        elif role == 'seller':
            queryset = queryset.filter(seller=self.request.user)

        return queryset.select_related('buyer', 'seller').order_by('-created_at')

    @action(detail=True, methods=['post'])
    def fund(self, request, pk=None):
        """Fund the escrow (buyer only)."""
        escrow = self.get_object()

        if escrow.buyer != request.user:
            return APIResponse.forbidden("Only the buyer can fund this escrow")

        if escrow.status != 'initialized':
            return APIResponse.error(
                message=f"Cannot fund escrow in {escrow.status} status",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        serializer = EscrowActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # In production, this would process payment
        escrow.mark_funded()

        # Create audit log
        EscrowAudit.objects.create(
            escrow=escrow,
            user=request.user,
            action='funded',
            notes=f"Escrow funded with ${escrow.amount}"
        )

        return APIResponse.success(
            data=EscrowTransactionDetailSerializer(escrow, context=self.get_serializer_context()).data,
            message="Escrow funded successfully"
        )

    @action(detail=True, methods=['post'])
    def mark_delivered(self, request, pk=None):
        """Mark service as delivered (seller only)."""
        escrow = self.get_object()

        if escrow.seller != request.user:
            return APIResponse.forbidden("Only the seller can mark service delivered")

        if escrow.status != 'funded':
            return APIResponse.error(
                message=f"Cannot mark delivered in {escrow.status} status",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        escrow.mark_service_delivered()

        EscrowAudit.objects.create(
            escrow=escrow,
            user=request.user,
            action='service_delivered',
            notes="Service marked as delivered by seller"
        )

        return APIResponse.success(
            data=EscrowTransactionDetailSerializer(escrow, context=self.get_serializer_context()).data,
            message="Service marked as delivered"
        )

    @action(detail=True, methods=['post'])
    def release(self, request, pk=None):
        """Release funds to seller (buyer only)."""
        escrow = self.get_object()

        if escrow.buyer != request.user:
            return APIResponse.forbidden("Only the buyer can release funds")

        if escrow.status != 'service_delivered':
            return APIResponse.error(
                message=f"Cannot release funds in {escrow.status} status",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        escrow.mark_released()

        # Create payout record
        EscrowPayout.objects.create(
            escrow=escrow,
            payout_id=f"payout_{escrow.id}",  # In production, from Stripe
            amount=escrow.amount,
            currency=escrow.currency,
            status='completed'
        )

        EscrowAudit.objects.create(
            escrow=escrow,
            user=request.user,
            action='released',
            notes=f"Funds released to seller: ${escrow.amount}"
        )

        return APIResponse.success(
            data=EscrowTransactionDetailSerializer(escrow, context=self.get_serializer_context()).data,
            message="Funds released to seller"
        )

    @action(detail=True, methods=['post'])
    def dispute(self, request, pk=None):
        """Raise a dispute (participant only)."""
        escrow = self.get_object()

        if escrow.buyer != request.user and escrow.seller != request.user:
            return APIResponse.forbidden("Only participants can raise disputes")

        if escrow.status not in ['funded', 'service_delivered']:
            return APIResponse.error(
                message=f"Cannot raise dispute in {escrow.status} status",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        serializer = EscrowActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        reason = serializer.validated_data.get('reason')
        if not reason:
            return APIResponse.error(
                message="Reason is required to raise dispute",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        # Create dispute
        dispute = Dispute.objects.create(
            escrow=escrow,
            raised_by=request.user,
            reason=reason,
            details=serializer.validated_data.get('notes', '')
        )

        escrow.raise_dispute()

        EscrowAudit.objects.create(
            escrow=escrow,
            user=request.user,
            action='dispute_raised',
            notes=f"Dispute raised: {reason}"
        )

        return APIResponse.success(
            data=DisputeDetailSerializer(dispute, context=self.get_serializer_context()).data,
            message="Dispute raised successfully"
        )

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel escrow (buyer only, before funding)."""
        escrow = self.get_object()

        if escrow.buyer != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Only the buyer can cancel this escrow")

        if escrow.status != 'initialized':
            return APIResponse.error(
                message="Can only cancel unfunded escrows",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        escrow.cancel()

        EscrowAudit.objects.create(
            escrow=escrow,
            user=request.user,
            action='cancelled',
            notes="Escrow cancelled by buyer"
        )

        return APIResponse.success(
            data=EscrowTransactionDetailSerializer(escrow, context=self.get_serializer_context()).data,
            message="Escrow cancelled"
        )

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get escrow statistics for current user."""
        user = request.user

        as_buyer = EscrowTransaction.objects.filter(buyer=user)
        as_seller = EscrowTransaction.objects.filter(seller=user)

        stats = {
            'as_buyer': {
                'total': as_buyer.count(),
                'active': as_buyer.filter(
                    status__in=['initialized', 'funded', 'service_delivered']
                ).count(),
                'total_amount': as_buyer.filter(
                    status__in=['funded', 'service_delivered', 'released']
                ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            },
            'as_seller': {
                'total': as_seller.count(),
                'active': as_seller.filter(
                    status__in=['funded', 'service_delivered']
                ).count(),
                'total_received': as_seller.filter(
                    status='released'
                ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            },
        }

        return APIResponse.success(data=stats)


class DisputeViewSet(SecureTenantViewSet):
    """
    ViewSet for disputes.

    Actions:
    - respond: Respond to a dispute (other party)
    - resolve: Resolve dispute (admin only)
    """
    queryset = Dispute.objects.all()
    serializer_class = DisputeListSerializer
    tenant_field = None

    action_permissions = {
        'resolve': [permissions.IsAdminUser],
    }

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return DisputeDetailSerializer
        if self.action == 'create':
            return DisputeCreateSerializer
        return DisputeListSerializer

    def get_queryset(self):
        queryset = Dispute.objects.all()
        user = self.request.user

        if not user.is_staff:
            queryset = queryset.filter(
                Q(raised_by=user) |
                Q(escrow__buyer=user) |
                Q(escrow__seller=user)
            )

        return queryset.select_related('escrow', 'raised_by').order_by('-created_at')

    @action(detail=True, methods=['post'])
    def respond(self, request, pk=None):
        """Respond to a dispute."""
        dispute = self.get_object()

        # Only the other party can respond
        escrow = dispute.escrow
        if dispute.raised_by == request.user:
            return APIResponse.error(
                message="Cannot respond to your own dispute",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        if escrow.buyer != request.user and escrow.seller != request.user:
            return APIResponse.forbidden("Only participants can respond")

        serializer = DisputeResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Add response to details
        dispute.details += f"\n\n--- Response from {request.user.get_full_name()} ---\n"
        dispute.details += serializer.validated_data['response']
        dispute.save()

        return APIResponse.success(
            data=DisputeDetailSerializer(dispute, context=self.get_serializer_context()).data,
            message="Response added to dispute"
        )

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve dispute (admin only)."""
        dispute = self.get_object()

        if dispute.resolved:
            return APIResponse.error(
                message="Dispute already resolved",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        serializer = DisputeResolveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        resolution = serializer.validated_data['resolution']
        escrow = dispute.escrow

        # Process resolution
        if resolution == 'refund_buyer':
            escrow.mark_refunded()
            notes = "Full refund to buyer"
        elif resolution == 'release_to_seller':
            escrow.mark_released()
            EscrowPayout.objects.create(
                escrow=escrow,
                payout_id=f"payout_{escrow.id}",
                amount=escrow.amount,
                currency=escrow.currency,
                status='completed'
            )
            notes = "Funds released to seller"
        else:  # partial_refund
            percentage = serializer.validated_data['refund_percentage']
            refund_amount = escrow.amount * percentage / 100
            seller_amount = escrow.amount - refund_amount
            notes = f"Partial refund: {percentage}% to buyer, {100-percentage}% to seller"

        dispute.resolved = True
        dispute.resolved_at = timezone.now()
        dispute.resolution_notes = serializer.validated_data['resolution_notes']
        dispute.save()

        EscrowAudit.objects.create(
            escrow=escrow,
            user=request.user,
            action='dispute_resolved',
            notes=notes
        )

        return APIResponse.success(
            data=DisputeDetailSerializer(dispute, context=self.get_serializer_context()).data,
            message="Dispute resolved"
        )


class EscrowPayoutViewSet(SecureReadOnlyViewSet):
    """ViewSet for escrow payouts (read-only)."""
    queryset = EscrowPayout.objects.all()
    serializer_class = EscrowPayoutSerializer
    tenant_field = None

    def get_queryset(self):
        queryset = EscrowPayout.objects.all()
        user = self.request.user

        if not user.is_staff:
            queryset = queryset.filter(escrow__seller=user)

        return queryset.select_related('escrow').order_by('-paid_at')


# =============================================================================
# STRIPE CONNECT VIEWSETS
# =============================================================================

class ConnectedAccountViewSet(SecureTenantViewSet):
    """
    ViewSet for Stripe Connect connected accounts.

    Actions:
    - create_onboarding_link: Generate onboarding URL
    - refresh_status: Refresh account status from Stripe
    - dashboard_link: Get Stripe Express Dashboard link
    - deauthorize: Disconnect account
    """
    queryset = ConnectedAccount.objects.all()
    serializer_class = ConnectedAccountListSerializer
    tenant_field = None

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return ConnectedAccountDetailSerializer
        if self.action == 'create':
            return ConnectedAccountCreateSerializer
        return ConnectedAccountListSerializer

    def get_queryset(self):
        queryset = ConnectedAccount.objects.all()
        user = self.request.user

        if not user.is_staff:
            queryset = queryset.filter(user=user)

        return queryset.select_related('user').order_by('-created_at')

    def perform_create(self, serializer):
        instance = serializer.save()

        # Create Stripe Connect account
        try:
            instance.create_connect_account()
        except Exception as e:
            logger.error(f"Failed to create Stripe account: {e}")
            # Don't delete, allow retry

    @action(detail=False, methods=['get'])
    def my_account(self, request):
        """Get current user's connected account."""
        try:
            account = ConnectedAccount.objects.select_related('user').get(
                user=request.user
            )
            serializer = ConnectedAccountDetailSerializer(
                account, context=self.get_serializer_context()
            )
            return Response(serializer.data)
        except ConnectedAccount.DoesNotExist:
            return APIResponse.not_found("No connected account found")

    @action(detail=True, methods=['post'])
    def create_onboarding_link(self, request, pk=None):
        """Generate onboarding link for connected account."""
        account = self.get_object()

        if account.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot generate link for another user's account")

        serializer = ConnectedAccountOnboardingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            # Get or create onboarding record
            onboarding, created = StripeConnectOnboarding.objects.get_or_create(
                connected_account=account
            )

            url = onboarding.generate_onboarding_link(
                return_url=serializer.validated_data['return_url'],
                refresh_url=serializer.validated_data['refresh_url']
            )

            return APIResponse.success(
                data={'onboarding_url': url},
                message="Onboarding link generated"
            )
        except Exception as e:
            logger.error(f"Failed to generate onboarding link: {e}")
            return APIResponse.error(
                message=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['post'])
    def refresh_status(self, request, pk=None):
        """Refresh account status from Stripe."""
        account = self.get_object()

        if account.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot refresh another user's account")

        try:
            account.refresh_account_status()
            return APIResponse.success(
                data=ConnectedAccountDetailSerializer(account, context=self.get_serializer_context()).data,
                message="Account status refreshed"
            )
        except Exception as e:
            logger.error(f"Failed to refresh account status: {e}")
            return APIResponse.error(
                message=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['get'])
    def dashboard_link(self, request, pk=None):
        """Get Stripe Express Dashboard link."""
        account = self.get_object()

        if account.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot access another user's dashboard")

        if not account.account_id:
            return APIResponse.error(
                message="Account not yet created in Stripe",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        try:
            import stripe
            login_link = stripe.Account.create_login_link(account.account_id)

            return APIResponse.success(
                data={
                    'url': login_link.url,
                    'expires_at': None  # Login links don't expire
                }
            )
        except Exception as e:
            logger.error(f"Failed to create dashboard link: {e}")
            return APIResponse.error(
                message=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['post'])
    def deauthorize(self, request, pk=None):
        """Deauthorize/disconnect connected account."""
        account = self.get_object()

        if account.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot deauthorize another user's account")

        account.account_status = 'disabled'
        account.charges_enabled = False
        account.payouts_enabled = False
        account.save()

        logger.info(f"Connected account deauthorized: {account.account_id}")

        return APIResponse.success(message="Account disconnected")


class PayoutScheduleViewSet(SecureTenantViewSet):
    """
    ViewSet for payout schedules.

    Actions:
    - pause: Pause automatic payouts
    - resume: Resume automatic payouts
    """
    queryset = PayoutSchedule.objects.all()
    serializer_class = PayoutScheduleSerializer
    tenant_field = None

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return PayoutScheduleCreateSerializer
        return PayoutScheduleSerializer

    def get_queryset(self):
        queryset = PayoutSchedule.objects.all()
        user = self.request.user

        if not user.is_staff:
            queryset = queryset.filter(connected_account__user=user)

        return queryset.select_related('connected_account', 'connected_account__user')

    @action(detail=True, methods=['post'])
    def pause(self, request, pk=None):
        """Pause automatic payouts."""
        schedule = self.get_object()

        if schedule.connected_account.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot modify another user's payout schedule")

        schedule.interval = 'manual'
        schedule.save()

        try:
            schedule.apply_to_stripe()
        except Exception as e:
            logger.error(f"Failed to apply payout schedule to Stripe: {e}")

        return APIResponse.success(
            data=PayoutScheduleSerializer(schedule, context=self.get_serializer_context()).data,
            message="Automatic payouts paused"
        )

    @action(detail=True, methods=['post'])
    def resume(self, request, pk=None):
        """Resume automatic payouts."""
        schedule = self.get_object()

        if schedule.connected_account.user != request.user and not request.user.is_staff:
            return APIResponse.forbidden("Cannot modify another user's payout schedule")

        serializer = PayoutScheduleCreateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        schedule.interval = serializer.validated_data.get('interval', 'daily')
        schedule.save()

        try:
            schedule.apply_to_stripe()
        except Exception as e:
            logger.error(f"Failed to apply payout schedule to Stripe: {e}")

        return APIResponse.success(
            data=PayoutScheduleSerializer(schedule, context=self.get_serializer_context()).data,
            message="Automatic payouts resumed"
        )


class PlatformFeeViewSet(AdminOnlyViewSet):
    """
    ViewSet for platform fees (admin only).

    Actions:
    - calculate: Calculate fee for a transaction
    - refund: Refund platform fee
    """
    queryset = PlatformFee.objects.all()
    serializer_class = PlatformFeeListSerializer
    tenant_field = None

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return PlatformFeeDetailSerializer
        return PlatformFeeListSerializer

    def get_queryset(self):
        queryset = PlatformFee.objects.all()

        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Filter by connected account
        account_id = self.request.query_params.get('connected_account')
        if account_id:
            queryset = queryset.filter(connected_account_id=account_id)

        return queryset.select_related(
            'connected_account', 'connected_account__user',
            'escrow', 'payment_transaction'
        ).order_by('-created_at')

    @action(detail=False, methods=['post'])
    def calculate(self, request):
        """Calculate platform fee for a transaction amount."""
        serializer = PlatformFeeCalculationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        amount = data['transaction_amount']
        fee_type = data['fee_type']
        percentage = data.get('percentage_rate', Decimal('10.00'))
        fixed = data.get('fixed_amount', Decimal('0.00'))

        if fee_type == 'percentage':
            fee = amount * percentage / 100
        elif fee_type == 'fixed':
            fee = fixed
        else:  # combined
            fee = (amount * percentage / 100) + fixed

        seller_receives = amount - fee

        return APIResponse.success(
            data={
                'transaction_amount': str(amount),
                'fee_amount': str(fee.quantize(Decimal('0.01'))),
                'seller_receives': str(seller_receives.quantize(Decimal('0.01'))),
                'fee_breakdown': {
                    'fee_type': fee_type,
                    'percentage_rate': str(percentage),
                    'fixed_amount': str(fixed),
                }
            }
        )

    @action(detail=True, methods=['post'])
    def refund(self, request, pk=None):
        """Refund platform fee (fully or partially)."""
        fee = self.get_object()

        if fee.status != 'collected':
            return APIResponse.error(
                message="Can only refund collected fees",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        serializer = PlatformFeeRefundSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        amount = serializer.validated_data.get('amount')

        try:
            fee.refund_fee(amount=amount)
            return APIResponse.success(
                data=PlatformFeeDetailSerializer(fee, context=self.get_serializer_context()).data,
                message="Fee refunded"
            )
        except Exception as e:
            logger.error(f"Failed to refund fee: {e}")
            return APIResponse.error(
                message=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get platform fee statistics."""
        queryset = self.get_queryset()

        stats = {
            'total_fees': queryset.count(),
            'collected_fees': queryset.filter(status='collected').count(),
            'total_collected': queryset.filter(status='collected').aggregate(
                total=Sum('fee_amount')
            )['total'] or Decimal('0.00'),
            'total_refunded': queryset.aggregate(
                total=Sum('refunded_amount')
            )['total'] or Decimal('0.00'),
            'average_fee_rate': queryset.filter(
                fee_type='percentage'
            ).aggregate(
                avg=Avg('percentage_rate')
            )['avg'] or Decimal('0.00'),
        }

        return APIResponse.success(data=stats)


class StripeWebhookEventViewSet(AdminOnlyViewSet):
    """ViewSet for Stripe webhook events (admin only, read-only)."""
    queryset = StripeWebhookEvent.objects.all()
    serializer_class = StripeWebhookEventSerializer
    tenant_field = None
    http_method_names = ['get']  # Read-only

    def get_queryset(self):
        queryset = StripeWebhookEvent.objects.all()

        # Filter by processed status
        processed = self.request.query_params.get('processed')
        if processed is not None:
            queryset = queryset.filter(processed=processed.lower() == 'true')

        return queryset.order_by('-received_at')


# =============================================================================
# FINANCE ANALYTICS VIEWSET
# =============================================================================

class FinanceAnalyticsViewSet(AdminOnlyViewSet):
    """
    ViewSet for finance analytics (admin only).

    Provides comprehensive analytics for:
    - Payment statistics
    - Subscription metrics
    - Escrow statistics
    - Stripe Connect metrics
    """
    # Dummy queryset for router registration - not used
    queryset = PaymentTransaction.objects.none()
    serializer_class = PaymentTransactionListSerializer
    tenant_field = None

    @action(detail=False, methods=['get'])
    def payment_stats(self, request):
        """Get payment statistics."""
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        queryset = PaymentTransaction.objects.all()

        if start_date:
            queryset = queryset.filter(created_at__date__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__date__lte=end_date)

        total = queryset.count()
        successful = queryset.filter(succeeded=True).count()

        stats = {
            'period_start': start_date,
            'period_end': end_date,
            'total_transactions': total,
            'successful_transactions': successful,
            'failed_transactions': total - successful,
            'total_amount': queryset.filter(succeeded=True).aggregate(
                total=Sum('amount')
            )['total'] or Decimal('0.00'),
            'average_transaction': queryset.filter(succeeded=True).aggregate(
                avg=Avg('amount')
            )['avg'] or Decimal('0.00'),
            'success_rate': (successful / total * 100) if total > 0 else 0,
        }

        return APIResponse.success(data=stats)

    @action(detail=False, methods=['get'])
    def subscription_stats(self, request):
        """Get subscription statistics."""
        subscriptions = UserSubscription.objects.all()

        active = subscriptions.filter(status='active').count()
        total = subscriptions.count()

        # Calculate MRR
        mrr = subscriptions.filter(
            status='active',
            plan__interval='month'
        ).aggregate(
            total=Sum('plan__price')
        )['total'] or Decimal('0.00')

        yearly_mrr = subscriptions.filter(
            status='active',
            plan__interval='year'
        ).aggregate(
            total=Sum('plan__price')
        )['total'] or Decimal('0.00')

        mrr += yearly_mrr / 12

        stats = {
            'total_subscribers': total,
            'active_subscribers': active,
            'churned_this_month': subscriptions.filter(
                status='canceled',
            ).count(),
            'new_this_month': subscriptions.filter(
                status='active',
            ).count(),
            'mrr': mrr,
            'arr': mrr * 12,
            'churn_rate': 0,  # Would need historical data
            'by_plan': dict(
                subscriptions.filter(status='active').values('plan__name').annotate(
                    count=Count('id')
                ).values_list('plan__name', 'count')
            ),
        }

        return APIResponse.success(data=stats)

    @action(detail=False, methods=['get'])
    def escrow_stats(self, request):
        """Get escrow statistics."""
        escrows = EscrowTransaction.objects.all()

        stats = {
            'total_escrows': escrows.count(),
            'active_escrows': escrows.filter(
                status__in=['initialized', 'funded', 'service_delivered']
            ).count(),
            'disputed_escrows': escrows.filter(status='dispute').count(),
            'total_volume': escrows.exclude(
                status__in=['initialized', 'cancelled']
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            'total_released': escrows.filter(status='released').aggregate(
                total=Sum('amount')
            )['total'] or Decimal('0.00'),
            'total_refunded': escrows.filter(status='refunded').aggregate(
                total=Sum('amount')
            )['total'] or Decimal('0.00'),
            'average_escrow_amount': escrows.aggregate(
                avg=Avg('amount')
            )['avg'] or Decimal('0.00'),
            'dispute_rate': 0,  # Calculate based on disputes
            'by_status': dict(
                escrows.values('status').annotate(
                    count=Count('id')
                ).values_list('status', 'count')
            ),
        }

        return APIResponse.success(data=stats)

    @action(detail=False, methods=['get'])
    def connect_stats(self, request):
        """Get Stripe Connect statistics."""
        accounts = ConnectedAccount.objects.all()
        fees = PlatformFee.objects.all()

        stats = {
            'total_connected_accounts': accounts.count(),
            'active_accounts': accounts.filter(account_status='active').count(),
            'pending_accounts': accounts.filter(
                account_status__in=['pending', 'onboarding']
            ).count(),
            'total_platform_fees': fees.filter(status='collected').aggregate(
                total=Sum('fee_amount')
            )['total'] or Decimal('0.00'),
            'total_payouts': EscrowPayout.objects.filter(
                status='completed'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            'average_fee_rate': fees.filter(fee_type='percentage').aggregate(
                avg=Avg('percentage_rate')
            )['avg'] or Decimal('0.00'),
            'by_status': dict(
                accounts.values('account_status').annotate(
                    count=Count('id')
                ).values_list('account_status', 'count')
            ),
            'by_country': dict(
                accounts.values('country').annotate(
                    count=Count('id')
                ).values_list('country', 'count')
            ),
        }

        return APIResponse.success(data=stats)

    @action(detail=False, methods=['get'])
    def revenue_chart(self, request):
        """Get revenue chart data."""
        from django.db.models.functions import TruncMonth

        # Get monthly revenue for the past 12 months
        twelve_months_ago = timezone.now() - timezone.timedelta(days=365)

        monthly_data = PaymentTransaction.objects.filter(
            succeeded=True,
            created_at__gte=twelve_months_ago
        ).annotate(
            month=TruncMonth('created_at')
        ).values('month').annotate(
            revenue=Sum('amount'),
            transactions=Count('id')
        ).order_by('month')

        labels = []
        revenue = []
        transactions = []

        for item in monthly_data:
            labels.append(item['month'].strftime('%b %Y'))
            revenue.append(item['revenue'] or Decimal('0.00'))
            transactions.append(item['transactions'])

        return APIResponse.success(
            data={
                'labels': labels,
                'revenue': [str(r) for r in revenue],
                'transactions': transactions,
                'fees': [str(Decimal('0.00'))] * len(labels),  # Would need fee tracking
            }
        )
