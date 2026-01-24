"""
Payments API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q, Sum
from django.utils import timezone

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    Currency,
    ExchangeRate,
    PaymentTransaction,
    PaymentMethod,
    RefundRequest,
    PaymentIntent,
)
from .serializers import (
    CurrencySerializer,
    ExchangeRateListSerializer,
    ExchangeRateDetailSerializer,
    PaymentMethodListSerializer,
    PaymentMethodDetailSerializer,
    PaymentMethodCreateSerializer,
    PaymentTransactionListSerializer,
    PaymentTransactionDetailSerializer,
    PaymentTransactionCreateSerializer,
    RefundRequestListSerializer,
    RefundRequestDetailSerializer,
    RefundRequestCreateSerializer,
    PaymentIntentSerializer,
)


class CurrencyViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for currencies.
    Currencies are managed by platform administrators.
    """
    queryset = Currency.objects.filter(is_active=True).order_by('code')
    serializer_class = CurrencySerializer
    filterset_fields = ['code', 'is_active']
    search_fields = ['code', 'name']
    ordering = ['code']


class ExchangeRateViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for exchange rates.
    Exchange rates are updated automatically via Celery tasks.
    """
    queryset = ExchangeRate.objects.select_related(
        'from_currency',
        'to_currency'
    ).order_by('-date', 'from_currency__code')
    filterset_fields = ['from_currency__code', 'to_currency__code', 'date']
    search_fields = ['from_currency__code', 'to_currency__code']
    ordering = ['-date']

    def get_serializer_class(self):
        if self.action == 'list':
            return ExchangeRateListSerializer
        return ExchangeRateDetailSerializer


class PaymentMethodViewSet(SecureTenantViewSet):
    """
    Viewset for payment methods.
    Users can manage their own payment methods.
    """
    queryset = PaymentMethod.objects.select_related('user').order_by('-is_default', '-created_at')
    filterset_fields = ['method_type', 'is_default', 'is_active']
    search_fields = ['billing_name', 'billing_email', 'last_four']
    ordering = ['-is_default', '-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return PaymentMethodListSerializer
        if self.action == 'create':
            return PaymentMethodCreateSerializer
        return PaymentMethodDetailSerializer

    def get_queryset(self):
        """Filter to user's own payment methods"""
        queryset = super().get_queryset()
        return queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Create payment method for current user"""
        serializer.save(
            user=self.request.user,
            tenant=self.request.tenant
        )

    @action(detail=True, methods=['post'])
    def set_default(self, request, pk=None):
        """Set this payment method as default"""
        payment_method = self.get_object()

        # Unset other default methods
        PaymentMethod.objects.filter(
            user=request.user,
            tenant=request.tenant,
            is_default=True
        ).exclude(pk=payment_method.pk).update(is_default=False)

        # Set this as default
        payment_method.is_default = True
        payment_method.save(update_fields=['is_default', 'updated_at'])

        serializer = self.get_serializer(payment_method)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """Verify payment method (placeholder for Stripe verification)"""
        payment_method = self.get_object()

        # TODO: Implement Stripe payment method verification
        # This would typically involve:
        # 1. Calling Stripe API to verify the payment method
        # 2. Updating card details (brand, last_four, expiry)
        # 3. Marking as verified

        serializer = self.get_serializer(payment_method)
        return Response(serializer.data)

    @action(detail=True, methods=['delete'])
    def deactivate(self, request, pk=None):
        """Deactivate payment method (soft delete)"""
        payment_method = self.get_object()

        if payment_method.is_default:
            return Response(
                {'detail': 'Cannot deactivate default payment method. Set another as default first.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        payment_method.is_active = False
        payment_method.save(update_fields=['is_active', 'updated_at'])

        return Response(status=status.HTTP_204_NO_CONTENT)


class PaymentTransactionViewSet(SecureTenantViewSet):
    """
    Viewset for payment transactions.
    Users can view payments where they are payer or payee.
    """
    queryset = PaymentTransaction.objects.select_related(
        'currency',
        'exchange_rate',
        'payer',
        'payee',
        'payment_method',
        'content_type'
    ).prefetch_related('refund_requests').order_by('-created_at')
    filterset_fields = ['status', 'currency__code']
    search_fields = ['transaction_id', 'payer__email', 'payee__email']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return PaymentTransactionListSerializer
        if self.action == 'create':
            return PaymentTransactionCreateSerializer
        return PaymentTransactionDetailSerializer

    def get_queryset(self):
        """Filter to transactions where user is payer or payee"""
        queryset = super().get_queryset()
        return queryset.filter(
            Q(payer=self.request.user) | Q(payee=self.request.user)
        )

    @action(detail=False, methods=['get'])
    def my_payments(self, request):
        """Get payments where current user is payer"""
        queryset = self.filter_queryset(self.get_queryset()).filter(payer=request.user)
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = PaymentTransactionListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PaymentTransactionListSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def my_receipts(self, request):
        """Get payments where current user is payee"""
        queryset = self.filter_queryset(self.get_queryset()).filter(payee=request.user)
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = PaymentTransactionListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PaymentTransactionListSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def refund(self, request, pk=None):
        """Request a refund for this payment"""
        payment = self.get_object()

        # Validate user is payer or payee
        if payment.payer != request.user and payment.payee != request.user:
            return Response(
                {'detail': 'You can only request refunds for your own payments'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate payment status
        if payment.status != 'succeeded':
            return Response(
                {'detail': 'Can only refund successful payments'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create refund request
        refund_serializer = RefundRequestCreateSerializer(
            data={
                'payment_transaction': payment.id,
                'refund_amount': request.data.get('refund_amount', payment.amount),
                'reason': request.data.get('reason', ''),
            },
            context={'request': request}
        )

        if refund_serializer.is_valid():
            refund_request = refund_serializer.save()
            return Response(
                RefundRequestDetailSerializer(refund_request).data,
                status=status.HTTP_201_CREATED
            )

        return Response(refund_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RefundRequestViewSet(SecureTenantViewSet):
    """
    Viewset for refund requests.
    Users can view their own refund requests.
    Admins can approve/reject refund requests.
    """
    queryset = RefundRequest.objects.select_related(
        'payment_transaction',
        'payment_transaction__currency',
        'requested_by',
        'processed_by'
    ).order_by('-created_at')
    filterset_fields = ['status']
    search_fields = ['payment_transaction__transaction_id', 'reason']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return RefundRequestListSerializer
        if self.action == 'create':
            return RefundRequestCreateSerializer
        return RefundRequestDetailSerializer

    def get_queryset(self):
        """Filter based on user permissions"""
        queryset = super().get_queryset()

        # Admins can see all refund requests
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor']:
            return queryset

        # Regular users see only their own refund requests
        return queryset.filter(requested_by=self.request.user)

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve refund request (admin only)"""
        refund_request = self.get_object()

        # Check permissions
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor']):
            return Response(
                {'detail': 'Only administrators can approve refund requests'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if refund_request.status != 'pending':
            return Response(
                {'detail': 'Can only approve pending refund requests'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update status
        refund_request.status = 'approved'
        refund_request.processed_by = request.user
        refund_request.processed_at = timezone.now()
        refund_request.admin_notes = request.data.get('admin_notes', '')
        refund_request.save()

        # TODO: Process actual refund via Stripe
        # This would typically involve:
        # 1. Calling Stripe API to process refund
        # 2. Updating stripe_refund_id
        # 3. Updating payment transaction status

        serializer = self.get_serializer(refund_request)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject refund request (admin only)"""
        refund_request = self.get_object()

        # Check permissions
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor']):
            return Response(
                {'detail': 'Only administrators can reject refund requests'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if refund_request.status != 'pending':
            return Response(
                {'detail': 'Can only reject pending refund requests'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update status
        refund_request.status = 'rejected'
        refund_request.processed_by = request.user
        refund_request.processed_at = timezone.now()
        refund_request.admin_notes = request.data.get('admin_notes', '')
        refund_request.save()

        serializer = self.get_serializer(refund_request)
        return Response(serializer.data)


class PaymentIntentViewSet(SecureTenantViewSet):
    """
    Viewset for payment intents.
    Used for Stripe payment flow.
    """
    queryset = PaymentIntent.objects.select_related(
        'user',
        'currency'
    ).order_by('-created_at')
    serializer_class = PaymentIntentSerializer
    filterset_fields = ['status', 'currency__code']
    search_fields = ['intent_id', 'stripe_payment_intent_id']
    ordering = ['-created_at']

    def get_queryset(self):
        """Filter to user's own payment intents"""
        queryset = super().get_queryset()
        return queryset.filter(user=self.request.user)

    @action(detail=True, methods=['post'])
    def confirm(self, request, pk=None):
        """Confirm payment intent (placeholder for Stripe confirmation)"""
        payment_intent = self.get_object()

        if payment_intent.status != 'requires_confirmation':
            return Response(
                {'detail': 'Payment intent is not in a confirmable state'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # TODO: Implement Stripe payment intent confirmation
        # This would typically involve:
        # 1. Calling Stripe API to confirm the payment intent
        # 2. Updating status based on Stripe response
        # 3. Creating PaymentTransaction if successful

        serializer = self.get_serializer(payment_intent)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel payment intent"""
        payment_intent = self.get_object()

        if payment_intent.status in ['succeeded', 'canceled']:
            return Response(
                {'detail': 'Cannot cancel payment intent in current state'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # TODO: Implement Stripe payment intent cancellation
        # This would typically involve:
        # 1. Calling Stripe API to cancel the payment intent
        # 2. Updating status to 'canceled'

        payment_intent.status = 'canceled'
        payment_intent.save(update_fields=['status', 'updated_at'])

        serializer = self.get_serializer(payment_intent)
        return Response(serializer.data)
