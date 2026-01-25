"""
Subscriptions API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import timedelta

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    SubscriptionProduct,
    SubscriptionTier,
    CustomerSubscription,
    SubscriptionInvoice,
    UsageRecord,
)
from .serializers import (
    SubscriptionProductListSerializer,
    SubscriptionProductDetailSerializer,
    SubscriptionProductCreateSerializer,
    SubscriptionTierSerializer,
    CustomerSubscriptionListSerializer,
    CustomerSubscriptionDetailSerializer,
    CustomerSubscriptionCreateSerializer,
    SubscriptionInvoiceListSerializer,
    SubscriptionInvoiceDetailSerializer,
    UsageRecordListSerializer,
    UsageRecordDetailSerializer,
    UsageRecordCreateSerializer,
)


class SubscriptionProductViewSet(SecureTenantViewSet):
    """
    ViewSet for subscription products.
    Tenants manage their own subscription product offerings.
    """
    queryset = SubscriptionProduct.objects.prefetch_related('tiers').order_by('sort_order', 'name')
    filterset_fields = ['product_type', 'is_active', 'is_public']
    search_fields = ['name', 'description']
    ordering = ['sort_order', 'name']

    def get_serializer_class(self):
        if self.action == 'list':
            return SubscriptionProductListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return SubscriptionProductCreateSerializer
        return SubscriptionProductDetailSerializer

    @action(detail=False, methods=['get'])
    def public(self, request):
        """Get public products (shown on pricing page)"""
        queryset = self.filter_queryset(self.get_queryset()).filter(
            is_active=True,
            is_public=True
        )
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = SubscriptionProductListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = SubscriptionProductListSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def subscribers(self, request, pk=None):
        """Get all subscribers for a product"""
        product = self.get_object()
        subscriptions = CustomerSubscription.objects.filter(
            product=product
        ).select_related('customer').order_by('-created_at')

        page = self.paginate_queryset(subscriptions)
        if page is not None:
            serializer = CustomerSubscriptionListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = CustomerSubscriptionListSerializer(subscriptions, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def revenue(self, request, pk=None):
        """Get revenue analytics for a product"""
        product = self.get_object()
        active_subs = product.customer_subscriptions.filter(status__in=['active', 'trialing'])

        monthly_revenue = active_subs.filter(billing_cycle='monthly').aggregate(
            total=Sum('total_price')
        )['total'] or 0

        yearly_revenue = active_subs.filter(billing_cycle='yearly').aggregate(
            total=Sum('total_price')
        )['total'] or 0

        mrr = monthly_revenue + (yearly_revenue / 12)

        return Response({
            'monthly_revenue': float(monthly_revenue),
            'yearly_revenue': float(yearly_revenue),
            'mrr': float(mrr),
            'arr': float(mrr * 12),
            'active_subscribers': active_subs.count(),
        })


class SubscriptionTierViewSet(SecureTenantViewSet):
    """
    ViewSet for subscription tiers.
    """
    queryset = SubscriptionTier.objects.select_related('product').order_by('product', 'min_quantity')
    serializer_class = SubscriptionTierSerializer
    filterset_fields = ['product']
    ordering = ['product', 'min_quantity']


class CustomerSubscriptionViewSet(SecureTenantViewSet):
    """
    ViewSet for customer subscriptions.
    Manage subscriptions to tenant's products.
    """
    queryset = CustomerSubscription.objects.select_related(
        'customer', 'product', 'tier'
    ).order_by('-created_at')
    filterset_fields = ['status', 'billing_cycle', 'product', 'customer']
    search_fields = ['customer__email', 'customer__first_name', 'customer__last_name']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return CustomerSubscriptionListSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return CustomerSubscriptionCreateSerializer
        return CustomerSubscriptionDetailSerializer

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel subscription (at end of period or immediately)"""
        subscription = self.get_object()

        if subscription.status in ['canceled', 'unpaid']:
            return Response(
                {'detail': 'Subscription is already canceled or unpaid'},
                status=status.HTTP_400_BAD_REQUEST
            )

        cancel_immediately = request.data.get('cancel_immediately', False)
        cancellation_reason = request.data.get('reason', '')

        subscription.cancellation_reason = cancellation_reason
        subscription.canceled_at = timezone.now()

        if cancel_immediately:
            subscription.status = 'canceled'
            subscription.ended_at = timezone.now()
        else:
            subscription.cancel_at_period_end = True

        subscription.save(update_fields=[
            'cancellation_reason', 'canceled_at', 'cancel_at_period_end',
            'status', 'ended_at', 'updated_at'
        ])

        serializer = self.get_serializer(subscription)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def reactivate(self, request, pk=None):
        """Reactivate a canceled subscription"""
        subscription = self.get_object()

        if subscription.status != 'canceled':
            return Response(
                {'detail': 'Only canceled subscriptions can be reactivated'},
                status=status.HTTP_400_BAD_REQUEST
            )

        subscription.status = 'active'
        subscription.cancel_at_period_end = False
        subscription.canceled_at = None
        subscription.cancellation_reason = ''
        subscription.ended_at = None
        subscription.save(update_fields=[
            'status', 'cancel_at_period_end', 'canceled_at',
            'cancellation_reason', 'ended_at', 'updated_at'
        ])

        serializer = self.get_serializer(subscription)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def upgrade(self, request, pk=None):
        """Upgrade subscription to a different product or tier"""
        subscription = self.get_object()

        if subscription.status not in ['active', 'trialing']:
            return Response(
                {'detail': 'Can only upgrade active or trialing subscriptions'},
                status=status.HTTP_400_BAD_REQUEST
            )

        new_product_id = request.data.get('product_id')
        new_tier_id = request.data.get('tier_id')

        if new_product_id:
            try:
                new_product = SubscriptionProduct.objects.get(pk=new_product_id)
                subscription.product = new_product
            except SubscriptionProduct.DoesNotExist:
                return Response(
                    {'detail': 'Product not found'},
                    status=status.HTTP_404_NOT_FOUND
                )

        if new_tier_id:
            try:
                new_tier = SubscriptionTier.objects.get(pk=new_tier_id)
                subscription.tier = new_tier
                subscription.price_per_unit = (
                    new_tier.price_per_unit_monthly if subscription.billing_cycle == 'monthly'
                    else new_tier.price_per_unit_yearly
                )
            except SubscriptionTier.DoesNotExist:
                return Response(
                    {'detail': 'Tier not found'},
                    status=status.HTTP_404_NOT_FOUND
                )

        subscription.save()

        serializer = self.get_serializer(subscription)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def downgrade(self, request, pk=None):
        """Downgrade subscription (same as upgrade, scheduled for next period)"""
        return self.upgrade(request, pk)

    @action(detail=True, methods=['post'])
    def update_quantity(self, request, pk=None):
        """Update subscription quantity (for per-seat products)"""
        subscription = self.get_object()

        if subscription.status not in ['active', 'trialing']:
            return Response(
                {'detail': 'Can only update quantity for active or trialing subscriptions'},
                status=status.HTTP_400_BAD_REQUEST
            )

        new_quantity = request.data.get('quantity')
        if not new_quantity or new_quantity < 1:
            return Response(
                {'detail': 'Quantity must be at least 1'},
                status=status.HTTP_400_BAD_REQUEST
            )

        subscription.quantity = new_quantity
        subscription.save(update_fields=['quantity', 'updated_at'])

        serializer = self.get_serializer(subscription)
        return Response(serializer.data)


class SubscriptionInvoiceViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for subscription invoices.
    Invoices are automatically generated by the system.
    """
    queryset = SubscriptionInvoice.objects.select_related(
        'customer', 'subscription__product'
    ).order_by('-invoice_date')
    filterset_fields = ['status', 'subscription', 'customer']
    search_fields = ['invoice_number', 'customer__email']
    ordering = ['-invoice_date']

    def get_serializer_class(self):
        if self.action == 'list':
            return SubscriptionInvoiceListSerializer
        return SubscriptionInvoiceDetailSerializer

    @action(detail=True, methods=['get'])
    def download_pdf(self, request, pk=None):
        """Get invoice PDF download URL"""
        invoice = self.get_object()

        if invoice.pdf_url:
            return Response({'pdf_url': invoice.pdf_url})
        else:
            return Response(
                {'detail': 'PDF not yet generated'},
                status=status.HTTP_404_NOT_FOUND
            )


class UsageRecordViewSet(SecureTenantViewSet):
    """
    ViewSet for usage records (metered billing).
    """
    queryset = UsageRecord.objects.select_related(
        'subscription__customer', 'subscription__product'
    ).order_by('-usage_date')
    filterset_fields = ['subscription', 'usage_type']
    search_fields = ['subscription__customer__email']
    ordering = ['-usage_date']

    def get_serializer_class(self):
        if self.action == 'list':
            return UsageRecordListSerializer
        if self.action == 'create':
            return UsageRecordCreateSerializer
        return UsageRecordDetailSerializer

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get usage summary by type and period"""
        subscription_id = request.query_params.get('subscription')
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        queryset = self.filter_queryset(self.get_queryset())

        if subscription_id:
            queryset = queryset.filter(subscription_id=subscription_id)
        if start_date:
            queryset = queryset.filter(usage_date__gte=start_date)
        if end_date:
            queryset = queryset.filter(usage_date__lte=end_date)

        summary = queryset.values('usage_type').annotate(
            total_quantity=Sum('quantity'),
            total_cost=Sum('total_amount'),
            record_count=Count('id')
        ).order_by('usage_type')

        return Response(summary)
