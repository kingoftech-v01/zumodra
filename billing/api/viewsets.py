"""
Billing API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.db.models import Sum, Count
from django.utils import timezone

from ..models import (
    SubscriptionPlan,
    TenantSubscription,
    PlatformInvoice,
    BillingHistory,
)
from .serializers import (
    SubscriptionPlanListSerializer,
    SubscriptionPlanDetailSerializer,
    TenantSubscriptionListSerializer,
    TenantSubscriptionDetailSerializer,
    PlatformInvoiceListSerializer,
    PlatformInvoiceDetailSerializer,
    BillingHistorySerializer,
)


class SubscriptionPlanViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public read-only viewset for subscription plans.
    No authentication required - anyone can view pricing.
    """
    queryset = SubscriptionPlan.objects.filter(is_active=True).order_by(
        'sort_order', 'price_monthly'
    )
    permission_classes = [AllowAny]
    filterset_fields = ['tier', 'is_public']
    search_fields = ['name', 'description']
    ordering = ['sort_order', 'price_monthly']
    lookup_field = 'slug'

    def get_serializer_class(self):
        if self.action == 'list':
            return SubscriptionPlanListSerializer
        return SubscriptionPlanDetailSerializer

    def get_queryset(self):
        queryset = super().get_queryset()

        # For unauthenticated users, only show public plans
        if not self.request.user.is_authenticated:
            queryset = queryset.filter(is_public=True)

        return queryset


class TenantSubscriptionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for tenant subscriptions.
    Users can only view their own tenant's subscription.
    """
    queryset = TenantSubscription.objects.select_related('tenant', 'plan').order_by('-created_at')
    permission_classes = [IsAuthenticated]
    filterset_fields = ['status', 'billing_cycle']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return TenantSubscriptionListSerializer
        return TenantSubscriptionDetailSerializer

    def get_queryset(self):
        """Filter to only show user's tenant subscriptions"""
        queryset = super().get_queryset()

        # Get user's tenant
        try:
            tenant = self.request.user.tenant
            return queryset.filter(tenant=tenant)
        except AttributeError:
            return TenantSubscription.objects.none()

    @action(detail=True, methods=['post'])
    def upgrade(self, request, pk=None):
        """
        Upgrade subscription to a higher tier.
        Would integrate with Stripe API in production.
        """
        subscription = self.get_object()

        # Check permission - only tenant owner can upgrade
        try:
            if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                    request.user.tenant_user.role == 'pdg'):
                return Response(
                    {'detail': 'Only tenant owner can upgrade subscription'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except AttributeError:
            return Response(
                {'detail': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        new_plan_id = request.data.get('plan_id')
        if not new_plan_id:
            return Response(
                {'detail': 'plan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            new_plan = SubscriptionPlan.objects.get(pk=new_plan_id)
        except SubscriptionPlan.DoesNotExist:
            return Response(
                {'detail': 'Plan not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # This would call Stripe API to upgrade subscription
        return Response({
            'detail': 'Subscription upgrade would be processed here',
            'note': 'Requires Stripe API integration',
            'current_plan': subscription.plan.name,
            'new_plan': new_plan.name,
        }, status=status.HTTP_501_NOT_IMPLEMENTED)

    @action(detail=True, methods=['post'])
    def downgrade(self, request, pk=None):
        """
        Downgrade subscription to a lower tier.
        Would integrate with Stripe API in production.
        """
        subscription = self.get_object()

        # Check permission
        try:
            if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                    request.user.tenant_user.role == 'pdg'):
                return Response(
                    {'detail': 'Only tenant owner can downgrade subscription'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except AttributeError:
            return Response(
                {'detail': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        new_plan_id = request.data.get('plan_id')
        if not new_plan_id:
            return Response(
                {'detail': 'plan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # This would call Stripe API
        return Response({
            'detail': 'Subscription downgrade would be processed here',
            'note': 'Requires Stripe API integration'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """
        Cancel subscription.
        Would integrate with Stripe API in production.
        """
        subscription = self.get_object()

        # Check permission
        try:
            if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                    request.user.tenant_user.role == 'pdg'):
                return Response(
                    {'detail': 'Only tenant owner can cancel subscription'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except AttributeError:
            return Response(
                {'detail': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        cancel_immediately = request.data.get('cancel_immediately', False)
        reason = request.data.get('reason', '')

        # This would call Stripe API
        return Response({
            'detail': 'Subscription cancellation would be processed here',
            'note': 'Requires Stripe API integration',
            'cancel_immediately': cancel_immediately,
        }, status=status.HTTP_501_NOT_IMPLEMENTED)

    @action(detail=True, methods=['post'])
    def reactivate(self, request, pk=None):
        """
        Reactivate a canceled subscription.
        """
        subscription = self.get_object()

        # Check permission
        try:
            if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                    request.user.tenant_user.role == 'pdg'):
                return Response(
                    {'detail': 'Only tenant owner can reactivate subscription'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except AttributeError:
            return Response(
                {'detail': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        if subscription.status != 'canceled':
            return Response(
                {'detail': 'Only canceled subscriptions can be reactivated'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # This would call Stripe API
        return Response({
            'detail': 'Subscription reactivation would be processed here',
            'note': 'Requires Stripe API integration'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)


class PlatformInvoiceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only viewset for platform invoices.
    Users can only view their own tenant's invoices.
    """
    queryset = PlatformInvoice.objects.select_related(
        'tenant', 'subscription__plan'
    ).order_by('-invoice_date')
    permission_classes = [IsAuthenticated]
    filterset_fields = ['status']
    search_fields = ['invoice_number']
    ordering = ['-invoice_date']

    def get_serializer_class(self):
        if self.action == 'list':
            return PlatformInvoiceListSerializer
        return PlatformInvoiceDetailSerializer

    def get_queryset(self):
        """Filter to only show user's tenant invoices"""
        queryset = super().get_queryset()

        # Get user's tenant
        try:
            tenant = self.request.user.tenant
            return queryset.filter(tenant=tenant)
        except AttributeError:
            return PlatformInvoice.objects.none()

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

    @action(detail=True, methods=['post'])
    def pay(self, request, pk=None):
        """
        Pay invoice.
        Would integrate with Stripe API in production.
        """
        invoice = self.get_object()

        # Check permission
        try:
            if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                    request.user.tenant_user.role == 'pdg'):
                return Response(
                    {'detail': 'Only tenant owner can pay invoices'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except AttributeError:
            return Response(
                {'detail': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        if invoice.status == 'paid':
            return Response(
                {'detail': 'Invoice already paid'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # This would call Stripe API to process payment
        return Response({
            'detail': 'Invoice payment would be processed here',
            'note': 'Requires Stripe API integration',
            'amount_due': float(invoice.amount_due),
        }, status=status.HTTP_501_NOT_IMPLEMENTED)


class BillingHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only viewset for billing history.
    Users can only view their own tenant's history.
    """
    queryset = BillingHistory.objects.select_related(
        'tenant', 'subscription', 'old_plan', 'new_plan', 'changed_by'
    ).order_by('-created_at')
    serializer_class = BillingHistorySerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['change_type']
    ordering = ['-created_at']

    def get_queryset(self):
        """Filter to only show user's tenant history"""
        queryset = super().get_queryset()

        # Get user's tenant
        try:
            tenant = self.request.user.tenant
            return queryset.filter(tenant=tenant)
        except AttributeError:
            return BillingHistory.objects.none()
