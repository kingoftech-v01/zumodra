"""
Escrow API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q
from django.utils import timezone

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    EscrowTransaction,
    MilestonePayment,
    EscrowRelease,
    Dispute,
    EscrowPayout,
    EscrowAudit,
)
from .serializers import (
    EscrowTransactionListSerializer,
    EscrowTransactionDetailSerializer,
    EscrowTransactionCreateSerializer,
    MilestonePaymentListSerializer,
    MilestonePaymentDetailSerializer,
    MilestonePaymentCreateSerializer,
    EscrowReleaseSerializer,
    DisputeListSerializer,
    DisputeDetailSerializer,
    DisputeCreateSerializer,
    EscrowPayoutSerializer,
    EscrowAuditSerializer,
)


class EscrowTransactionViewSet(SecureTenantViewSet):
    """
    Viewset for escrow transactions.
    Users can view escrow where they are client or provider.
    """
    queryset = EscrowTransaction.objects.select_related(
        'client',
        'provider',
        'payment_transaction',
        'content_type'
    ).prefetch_related(
        'releases',
        'disputes',
        'payouts'
    ).order_by('-created_at')
    filterset_fields = ['status', 'currency']
    search_fields = ['escrow_id', 'description', 'client__email', 'provider__email']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return EscrowTransactionListSerializer
        if self.action == 'create':
            return EscrowTransactionCreateSerializer
        return EscrowTransactionDetailSerializer

    def get_queryset(self):
        """Filter to escrow where user is client or provider"""
        queryset = super().get_queryset()

        # Admins see all
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor']:
            return queryset

        # Regular users see only their own
        return queryset.filter(
            Q(client=self.request.user) | Q(provider=self.request.user)
        )

    @action(detail=True, methods=['post'])
    def fund(self, request, pk=None):
        """Fund the escrow (client only)"""
        escrow = self.get_object()

        # Validate user is client
        if escrow.client != request.user:
            return Response(
                {'detail': 'Only the client can fund the escrow'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if escrow.status != 'pending':
            return Response(
                {'detail': 'Escrow is not in pending status'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # TODO: Process payment via Stripe
        # This would typically involve:
        # 1. Creating a PaymentIntent
        # 2. Processing the payment
        # 3. Linking PaymentTransaction to escrow

        # Update escrow status
        escrow.status = 'funded'
        escrow.funded_at = timezone.now()
        escrow.save(update_fields=['status', 'funded_at', 'updated_at'])

        serializer = self.get_serializer(escrow)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def mark_complete(self, request, pk=None):
        """Mark work as complete (provider only)"""
        escrow = self.get_object()

        # Validate user is provider
        if escrow.provider != request.user:
            return Response(
                {'detail': 'Only the provider can mark work as complete'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if escrow.status != 'funded':
            return Response(
                {'detail': 'Escrow must be funded to mark work complete'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update work completion
        escrow.work_completed_at = timezone.now()
        escrow.save(update_fields=['work_completed_at', 'updated_at'])

        serializer = self.get_serializer(escrow)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def release(self, request, pk=None):
        """Release funds to provider (client only or automatic)"""
        escrow = self.get_object()

        # Validate user is client or admin
        if escrow.client != request.user and not (
            request.user.is_staff or hasattr(request.user, 'tenant_user') and \
            request.user.tenant_user.role in ['pdg', 'supervisor']
        ):
            return Response(
                {'detail': 'Only the client can release funds'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if not escrow.is_releasable:
            return Response(
                {'detail': 'Escrow cannot be released in current status'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create release record
        release = EscrowRelease.objects.create(
            tenant=request.tenant,
            escrow_transaction=escrow,
            release_type='full',
            amount=escrow.amount,
            approved_by=request.user,
            approval_reason=request.data.get('approval_reason', ''),
            is_automatic=False
        )

        # Update escrow status
        escrow.status = 'released'
        escrow.released_at = timezone.now()
        escrow.save(update_fields=['status', 'released_at', 'updated_at'])

        # TODO: Process payout to provider via Stripe Connect
        # This would typically involve:
        # 1. Creating a Transfer to provider's connected account
        # 2. Creating EscrowPayout record
        # 3. Linking PaymentTransaction

        serializer = self.get_serializer(escrow)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def refund(self, request, pk=None):
        """Refund escrow to client (admin only)"""
        escrow = self.get_object()

        # Validate user is admin
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor']):
            return Response(
                {'detail': 'Only administrators can process refunds'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if escrow.status not in ['pending', 'funded']:
            return Response(
                {'detail': 'Can only refund pending or funded escrow'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create release record (refund type)
        release = EscrowRelease.objects.create(
            tenant=request.tenant,
            escrow_transaction=escrow,
            release_type='refund',
            amount=escrow.amount,
            approved_by=request.user,
            approval_reason=request.data.get('approval_reason', ''),
            is_automatic=False
        )

        # Update escrow status
        escrow.status = 'refunded'
        escrow.refunded_at = timezone.now()
        escrow.save(update_fields=['status', 'refunded_at', 'updated_at'])

        # TODO: Process refund via Stripe
        # This would typically involve:
        # 1. Creating a Refund for the original payment
        # 2. Updating PaymentTransaction

        serializer = self.get_serializer(escrow)
        return Response(serializer.data)


class MilestonePaymentViewSet(SecureTenantViewSet):
    """
    Viewset for milestone payments.
    """
    queryset = MilestonePayment.objects.select_related(
        'escrow_transaction',
        'escrow_transaction__client',
        'escrow_transaction__provider',
        'content_type'
    ).order_by('-created_at')
    filterset_fields = ['status']
    search_fields = ['title', 'description']
    ordering = ['milestone_number']

    def get_serializer_class(self):
        if self.action == 'list':
            return MilestonePaymentListSerializer
        if self.action == 'create':
            return MilestonePaymentCreateSerializer
        return MilestonePaymentDetailSerializer

    @action(detail=True, methods=['post'])
    def mark_completed(self, request, pk=None):
        """Mark milestone as completed (provider only)"""
        milestone = self.get_object()

        # Validate status
        if milestone.status != 'in_progress':
            return Response(
                {'detail': 'Milestone must be in progress'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update milestone
        milestone.status = 'completed'
        milestone.completed_at = timezone.now()
        milestone.delivered_files = request.data.get('delivered_files', [])
        milestone.save(update_fields=['status', 'completed_at', 'delivered_files', 'updated_at'])

        # If escrow exists, mark work as complete
        if milestone.escrow_transaction:
            milestone.escrow_transaction.work_completed_at = timezone.now()
            milestone.escrow_transaction.save(update_fields=['work_completed_at', 'updated_at'])

        serializer = self.get_serializer(milestone)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve completed milestone (client only)"""
        milestone = self.get_object()

        # Validate status
        if milestone.status != 'completed':
            return Response(
                {'detail': 'Milestone must be completed before approval'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update milestone
        milestone.status = 'approved'
        milestone.approved_at = timezone.now()
        milestone.save(update_fields=['status', 'approved_at', 'updated_at'])

        serializer = self.get_serializer(milestone)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def pay(self, request, pk=None):
        """Process payment for approved milestone (admin only)"""
        milestone = self.get_object()

        # Validate user is admin
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor']):
            return Response(
                {'detail': 'Only administrators can process payments'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if milestone.status != 'approved':
            return Response(
                {'detail': 'Milestone must be approved before payment'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update milestone
        milestone.status = 'paid'
        milestone.paid_at = timezone.now()
        milestone.save(update_fields=['status', 'paid_at', 'updated_at'])

        # If escrow exists, release funds
        if milestone.escrow_transaction and milestone.escrow_transaction.is_releasable:
            escrow = milestone.escrow_transaction
            escrow.status = 'released'
            escrow.released_at = timezone.now()
            escrow.save(update_fields=['status', 'released_at', 'updated_at'])

        serializer = self.get_serializer(milestone)
        return Response(serializer.data)


class EscrowReleaseViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for escrow releases.
    Releases are created automatically via escrow actions.
    """
    queryset = EscrowRelease.objects.select_related(
        'escrow_transaction',
        'approved_by',
        'payout_transaction'
    ).order_by('-released_at')
    serializer_class = EscrowReleaseSerializer
    filterset_fields = ['release_type', 'is_automatic']
    search_fields = ['escrow_transaction__escrow_id', 'approval_reason']
    ordering = ['-released_at']


class DisputeViewSet(SecureTenantViewSet):
    """
    Viewset for disputes.
    Users can view disputes where they are client or provider.
    Admins can resolve disputes.
    """
    queryset = Dispute.objects.select_related(
        'escrow_transaction',
        'escrow_transaction__client',
        'escrow_transaction__provider',
        'initiated_by',
        'resolved_by'
    ).order_by('-opened_at')
    filterset_fields = ['status']
    search_fields = ['dispute_id', 'reason', 'escrow_transaction__escrow_id']
    ordering = ['-opened_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return DisputeListSerializer
        if self.action == 'create':
            return DisputeCreateSerializer
        return DisputeDetailSerializer

    def get_queryset(self):
        """Filter based on user permissions"""
        queryset = super().get_queryset()

        # Admins see all disputes
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor']:
            return queryset

        # Regular users see disputes where they are client or provider
        return queryset.filter(
            Q(escrow_transaction__client=self.request.user) |
            Q(escrow_transaction__provider=self.request.user)
        )

    @action(detail=True, methods=['post'])
    def add_evidence(self, request, pk=None):
        """Add evidence to dispute"""
        dispute = self.get_object()

        # Validate user is client or provider
        if request.user not in [dispute.escrow_transaction.client, dispute.escrow_transaction.provider]:
            return Response(
                {'detail': 'Only parties involved can add evidence'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if dispute.status not in ['open', 'under_review']:
            return Response(
                {'detail': 'Can only add evidence to open or under review disputes'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Add evidence
        new_evidence = request.data.get('evidence', [])
        dispute.evidence.extend(new_evidence)
        dispute.save(update_fields=['evidence', 'updated_at'])

        serializer = self.get_serializer(dispute)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve dispute (admin only)"""
        dispute = self.get_object()

        # Validate user is admin
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor']):
            return Response(
                {'detail': 'Only administrators can resolve disputes'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if dispute.status not in ['open', 'under_review']:
            return Response(
                {'detail': 'Can only resolve open or under review disputes'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get resolution details
        resolution = request.data.get('resolution')
        resolution_notes = request.data.get('resolution_notes', '')

        if not resolution:
            return Response(
                {'detail': 'Resolution is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update dispute
        dispute.status = 'resolved'
        dispute.resolution = resolution
        dispute.resolution_notes = resolution_notes
        dispute.resolved_by = request.user
        dispute.resolved_at = timezone.now()

        # Handle partial resolution
        if resolution == 'partial_release':
            dispute.provider_amount = request.data.get('provider_amount', 0)
            dispute.client_refund_amount = request.data.get('client_refund_amount', 0)

        dispute.save()

        # Update escrow based on resolution
        escrow = dispute.escrow_transaction
        if resolution == 'release_to_provider':
            # Release full amount to provider
            escrow.status = 'released'
            escrow.released_at = timezone.now()
            escrow.save(update_fields=['status', 'released_at', 'updated_at'])

        elif resolution == 'refund_to_client':
            # Refund full amount to client
            escrow.status = 'refunded'
            escrow.refunded_at = timezone.now()
            escrow.save(update_fields=['status', 'refunded_at', 'updated_at'])

        elif resolution == 'partial_release':
            # TODO: Implement partial release logic
            pass

        serializer = self.get_serializer(dispute)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def escalate(self, request, pk=None):
        """Escalate dispute (admin only)"""
        dispute = self.get_object()

        # Validate user is admin
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor']):
            return Response(
                {'detail': 'Only administrators can escalate disputes'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if dispute.status != 'under_review':
            return Response(
                {'detail': 'Can only escalate disputes under review'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update status
        dispute.status = 'escalated'
        dispute.save(update_fields=['status', 'updated_at'])

        serializer = self.get_serializer(dispute)
        return Response(serializer.data)


class EscrowPayoutViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for escrow payouts.
    Payouts are created automatically when escrow is released.
    """
    queryset = EscrowPayout.objects.select_related(
        'escrow_transaction',
        'provider',
        'payment_transaction'
    ).order_by('-initiated_at')
    serializer_class = EscrowPayoutSerializer
    filterset_fields = ['status']
    search_fields = ['payout_id', 'escrow_transaction__escrow_id', 'provider__email']
    ordering = ['-initiated_at']

    def get_queryset(self):
        """Filter based on user permissions"""
        queryset = super().get_queryset()

        # Admins see all payouts
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor']:
            return queryset

        # Regular users see only their own payouts
        return queryset.filter(provider=self.request.user)


class EscrowAuditViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for escrow audit logs (enterprise only).
    """
    queryset = EscrowAudit.objects.select_related(
        'escrow_transaction',
        'actor'
    ).order_by('-created_at')
    serializer_class = EscrowAuditSerializer
    filterset_fields = ['action']
    search_fields = ['escrow_transaction__escrow_id', 'description']
    ordering = ['-created_at']

    def get_queryset(self):
        """Only admins can view audit logs"""
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            # Return empty queryset for non-admins
            return EscrowAudit.objects.none()

        return super().get_queryset()
