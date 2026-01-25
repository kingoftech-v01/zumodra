"""
Escrow API Serializers
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from ..models import (
    EscrowTransaction,
    MilestonePayment,
    EscrowRelease,
    Dispute,
    EscrowPayout,
    EscrowAudit,
)

User = get_user_model()


# Escrow Transaction Serializers

class EscrowTransactionListSerializer(serializers.ModelSerializer):
    """Lightweight escrow transaction list serializer"""
    client_email = serializers.EmailField(source='client.email', read_only=True)
    provider_email = serializers.EmailField(source='provider.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = EscrowTransaction
        fields = [
            'id',
            'escrow_id',
            'amount',
            'currency',
            'platform_fee_amount',
            'payout_amount',
            'client_email',
            'provider_email',
            'status',
            'status_display',
            'created_at',
        ]
        read_only_fields = fields


class EscrowTransactionDetailSerializer(serializers.ModelSerializer):
    """Detailed escrow transaction serializer"""
    client_email = serializers.EmailField(source='client.email', read_only=True)
    provider_email = serializers.EmailField(source='provider.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_releasable = serializers.BooleanField(read_only=True)
    can_auto_release = serializers.BooleanField(read_only=True)

    class Meta:
        model = EscrowTransaction
        fields = [
            'id',
            'escrow_id',
            'amount',
            'currency',
            'platform_fee_percentage',
            'platform_fee_amount',
            'payout_amount',
            'client',
            'client_email',
            'provider',
            'provider_email',
            'status',
            'status_display',
            'content_type',
            'object_id',
            'description',
            'auto_release_days',
            'work_completed_at',
            'auto_release_at',
            'payment_transaction',
            'funded_at',
            'released_at',
            'refunded_at',
            'metadata',
            'is_releasable',
            'can_auto_release',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'escrow_id',
            'client_email',
            'provider_email',
            'status_display',
            'platform_fee_amount',
            'payout_amount',
            'auto_release_at',
            'funded_at',
            'released_at',
            'refunded_at',
            'is_releasable',
            'can_auto_release',
            'created_at',
            'updated_at',
        ]


class EscrowTransactionCreateSerializer(serializers.ModelSerializer):
    """Create escrow transaction serializer"""

    class Meta:
        model = EscrowTransaction
        fields = [
            'amount',
            'currency',
            'provider',
            'description',
            'auto_release_days',
            'content_type',
            'object_id',
            'metadata',
        ]

    def validate(self, data):
        """Validate escrow creation"""
        if data['amount'] <= 0:
            raise serializers.ValidationError("Amount must be greater than 0")

        # Client is automatically set to request.user
        if data['provider'] == self.context['request'].user:
            raise serializers.ValidationError("Cannot create escrow with yourself as provider")

        return data

    def create(self, validated_data):
        """Create escrow with client set to request user"""
        validated_data['client'] = self.context['request'].user
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)


# Milestone Payment Serializers

class MilestonePaymentListSerializer(serializers.ModelSerializer):
    """Lightweight milestone payment list serializer"""
    escrow_id = serializers.CharField(source='escrow_transaction.escrow_id', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = MilestonePayment
        fields = [
            'id',
            'milestone_number',
            'title',
            'amount',
            'currency',
            'status',
            'status_display',
            'escrow_id',
            'due_date',
            'created_at',
        ]
        read_only_fields = ['id', 'escrow_id', 'created_at']


class MilestonePaymentDetailSerializer(serializers.ModelSerializer):
    """Detailed milestone payment serializer"""
    escrow_transaction_detail = EscrowTransactionDetailSerializer(source='escrow_transaction', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_paid = serializers.BooleanField(read_only=True)

    class Meta:
        model = MilestonePayment
        fields = [
            'id',
            'milestone_number',
            'title',
            'description',
            'amount',
            'currency',
            'status',
            'status_display',
            'escrow_transaction',
            'escrow_transaction_detail',
            'deliverables',
            'delivered_files',
            'due_date',
            'started_at',
            'completed_at',
            'approved_at',
            'paid_at',
            'content_type',
            'object_id',
            'metadata',
            'is_paid',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'status_display',
            'escrow_transaction_detail',
            'started_at',
            'completed_at',
            'approved_at',
            'paid_at',
            'is_paid',
            'created_at',
            'updated_at',
        ]


class MilestonePaymentCreateSerializer(serializers.ModelSerializer):
    """Create milestone payment serializer"""

    class Meta:
        model = MilestonePayment
        fields = [
            'milestone_number',
            'title',
            'description',
            'amount',
            'currency',
            'deliverables',
            'due_date',
            'content_type',
            'object_id',
            'metadata',
        ]

    def validate(self, data):
        """Validate milestone creation"""
        if data['amount'] <= 0:
            raise serializers.ValidationError("Amount must be greater than 0")

        return data


# Escrow Release Serializers (Read-Only)

class EscrowReleaseSerializer(serializers.ModelSerializer):
    """Escrow release serializer (read-only)"""
    escrow_id = serializers.CharField(source='escrow_transaction.escrow_id', read_only=True)
    release_type_display = serializers.CharField(source='get_release_type_display', read_only=True)
    approved_by_email = serializers.EmailField(source='approved_by.email', read_only=True, allow_null=True)

    class Meta:
        model = EscrowRelease
        fields = [
            'id',
            'escrow_transaction',
            'escrow_id',
            'release_type',
            'release_type_display',
            'amount',
            'approved_by',
            'approved_by_email',
            'approval_reason',
            'is_automatic',
            'payout_transaction',
            'released_at',
            'metadata',
        ]
        read_only_fields = fields


# Dispute Serializers

class DisputeListSerializer(serializers.ModelSerializer):
    """Lightweight dispute list serializer"""
    escrow_id = serializers.CharField(source='escrow_transaction.escrow_id', read_only=True)
    initiated_by_email = serializers.EmailField(source='initiated_by.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Dispute
        fields = [
            'id',
            'dispute_id',
            'escrow_id',
            'initiated_by_email',
            'reason',
            'status',
            'status_display',
            'opened_at',
        ]
        read_only_fields = ['id', 'dispute_id', 'escrow_id', 'initiated_by_email', 'opened_at']


class DisputeDetailSerializer(serializers.ModelSerializer):
    """Detailed dispute serializer"""
    escrow_transaction_detail = EscrowTransactionDetailSerializer(source='escrow_transaction', read_only=True)
    initiated_by_email = serializers.EmailField(source='initiated_by.email', read_only=True)
    resolved_by_email = serializers.EmailField(source='resolved_by.email', read_only=True, allow_null=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    resolution_display = serializers.CharField(source='get_resolution_display', read_only=True, allow_null=True)

    class Meta:
        model = Dispute
        fields = [
            'id',
            'dispute_id',
            'escrow_transaction',
            'escrow_transaction_detail',
            'initiated_by',
            'initiated_by_email',
            'reason',
            'evidence',
            'status',
            'status_display',
            'resolution',
            'resolution_display',
            'resolution_notes',
            'resolved_by',
            'resolved_by_email',
            'resolved_at',
            'provider_amount',
            'client_refund_amount',
            'opened_at',
            'closed_at',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'dispute_id',
            'escrow_transaction_detail',
            'initiated_by_email',
            'status_display',
            'resolution_display',
            'resolved_by',
            'resolved_by_email',
            'resolved_at',
            'opened_at',
            'closed_at',
            'created_at',
            'updated_at',
        ]


class DisputeCreateSerializer(serializers.ModelSerializer):
    """Create dispute serializer"""

    class Meta:
        model = Dispute
        fields = [
            'escrow_transaction',
            'reason',
            'evidence',
        ]

    def validate(self, data):
        """Validate dispute creation"""
        escrow = data['escrow_transaction']

        # Validate escrow belongs to tenant
        if escrow.tenant != self.context['request'].tenant:
            raise serializers.ValidationError("Escrow transaction not found")

        # Validate escrow is in funded or released status
        if escrow.status not in ['funded', 'released']:
            raise serializers.ValidationError("Can only dispute funded or released escrow transactions")

        # Validate user is client or provider
        user = self.context['request'].user
        if user not in [escrow.client, escrow.provider]:
            raise serializers.ValidationError("Only client or provider can initiate disputes")

        # Check for existing open disputes
        existing_dispute = Dispute.objects.filter(
            escrow_transaction=escrow,
            status__in=['open', 'under_review']
        ).exists()

        if existing_dispute:
            raise serializers.ValidationError("There is already an open dispute for this escrow transaction")

        return data

    def create(self, validated_data):
        """Create dispute with initiated_by set to request user"""
        validated_data['initiated_by'] = self.context['request'].user
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)


# Escrow Payout Serializers (Read-Only)

class EscrowPayoutSerializer(serializers.ModelSerializer):
    """Escrow payout serializer (read-only)"""
    escrow_id = serializers.CharField(source='escrow_transaction.escrow_id', read_only=True)
    provider_email = serializers.EmailField(source='provider.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = EscrowPayout
        fields = [
            'id',
            'payout_id',
            'escrow_transaction',
            'escrow_id',
            'provider',
            'provider_email',
            'gross_amount',
            'platform_fee',
            'net_amount',
            'currency',
            'status',
            'status_display',
            'payment_transaction',
            'stripe_transfer_id',
            'initiated_at',
            'paid_at',
            'failed_at',
            'failure_reason',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = fields


# Escrow Audit Serializers (Read-Only)

class EscrowAuditSerializer(serializers.ModelSerializer):
    """Escrow audit log serializer (read-only, enterprise)"""
    escrow_id = serializers.CharField(source='escrow_transaction.escrow_id', read_only=True)
    actor_email = serializers.EmailField(source='actor.email', read_only=True, allow_null=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = EscrowAudit
        fields = [
            'id',
            'escrow_transaction',
            'escrow_id',
            'action',
            'action_display',
            'description',
            'actor',
            'actor_email',
            'previous_state',
            'new_state',
            'ip_address',
            'user_agent',
            'created_at',
        ]
        read_only_fields = fields
