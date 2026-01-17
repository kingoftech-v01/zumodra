"""
Finance API Serializers - Payment, Subscription, and Stripe Connect REST API Serializers

This module provides DRF serializers for:
- Payment transactions and history
- Subscription plans and user subscriptions
- Invoices and payment methods
- Refund requests
- Escrow transactions and disputes
- Stripe Connect marketplace (connected accounts, payouts, platform fees)
"""

from decimal import Decimal
from rest_framework import serializers
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from django.utils import timezone
from django.db import transaction

from .models import (
    PaymentTransaction, SubscriptionPlan, UserSubscription,
    Invoice, RefundRequest, PaymentMethod, StripeWebhookEvent,
    EscrowTransaction, Dispute, EscrowPayout, EscrowAudit,
    ConnectedAccount, PayoutSchedule, PlatformFee, StripeConnectOnboarding
)
from custom_account_u.models import CustomUser
from core.serializers import SensitiveFieldMixin, AuditedSerializerMixin


# ==================== USER SERIALIZERS ====================

class FinanceUserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user information for nested representations"""
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name']
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_full_name(self, obj):
        return obj.get_full_name()


# ==================== PAYMENT TRANSACTION SERIALIZERS ====================

class PaymentTransactionListSerializer(serializers.ModelSerializer):
    """
    Compact serializer for listing payment transactions.
    Optimized for list views with minimal nested data.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    status_display = serializers.SerializerMethodField()

    class Meta:
        model = PaymentTransaction
        fields = [
            'id', 'user_email', 'user_full_name',
            'amount', 'currency', 'description',
            'succeeded', 'status_display',
            'created_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_status_display(self, obj):
        if obj.succeeded:
            return 'Succeeded'
        elif obj.failure_code:
            return 'Failed'
        return 'Processing'


class PaymentTransactionDetailSerializer(SensitiveFieldMixin, serializers.ModelSerializer):
    """
    Full payment transaction detail serializer.
    Includes Stripe payment intent ID (sensitive).
    """
    user = FinanceUserMinimalSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()
    has_refund_request = serializers.SerializerMethodField()
    refund_status = serializers.SerializerMethodField()

    sensitive_fields = ['stripe_payment_intent_id']
    sensitive_roles = {'owner', 'admin'}

    class Meta:
        model = PaymentTransaction
        fields = [
            'id', 'user', 'amount', 'currency',
            'stripe_payment_intent_id', 'description',
            'succeeded', 'status_display',
            'failure_code', 'failure_message',
            'has_refund_request', 'refund_status',
            'created_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_status_display(self, obj):
        if obj.succeeded:
            return 'Succeeded'
        elif obj.failure_code:
            return 'Failed'
        return 'Processing'

    @extend_schema_field(OpenApiTypes.STR)
    def get_has_refund_request(self, obj):
        return hasattr(obj, 'refund_request')

    @extend_schema_field(OpenApiTypes.STR)
    def get_refund_status(self, obj):
        if hasattr(obj, 'refund_request'):
            refund = obj.refund_request
            if refund.approved:
                return 'Refunded'
            elif refund.processed_at:
                return 'Rejected'
            return 'Pending'
        return None


class PaymentTransactionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating payment transactions"""
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='user',
        write_only=True
    )

    class Meta:
        model = PaymentTransaction
        fields = [
            'user_id', 'amount', 'currency', 'description',
            'stripe_payment_intent_id'
        ]

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero.")
        return value


# ==================== SUBSCRIPTION SERIALIZERS ====================

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """Serializer for subscription plans (read-only for public display)"""
    price_display = serializers.SerializerMethodField()
    features = serializers.SerializerMethodField()

    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'price', 'currency', 'interval',
            'description', 'price_display', 'features',
            'stripe_product_id', 'stripe_price_id'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_price_display(self, obj):
        interval_label = 'month' if obj.interval == 'month' else 'year'
        return f"${obj.price}/{interval_label}"

    @extend_schema_field(OpenApiTypes.STR)
    def get_features(self, obj):
        # Parse features from description or return empty list
        if obj.description:
            return [f.strip() for f in obj.description.split('\n') if f.strip()]
        return []


class SubscriptionPlanAdminSerializer(serializers.ModelSerializer):
    """Full serializer for subscription plans (admin access)"""

    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'stripe_product_id', 'stripe_price_id',
            'price', 'currency', 'interval', 'description'
        ]


class UserSubscriptionSerializer(serializers.ModelSerializer):
    """Serializer for user subscription status"""
    user = FinanceUserMinimalSerializer(read_only=True)
    plan = SubscriptionPlanSerializer(read_only=True)
    is_active = serializers.SerializerMethodField()
    days_remaining = serializers.SerializerMethodField()
    can_cancel = serializers.SerializerMethodField()
    can_upgrade = serializers.SerializerMethodField()

    class Meta:
        model = UserSubscription
        fields = [
            'id', 'user', 'plan', 'stripe_subscription_id',
            'status', 'is_active', 'days_remaining',
            'current_period_start', 'current_period_end',
            'can_cancel', 'can_upgrade'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_active(self, obj):
        return obj.status == 'active'

    @extend_schema_field(OpenApiTypes.STR)
    def get_days_remaining(self, obj):
        if obj.current_period_end:
            delta = obj.current_period_end - timezone.now()
            return max(0, delta.days)
        return 0

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_cancel(self, obj):
        return obj.status in ['active', 'trialing']

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_upgrade(self, obj):
        return obj.status in ['active', 'trialing']


class UserSubscriptionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating user subscriptions"""
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='user',
        write_only=True
    )
    plan_id = serializers.PrimaryKeyRelatedField(
        queryset=SubscriptionPlan.objects.all(),
        source='plan',
        write_only=True
    )

    class Meta:
        model = UserSubscription
        fields = [
            'user_id', 'plan_id', 'stripe_subscription_id',
            'status', 'current_period_start', 'current_period_end'
        ]


class SubscriptionCancelSerializer(serializers.Serializer):
    """Serializer for canceling a subscription"""
    reason = serializers.CharField(required=False, allow_blank=True)
    cancel_at_period_end = serializers.BooleanField(default=True)


class SubscriptionUpgradeSerializer(serializers.Serializer):
    """Serializer for upgrading a subscription"""
    new_plan_id = serializers.PrimaryKeyRelatedField(
        queryset=SubscriptionPlan.objects.all()
    )
    prorate = serializers.BooleanField(default=True)


# ==================== INVOICE SERIALIZERS ====================

class InvoiceListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing invoices"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    status_display = serializers.SerializerMethodField()
    is_overdue = serializers.SerializerMethodField()

    class Meta:
        model = Invoice
        fields = [
            'id', 'invoice_number', 'user_email',
            'amount_due', 'amount_paid', 'currency',
            'paid', 'status_display', 'is_overdue',
            'due_date', 'created_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_status_display(self, obj):
        if obj.paid:
            return 'Paid'
        elif obj.due_date and obj.due_date < timezone.now():
            return 'Overdue'
        return 'Pending'

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_overdue(self, obj):
        if obj.paid:
            return False
        if obj.due_date:
            return timezone.now() > obj.due_date
        return False


class InvoiceDetailSerializer(SensitiveFieldMixin, serializers.ModelSerializer):
    """Full invoice detail serializer"""
    user = FinanceUserMinimalSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()
    is_overdue = serializers.SerializerMethodField()
    balance_due = serializers.SerializerMethodField()
    can_pay = serializers.SerializerMethodField()

    sensitive_fields = ['stripe_invoice_id']
    sensitive_roles = {'owner', 'admin'}

    class Meta:
        model = Invoice
        fields = [
            'id', 'user', 'invoice_number', 'stripe_invoice_id',
            'amount_due', 'amount_paid', 'balance_due', 'currency',
            'due_date', 'paid', 'paid_at',
            'status_display', 'is_overdue', 'can_pay',
            'created_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_status_display(self, obj):
        if obj.paid:
            return 'Paid'
        elif obj.due_date and obj.due_date < timezone.now():
            return 'Overdue'
        return 'Pending'

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_overdue(self, obj):
        if obj.paid:
            return False
        if obj.due_date:
            return timezone.now() > obj.due_date
        return False

    @extend_schema_field(OpenApiTypes.STR)
    def get_balance_due(self, obj):
        return obj.amount_due - obj.amount_paid

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_pay(self, obj):
        return not obj.paid and (obj.amount_due - obj.amount_paid) > 0


class InvoiceCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating invoices"""
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='user',
        write_only=True
    )

    class Meta:
        model = Invoice
        fields = [
            'user_id', 'invoice_number', 'amount_due',
            'currency', 'due_date'
        ]

    def validate_amount_due(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero.")
        return value


class InvoicePaySerializer(serializers.Serializer):
    """Serializer for paying an invoice"""
    payment_method_id = serializers.CharField(required=True)
    amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, allow_null=True
    )


# ==================== PAYMENT METHOD SERIALIZERS ====================

class PaymentMethodSerializer(SensitiveFieldMixin, serializers.ModelSerializer):
    """Serializer for payment methods"""
    card_display = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()

    sensitive_fields = ['stripe_payment_method_id']
    sensitive_roles = {'owner', 'admin'}

    class Meta:
        model = PaymentMethod
        fields = [
            'id', 'stripe_payment_method_id',
            'card_brand', 'card_last4',
            'card_exp_month', 'card_exp_year',
            'is_default', 'card_display', 'is_expired',
            'added_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_card_display(self, obj):
        return f"{obj.card_brand} ****{obj.card_last4}"

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_expired(self, obj):
        now = timezone.now()
        if obj.card_exp_year < now.year:
            return True
        if obj.card_exp_year == now.year and obj.card_exp_month < now.month:
            return True
        return False


class PaymentMethodCreateSerializer(serializers.ModelSerializer):
    """Serializer for adding new payment methods"""
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='user',
        write_only=True
    )

    class Meta:
        model = PaymentMethod
        fields = [
            'user_id', 'stripe_payment_method_id',
            'card_brand', 'card_last4',
            'card_exp_month', 'card_exp_year',
            'is_default'
        ]

    def validate_card_exp_month(self, value):
        if value < 1 or value > 12:
            raise serializers.ValidationError("Invalid expiration month.")
        return value

    def validate_card_exp_year(self, value):
        current_year = timezone.now().year
        if value < current_year:
            raise serializers.ValidationError("Card is expired.")
        return value

    @transaction.atomic
    def create(self, validated_data):
        """If this is set as default, unset other defaults"""
        if validated_data.get('is_default', False):
            PaymentMethod.objects.filter(
                user=validated_data['user'],
                is_default=True
            ).update(is_default=False)
        return super().create(validated_data)


class SetDefaultPaymentMethodSerializer(serializers.Serializer):
    """Serializer for setting a payment method as default"""
    payment_method_id = serializers.IntegerField()


# ==================== REFUND SERIALIZERS ====================

class RefundRequestSerializer(serializers.ModelSerializer):
    """Serializer for refund requests"""
    payment = PaymentTransactionListSerializer(read_only=True)
    processed_by = FinanceUserMinimalSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()
    can_approve = serializers.SerializerMethodField()

    class Meta:
        model = RefundRequest
        fields = [
            'id', 'payment', 'reason',
            'approved', 'requested_at',
            'processed_at', 'processed_by',
            'status_display', 'can_approve'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_status_display(self, obj):
        if obj.approved:
            return 'Approved'
        elif obj.processed_at:
            return 'Rejected'
        return 'Pending'

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_approve(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return not obj.processed_at and (
            request.user.is_staff or request.user.is_superuser
        )


class RefundRequestCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating refund requests"""
    payment_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = RefundRequest
        fields = ['payment_id', 'reason']

    def validate_payment_id(self, value):
        try:
            payment = PaymentTransaction.objects.get(id=value)
        except PaymentTransaction.DoesNotExist:
            raise serializers.ValidationError("Payment not found.")

        if not payment.succeeded:
            raise serializers.ValidationError("Cannot refund a failed payment.")

        if hasattr(payment, 'refund_request'):
            raise serializers.ValidationError(
                "A refund request already exists for this payment."
            )

        return value

    def create(self, validated_data):
        payment_id = validated_data.pop('payment_id')
        payment = PaymentTransaction.objects.get(id=payment_id)
        validated_data['payment'] = payment
        return super().create(validated_data)


class RefundApproveSerializer(serializers.Serializer):
    """Serializer for approving/rejecting refund requests"""
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    notes = serializers.CharField(required=False, allow_blank=True)


# ==================== ESCROW TRANSACTION SERIALIZERS ====================

class EscrowTransactionListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing escrow transactions"""
    buyer_name = serializers.CharField(source='buyer.get_full_name', read_only=True)
    seller_name = serializers.CharField(source='seller.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_participant = serializers.SerializerMethodField()

    class Meta:
        model = EscrowTransaction
        fields = [
            'id', 'buyer_name', 'seller_name',
            'amount', 'currency', 'status', 'status_display',
            'is_participant', 'created_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_participant(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.buyer == request.user or obj.seller == request.user


class EscrowTransactionDetailSerializer(
    SensitiveFieldMixin,
    AuditedSerializerMixin,
    serializers.ModelSerializer
):
    """Full escrow transaction detail serializer"""
    buyer = FinanceUserMinimalSerializer(read_only=True)
    seller = FinanceUserMinimalSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    disputes = serializers.SerializerMethodField()
    audit_logs = serializers.SerializerMethodField()
    can_fund = serializers.SerializerMethodField()
    can_release = serializers.SerializerMethodField()
    can_dispute = serializers.SerializerMethodField()
    is_buyer = serializers.SerializerMethodField()
    is_seller = serializers.SerializerMethodField()
    payout_info = serializers.SerializerMethodField()

    sensitive_fields = ['payment_intent_id', 'payout_id']
    sensitive_roles = {'owner', 'admin'}
    audit_all_access = True

    class Meta:
        model = EscrowTransaction
        fields = [
            'id', 'buyer', 'seller',
            'amount', 'currency', 'status', 'status_display',
            'payment_intent_id', 'payout_id',
            'agreement_details',
            'created_at', 'funded_at', 'service_delivered_at',
            'released_at', 'refunded_at', 'cancelled_at',
            'dispute_raised_at',
            'disputes', 'audit_logs', 'payout_info',
            'can_fund', 'can_release', 'can_dispute',
            'is_buyer', 'is_seller'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_disputes(self, obj):
        disputes = obj.disputes.all()[:5]
        return DisputeListSerializer(disputes, many=True, context=self.context).data

    @extend_schema_field(OpenApiTypes.STR)
    def get_audit_logs(self, obj):
        logs = obj.audit_logs.all().order_by('-timestamp')[:10]
        return EscrowAuditSerializer(logs, many=True, context=self.context).data

    @extend_schema_field(OpenApiTypes.STR)
    def get_payout_info(self, obj):
        if hasattr(obj, 'payout'):
            return EscrowPayoutSerializer(obj.payout, context=self.context).data
        return None

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_fund(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return (
            obj.status == 'initialized' and
            obj.buyer == request.user
        )

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_release(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return (
            obj.status == 'service_delivered' and
            obj.buyer == request.user
        )

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_dispute(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return (
            obj.status in ['funded', 'service_delivered'] and
            (obj.buyer == request.user or obj.seller == request.user)
        )

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_buyer(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.buyer == request.user

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_seller(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.seller == request.user


class EscrowTransactionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating escrow transactions"""
    buyer_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='buyer',
        write_only=True
    )
    seller_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='seller',
        write_only=True
    )

    class Meta:
        model = EscrowTransaction
        fields = [
            'buyer_id', 'seller_id', 'amount', 'currency',
            'agreement_details'
        ]

    def validate(self, data):
        if data['buyer'] == data['seller']:
            raise serializers.ValidationError({
                'seller_id': 'Buyer and seller cannot be the same person.'
            })
        return data

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero.")
        return value


class EscrowActionSerializer(serializers.Serializer):
    """Serializer for escrow actions (fund, release, dispute)"""
    action = serializers.ChoiceField(
        choices=['fund', 'mark_delivered', 'release', 'dispute', 'cancel']
    )
    payment_method_id = serializers.CharField(required=False)
    reason = serializers.CharField(required=False, allow_blank=True)
    notes = serializers.CharField(required=False, allow_blank=True)

    def validate(self, data):
        action = data.get('action')
        if action == 'fund' and not data.get('payment_method_id'):
            raise serializers.ValidationError({
                'payment_method_id': 'Payment method is required to fund escrow.'
            })
        if action == 'dispute' and not data.get('reason'):
            raise serializers.ValidationError({
                'reason': 'Reason is required to raise a dispute.'
            })
        return data


# ==================== DISPUTE SERIALIZERS ====================

class DisputeListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing disputes"""
    raised_by_name = serializers.CharField(
        source='raised_by.get_full_name', read_only=True
    )
    escrow_id = serializers.UUIDField(source='escrow.id', read_only=True)

    class Meta:
        model = Dispute
        fields = [
            'id', 'escrow_id', 'raised_by_name',
            'reason', 'resolved', 'created_at', 'resolved_at'
        ]
        read_only_fields = fields


class DisputeDetailSerializer(serializers.ModelSerializer):
    """Full dispute detail serializer"""
    raised_by = FinanceUserMinimalSerializer(read_only=True)
    escrow = EscrowTransactionListSerializer(read_only=True)
    can_respond = serializers.SerializerMethodField()
    can_resolve = serializers.SerializerMethodField()

    class Meta:
        model = Dispute
        fields = [
            'id', 'escrow', 'raised_by',
            'reason', 'details', 'resolved',
            'resolution_notes', 'created_at', 'resolved_at',
            'can_respond', 'can_resolve'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_respond(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        # The other party can respond
        if obj.raised_by == request.user:
            return False
        escrow = obj.escrow
        return (
            not obj.resolved and
            (escrow.buyer == request.user or escrow.seller == request.user)
        )

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_resolve(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return not obj.resolved and (
            request.user.is_staff or request.user.is_superuser
        )


class DisputeCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating disputes"""
    escrow_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = Dispute
        fields = ['escrow_id', 'reason', 'details']

    def validate_escrow_id(self, value):
        try:
            escrow = EscrowTransaction.objects.get(id=value)
        except EscrowTransaction.DoesNotExist:
            raise serializers.ValidationError("Escrow transaction not found.")

        if escrow.status not in ['funded', 'service_delivered']:
            raise serializers.ValidationError(
                "Cannot raise dispute on an escrow in this status."
            )

        return value

    def create(self, validated_data):
        escrow_id = validated_data.pop('escrow_id')
        escrow = EscrowTransaction.objects.get(id=escrow_id)
        validated_data['escrow'] = escrow
        validated_data['raised_by'] = self.context['request'].user

        # Update escrow status
        escrow.raise_dispute()

        return super().create(validated_data)


class DisputeResponseSerializer(serializers.Serializer):
    """Serializer for responding to a dispute"""
    response = serializers.CharField()
    evidence = serializers.FileField(required=False)


class DisputeResolveSerializer(serializers.Serializer):
    """Serializer for resolving disputes"""
    resolution = serializers.ChoiceField(
        choices=['refund_buyer', 'release_to_seller', 'partial_refund']
    )
    refund_percentage = serializers.IntegerField(
        min_value=0, max_value=100, required=False
    )
    resolution_notes = serializers.CharField()

    def validate(self, data):
        if data['resolution'] == 'partial_refund':
            if 'refund_percentage' not in data:
                raise serializers.ValidationError({
                    'refund_percentage': 'Required for partial refund.'
                })
        return data


# ==================== ESCROW PAYOUT SERIALIZERS ====================

class EscrowPayoutSerializer(SensitiveFieldMixin, serializers.ModelSerializer):
    """Serializer for escrow payouts"""
    escrow_id = serializers.UUIDField(source='escrow.id', read_only=True)

    sensitive_fields = ['payout_id']
    sensitive_roles = {'owner', 'admin'}

    class Meta:
        model = EscrowPayout
        fields = [
            'id', 'escrow_id', 'payout_id',
            'amount', 'currency', 'status',
            'failure_reason', 'paid_at'
        ]
        read_only_fields = fields


# ==================== ESCROW AUDIT SERIALIZERS ====================

class EscrowAuditSerializer(serializers.ModelSerializer):
    """Serializer for escrow audit logs"""
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    escrow_id = serializers.UUIDField(source='escrow.id', read_only=True)

    class Meta:
        model = EscrowAudit
        fields = [
            'id', 'escrow_id', 'user_name',
            'action', 'notes', 'timestamp'
        ]
        read_only_fields = fields


# ==================== STRIPE CONNECT - CONNECTED ACCOUNT SERIALIZERS ====================

class ConnectedAccountListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing connected accounts"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_account_status_display', read_only=True)
    is_ready = serializers.SerializerMethodField()

    class Meta:
        model = ConnectedAccount
        fields = [
            'id', 'account_id', 'user_email', 'user_name',
            'account_status', 'status_display',
            'charges_enabled', 'payouts_enabled',
            'is_ready', 'created_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_ready(self, obj):
        return obj.charges_enabled and obj.payouts_enabled


class ConnectedAccountDetailSerializer(
    SensitiveFieldMixin,
    AuditedSerializerMixin,
    serializers.ModelSerializer
):
    """Full connected account detail serializer"""
    user = FinanceUserMinimalSerializer(read_only=True)
    status_display = serializers.CharField(source='get_account_status_display', read_only=True)
    business_type_display = serializers.CharField(
        source='get_business_type_display', read_only=True
    )
    is_ready = serializers.SerializerMethodField()
    payout_schedule = serializers.SerializerMethodField()
    onboarding_status = serializers.SerializerMethodField()
    can_create_onboarding_link = serializers.SerializerMethodField()
    total_platform_fees = serializers.SerializerMethodField()

    sensitive_fields = ['account_id']
    sensitive_roles = {'owner', 'admin'}
    audit_all_access = True

    class Meta:
        model = ConnectedAccount
        fields = [
            'id', 'user', 'account_id',
            'account_status', 'status_display',
            'charges_enabled', 'payouts_enabled', 'details_submitted',
            'capabilities', 'country', 'default_currency',
            'business_type', 'business_type_display',
            'is_ready', 'payout_schedule', 'onboarding_status',
            'can_create_onboarding_link', 'total_platform_fees',
            'created_at', 'updated_at', 'activated_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_ready(self, obj):
        return obj.charges_enabled and obj.payouts_enabled

    @extend_schema_field(OpenApiTypes.STR)
    def get_payout_schedule(self, obj):
        if hasattr(obj, 'payout_schedule'):
            return PayoutScheduleSerializer(
                obj.payout_schedule, context=self.context
            ).data
        return None

    @extend_schema_field(OpenApiTypes.STR)
    def get_onboarding_status(self, obj):
        if hasattr(obj, 'onboarding'):
            return StripeConnectOnboardingSerializer(
                obj.onboarding, context=self.context
            ).data
        return None

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_create_onboarding_link(self, obj):
        return (
            obj.account_id and
            obj.account_status in ['pending', 'onboarding', 'restricted']
        )

    @extend_schema_field(OpenApiTypes.STR)
    def get_total_platform_fees(self, obj):
        from django.db.models import Sum
        total = obj.platform_fees.filter(status='collected').aggregate(
            total=Sum('fee_amount')
        )['total']
        return total or Decimal('0.00')


class ConnectedAccountCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating connected accounts"""
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='user',
        write_only=True
    )

    class Meta:
        model = ConnectedAccount
        fields = [
            'user_id', 'country', 'default_currency', 'business_type'
        ]

    def validate_user_id(self, value):
        if ConnectedAccount.objects.filter(user=value).exists():
            raise serializers.ValidationError(
                "This user already has a connected account."
            )
        return value


class ConnectedAccountOnboardingSerializer(serializers.Serializer):
    """Serializer for creating onboarding links"""
    return_url = serializers.URLField()
    refresh_url = serializers.URLField()


class ConnectedAccountRefreshSerializer(serializers.Serializer):
    """Serializer for refreshing account status"""
    pass  # No input required


class ConnectedAccountDashboardLinkSerializer(serializers.Serializer):
    """Response serializer for dashboard link"""
    url = serializers.URLField()
    expires_at = serializers.DateTimeField()


# ==================== STRIPE CONNECT - PAYOUT SCHEDULE SERIALIZERS ====================

class PayoutScheduleSerializer(serializers.ModelSerializer):
    """Serializer for payout schedules"""
    connected_account_id = serializers.UUIDField(
        source='connected_account.id', read_only=True
    )
    interval_display = serializers.CharField(source='get_interval_display', read_only=True)
    weekly_anchor_display = serializers.CharField(
        source='get_weekly_anchor_display', read_only=True, allow_null=True
    )

    class Meta:
        model = PayoutSchedule
        fields = [
            'id', 'connected_account_id',
            'interval', 'interval_display',
            'weekly_anchor', 'weekly_anchor_display',
            'monthly_anchor', 'delay_days',
            'minimum_payout_amount',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class PayoutScheduleCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating payout schedules"""
    connected_account_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = PayoutSchedule
        fields = [
            'connected_account_id', 'interval', 'weekly_anchor',
            'monthly_anchor', 'delay_days', 'minimum_payout_amount'
        ]

    def validate_connected_account_id(self, value):
        try:
            account = ConnectedAccount.objects.get(id=value)
        except ConnectedAccount.DoesNotExist:
            raise serializers.ValidationError("Connected account not found.")
        return value

    def validate_monthly_anchor(self, value):
        if value < 1 or value > 31:
            raise serializers.ValidationError(
                "Monthly anchor must be between 1 and 31."
            )
        return value

    def validate(self, data):
        interval = data.get('interval')
        if interval == 'weekly' and not data.get('weekly_anchor'):
            raise serializers.ValidationError({
                'weekly_anchor': 'Required for weekly payout schedule.'
            })
        return data

    def create(self, validated_data):
        account_id = validated_data.pop('connected_account_id')
        account = ConnectedAccount.objects.get(id=account_id)
        validated_data['connected_account'] = account
        return super().create(validated_data)


class PayoutSchedulePauseSerializer(serializers.Serializer):
    """Serializer for pausing payout schedule"""
    reason = serializers.CharField(required=False, allow_blank=True)


# ==================== STRIPE CONNECT - PLATFORM FEE SERIALIZERS ====================

class PlatformFeeListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing platform fees"""
    connected_account_user = serializers.CharField(
        source='connected_account.user.get_full_name', read_only=True
    )
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = PlatformFee
        fields = [
            'id', 'connected_account_user',
            'transaction_amount', 'fee_amount', 'currency',
            'fee_type', 'status', 'status_display',
            'created_at', 'collected_at'
        ]
        read_only_fields = fields


class PlatformFeeDetailSerializer(SensitiveFieldMixin, serializers.ModelSerializer):
    """Full platform fee detail serializer"""
    connected_account = ConnectedAccountListSerializer(read_only=True)
    escrow = EscrowTransactionListSerializer(read_only=True)
    payment_transaction = PaymentTransactionListSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    fee_type_display = serializers.CharField(source='get_fee_type_display', read_only=True)
    can_refund = serializers.SerializerMethodField()
    net_fee = serializers.SerializerMethodField()

    sensitive_fields = ['stripe_application_fee_id', 'stripe_transfer_id']
    sensitive_roles = {'owner', 'admin'}

    class Meta:
        model = PlatformFee
        fields = [
            'id', 'connected_account', 'escrow', 'payment_transaction',
            'fee_type', 'fee_type_display',
            'percentage_rate', 'fixed_amount',
            'transaction_amount', 'fee_amount', 'currency',
            'stripe_application_fee_id', 'stripe_transfer_id',
            'status', 'status_display',
            'collected_at', 'refunded_at', 'refunded_amount',
            'can_refund', 'net_fee',
            'created_at', 'updated_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_refund(self, obj):
        return (
            obj.status == 'collected' and
            obj.stripe_application_fee_id and
            obj.refunded_amount < obj.fee_amount
        )

    @extend_schema_field(OpenApiTypes.STR)
    def get_net_fee(self, obj):
        return obj.fee_amount - obj.refunded_amount


class PlatformFeeCalculationSerializer(serializers.Serializer):
    """Serializer for calculating platform fees"""
    transaction_amount = serializers.DecimalField(
        max_digits=10, decimal_places=2
    )
    fee_type = serializers.ChoiceField(
        choices=['percentage', 'fixed', 'combined'],
        default='percentage'
    )
    percentage_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False, default=Decimal('10.00')
    )
    fixed_amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, default=Decimal('0.00')
    )


class PlatformFeeCalculationResponseSerializer(serializers.Serializer):
    """Response serializer for fee calculation"""
    transaction_amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    fee_amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    seller_receives = serializers.DecimalField(max_digits=10, decimal_places=2)
    fee_breakdown = serializers.DictField()


class PlatformFeeRefundSerializer(serializers.Serializer):
    """Serializer for refunding platform fees"""
    amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, allow_null=True
    )
    reason = serializers.CharField(required=False, allow_blank=True)


# ==================== STRIPE CONNECT - ONBOARDING SERIALIZERS ====================

class StripeConnectOnboardingSerializer(serializers.ModelSerializer):
    """Serializer for Stripe Connect onboarding status"""
    connected_account_id = serializers.UUIDField(
        source='connected_account.id', read_only=True
    )
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_link_expired = serializers.BooleanField(read_only=True)
    requirements_summary = serializers.SerializerMethodField()

    class Meta:
        model = StripeConnectOnboarding
        fields = [
            'id', 'connected_account_id',
            'status', 'status_display',
            'onboarding_url', 'return_url', 'refresh_url',
            'requirements_current', 'requirements_past_due',
            'requirements_eventually_due', 'requirements_pending_verification',
            'requirements_summary',
            'started_at', 'completed_at', 'link_expires_at',
            'is_link_expired', 'error_message',
            'created_at', 'last_updated_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_requirements_summary(self, obj):
        current = len(obj.requirements_current)
        past_due = len(obj.requirements_past_due)
        eventually = len(obj.requirements_eventually_due)
        pending = len(obj.requirements_pending_verification)

        return {
            'total_requirements': current + past_due + eventually + pending,
            'current': current,
            'past_due': past_due,
            'eventually_due': eventually,
            'pending_verification': pending,
            'needs_action': past_due > 0 or current > 0
        }


class StripeConnectOnboardingCreateSerializer(serializers.Serializer):
    """Serializer for initiating onboarding"""
    return_url = serializers.URLField()
    refresh_url = serializers.URLField()


# ==================== STRIPE CONNECT - TRANSFER SERIALIZERS ====================

class TransferListSerializer(serializers.Serializer):
    """Serializer for listing Stripe transfers (read from Stripe API)"""
    id = serializers.CharField()
    amount = serializers.IntegerField()
    amount_display = serializers.SerializerMethodField()
    currency = serializers.CharField()
    destination = serializers.CharField()
    description = serializers.CharField(allow_null=True)
    created = serializers.DateTimeField()
    reversed = serializers.BooleanField()

    @extend_schema_field(OpenApiTypes.STR)
    def get_amount_display(self, obj):
        amount = obj.get('amount', 0) / 100
        currency = obj.get('currency', 'usd').upper()
        return f"${amount:.2f} {currency}"


class TransferCreateSerializer(serializers.Serializer):
    """Serializer for creating transfers to connected accounts"""
    connected_account_id = serializers.UUIDField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    currency = serializers.CharField(default='usd', max_length=3)
    description = serializers.CharField(required=False, allow_blank=True)

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero.")
        return value


class TransferReverseSerializer(serializers.Serializer):
    """Serializer for reversing transfers"""
    amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, allow_null=True
    )
    description = serializers.CharField(required=False, allow_blank=True)


# ==================== STRIPE CONNECT - BALANCE SERIALIZERS ====================

class BalanceSerializer(serializers.Serializer):
    """Serializer for Stripe balance information"""
    available = serializers.ListField(child=serializers.DictField())
    pending = serializers.ListField(child=serializers.DictField())
    total_available = serializers.SerializerMethodField()
    total_pending = serializers.SerializerMethodField()

    @extend_schema_field(OpenApiTypes.STR)
    def get_total_available(self, obj):
        return sum(b.get('amount', 0) for b in obj.get('available', [])) / 100

    @extend_schema_field(OpenApiTypes.STR)
    def get_total_pending(self, obj):
        return sum(b.get('amount', 0) for b in obj.get('pending', [])) / 100


class BalanceTransactionSerializer(serializers.Serializer):
    """Serializer for balance transactions"""
    id = serializers.CharField()
    amount = serializers.IntegerField()
    amount_display = serializers.SerializerMethodField()
    currency = serializers.CharField()
    type = serializers.CharField()
    description = serializers.CharField(allow_null=True)
    net = serializers.IntegerField()
    fee = serializers.IntegerField()
    created = serializers.DateTimeField()
    available_on = serializers.DateTimeField()
    status = serializers.CharField()

    @extend_schema_field(OpenApiTypes.STR)
    def get_amount_display(self, obj):
        amount = obj.get('amount', 0) / 100
        return f"${amount:.2f}"


# ==================== WEBHOOK SERIALIZERS ====================

class StripeWebhookEventSerializer(serializers.ModelSerializer):
    """Serializer for Stripe webhook events (admin view)"""
    age_minutes = serializers.SerializerMethodField()

    class Meta:
        model = StripeWebhookEvent
        fields = [
            'id', 'event_id', 'json_payload',
            'processed', 'processed_at', 'error_message',
            'received_at', 'age_minutes'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_age_minutes(self, obj):
        delta = timezone.now() - obj.received_at
        return int(delta.total_seconds() / 60)


# ==================== ANALYTICS SERIALIZERS ====================

class PaymentStatsSerializer(serializers.Serializer):
    """Serializer for payment statistics"""
    period_start = serializers.DateField()
    period_end = serializers.DateField()
    total_transactions = serializers.IntegerField()
    successful_transactions = serializers.IntegerField()
    failed_transactions = serializers.IntegerField()
    total_amount = serializers.DecimalField(max_digits=14, decimal_places=2)
    average_transaction = serializers.DecimalField(max_digits=10, decimal_places=2)
    success_rate = serializers.FloatField()


class RevenueChartDataSerializer(serializers.Serializer):
    """Serializer for revenue chart data"""
    labels = serializers.ListField(child=serializers.CharField())
    revenue = serializers.ListField(child=serializers.DecimalField(max_digits=14, decimal_places=2))
    transactions = serializers.ListField(child=serializers.IntegerField())
    fees = serializers.ListField(child=serializers.DecimalField(max_digits=14, decimal_places=2))


class SubscriptionStatsSerializer(serializers.Serializer):
    """Serializer for subscription statistics"""
    total_subscribers = serializers.IntegerField()
    active_subscribers = serializers.IntegerField()
    churned_this_month = serializers.IntegerField()
    new_this_month = serializers.IntegerField()
    mrr = serializers.DecimalField(max_digits=14, decimal_places=2)
    arr = serializers.DecimalField(max_digits=14, decimal_places=2)
    churn_rate = serializers.FloatField()
    by_plan = serializers.DictField()


class EscrowStatsSerializer(serializers.Serializer):
    """Serializer for escrow statistics"""
    total_escrows = serializers.IntegerField()
    active_escrows = serializers.IntegerField()
    disputed_escrows = serializers.IntegerField()
    total_volume = serializers.DecimalField(max_digits=14, decimal_places=2)
    total_released = serializers.DecimalField(max_digits=14, decimal_places=2)
    total_refunded = serializers.DecimalField(max_digits=14, decimal_places=2)
    average_escrow_amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    dispute_rate = serializers.FloatField()
    by_status = serializers.DictField()


class ConnectStatsSerializer(serializers.Serializer):
    """Serializer for Stripe Connect statistics"""
    total_connected_accounts = serializers.IntegerField()
    active_accounts = serializers.IntegerField()
    pending_accounts = serializers.IntegerField()
    total_platform_fees = serializers.DecimalField(max_digits=14, decimal_places=2)
    total_payouts = serializers.DecimalField(max_digits=14, decimal_places=2)
    average_fee_rate = serializers.FloatField()
    by_status = serializers.DictField()
    by_country = serializers.DictField()
