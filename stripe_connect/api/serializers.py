"""
Stripe Connect API Serializers
"""

from rest_framework import serializers
from ..models import (
    ConnectedAccount,
    StripeConnectOnboarding,
    PlatformFee,
    PayoutSchedule,
    Transfer,
    BalanceTransaction,
)


# ============= ConnectedAccount Serializers =============

class ConnectedAccountListSerializer(serializers.ModelSerializer):
    """Lightweight connected account list"""
    provider_email = serializers.EmailField(source='provider.email', read_only=True)
    provider_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    account_type_display = serializers.CharField(source='get_account_type_display', read_only=True)
    is_fully_onboarded = serializers.BooleanField(read_only=True)
    needs_verification = serializers.BooleanField(read_only=True)

    class Meta:
        model = ConnectedAccount
        fields = [
            'id', 'provider', 'provider_email', 'provider_name',
            'stripe_account_id', 'account_type', 'account_type_display',
            'status', 'status_display', 'charges_enabled', 'payouts_enabled',
            'transfers_enabled', 'is_fully_onboarded', 'needs_verification',
            'created_at',
        ]
        read_only_fields = fields

    def get_provider_name(self, obj):
        return obj.provider.get_full_name()


class ConnectedAccountDetailSerializer(serializers.ModelSerializer):
    """Full connected account details"""
    provider_email = serializers.EmailField(source='provider.email', read_only=True)
    provider_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    account_type_display = serializers.CharField(source='get_account_type_display', read_only=True)
    is_fully_onboarded = serializers.BooleanField(read_only=True)
    needs_verification = serializers.BooleanField(read_only=True)

    class Meta:
        model = ConnectedAccount
        fields = [
            'id', 'provider', 'provider_email', 'provider_name',
            'stripe_account_id', 'account_type', 'account_type_display',
            'status', 'status_display', 'charges_enabled', 'payouts_enabled',
            'transfers_enabled', 'requirements', 'requirements_pending',
            'verification_status', 'verification_disabled_reason',
            'business_type', 'country', 'default_currency', 'email',
            'dashboard_link_expires', 'metadata', 'is_fully_onboarded',
            'needs_verification', 'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'stripe_account_id', 'status', 'charges_enabled',
            'payouts_enabled', 'transfers_enabled', 'requirements',
            'requirements_pending', 'verification_status',
            'verification_disabled_reason', 'created_at', 'updated_at',
        ]

    def get_provider_name(self, obj):
        return obj.provider.get_full_name()


# ============= StripeConnectOnboarding Serializers =============

class StripeConnectOnboardingSerializer(serializers.ModelSerializer):
    """Stripe Connect onboarding serializer"""
    account_provider = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_onboarding_url_valid = serializers.BooleanField(read_only=True)

    class Meta:
        model = StripeConnectOnboarding
        fields = [
            'id', 'connected_account', 'account_provider', 'status',
            'status_display', 'onboarding_url', 'onboarding_url_expires',
            'completed_at', 'return_url', 'refresh_url', 'metadata',
            'is_onboarding_url_valid', 'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'onboarding_url', 'onboarding_url_expires',
            'completed_at', 'created_at', 'updated_at',
        ]

    def get_account_provider(self, obj):
        return obj.connected_account.provider.get_full_name()


# ============= PlatformFee Serializers =============

class PlatformFeeSerializer(serializers.ModelSerializer):
    """Platform fee serializer"""
    class Meta:
        model = PlatformFee
        fields = [
            'id', 'name', 'percentage', 'fixed_amount', 'currency',
            'min_fee', 'max_fee', 'applies_to', 'is_active',
            'description', 'metadata', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_percentage(self, value):
        if value < 0 or value > 100:
            raise serializers.ValidationError("Percentage must be between 0 and 100")
        return value


# ============= PayoutSchedule Serializers =============

class PayoutScheduleSerializer(serializers.ModelSerializer):
    """Payout schedule serializer"""
    account_provider = serializers.SerializerMethodField()
    interval_display = serializers.CharField(source='get_interval_display', read_only=True)
    weekly_anchor_display = serializers.CharField(source='get_weekly_anchor_display', read_only=True)

    class Meta:
        model = PayoutSchedule
        fields = [
            'id', 'connected_account', 'account_provider', 'interval',
            'interval_display', 'weekly_anchor', 'weekly_anchor_display',
            'monthly_anchor', 'delay_days', 'minimum_payout', 'currency',
            'is_active', 'metadata', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_account_provider(self, obj):
        return obj.connected_account.provider.get_full_name()

    def validate_monthly_anchor(self, value):
        if value < 1 or value > 31:
            raise serializers.ValidationError("Monthly anchor must be between 1 and 31")
        return value


# ============= Transfer Serializers =============

class TransferListSerializer(serializers.ModelSerializer):
    """Lightweight transfer list"""
    provider_email = serializers.EmailField(
        source='connected_account.provider.email',
        read_only=True
    )
    provider_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Transfer
        fields = [
            'id', 'transfer_id', 'stripe_transfer_id', 'provider_email',
            'provider_name', 'amount', 'currency', 'status', 'status_display',
            'created_at_stripe', 'arrival_date', 'created_at',
        ]
        read_only_fields = fields

    def get_provider_name(self, obj):
        return obj.connected_account.provider.get_full_name()


class TransferDetailSerializer(serializers.ModelSerializer):
    """Full transfer details"""
    connected_account = ConnectedAccountListSerializer(read_only=True)
    provider_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Transfer
        fields = [
            'id', 'transfer_id', 'stripe_transfer_id', 'connected_account',
            'provider_name', 'amount', 'currency', 'status', 'status_display',
            'source_transaction', 'description', 'created_at_stripe',
            'arrival_date', 'failure_code', 'failure_message', 'reversed',
            'reversed_at', 'metadata', 'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'transfer_id', 'stripe_transfer_id', 'status',
            'created_at_stripe', 'arrival_date', 'failure_code',
            'failure_message', 'reversed', 'reversed_at',
            'created_at', 'updated_at',
        ]

    def get_provider_name(self, obj):
        return obj.connected_account.provider.get_full_name()


# ============= BalanceTransaction Serializers =============

class BalanceTransactionListSerializer(serializers.ModelSerializer):
    """Lightweight balance transaction list"""
    provider_email = serializers.EmailField(
        source='connected_account.provider.email',
        read_only=True
    )
    transaction_type_display = serializers.CharField(
        source='get_transaction_type_display',
        read_only=True
    )
    is_credit = serializers.BooleanField(read_only=True)
    is_debit = serializers.BooleanField(read_only=True)

    class Meta:
        model = BalanceTransaction
        fields = [
            'id', 'stripe_balance_transaction_id', 'provider_email',
            'transaction_type', 'transaction_type_display', 'amount',
            'fee', 'net', 'currency', 'is_credit', 'is_debit',
            'created_at_stripe',
        ]
        read_only_fields = fields


class BalanceTransactionDetailSerializer(serializers.ModelSerializer):
    """Full balance transaction details"""
    connected_account = ConnectedAccountListSerializer(read_only=True)
    transaction_type_display = serializers.CharField(
        source='get_transaction_type_display',
        read_only=True
    )
    is_credit = serializers.BooleanField(read_only=True)
    is_debit = serializers.BooleanField(read_only=True)

    class Meta:
        model = BalanceTransaction
        fields = [
            'id', 'stripe_balance_transaction_id', 'connected_account',
            'transaction_type', 'transaction_type_display', 'amount',
            'fee', 'net', 'currency', 'description', 'source_id',
            'transfer', 'available_on', 'created_at_stripe', 'metadata',
            'is_credit', 'is_debit', 'created_at', 'updated_at',
        ]
        read_only_fields = fields
