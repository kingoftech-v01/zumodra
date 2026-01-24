"""
Payments API Serializers
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from ..models import (
    Currency,
    ExchangeRate,
    PaymentTransaction,
    PaymentMethod,
    RefundRequest,
    PaymentIntent,
)

User = get_user_model()


# Currency Serializers

class CurrencySerializer(serializers.ModelSerializer):
    """Read-only currency serializer"""

    class Meta:
        model = Currency
        fields = [
            'id',
            'code',
            'name',
            'symbol',
            'decimal_places',
            'is_active',
        ]
        read_only_fields = fields


# Exchange Rate Serializers

class ExchangeRateListSerializer(serializers.ModelSerializer):
    """Lightweight exchange rate list serializer"""
    from_currency_code = serializers.CharField(source='from_currency.code', read_only=True)
    to_currency_code = serializers.CharField(source='to_currency.code', read_only=True)

    class Meta:
        model = ExchangeRate
        fields = [
            'id',
            'from_currency_code',
            'to_currency_code',
            'rate',
            'date',
        ]
        read_only_fields = fields


class ExchangeRateDetailSerializer(serializers.ModelSerializer):
    """Detailed exchange rate serializer"""
    from_currency = CurrencySerializer(read_only=True)
    to_currency = CurrencySerializer(read_only=True)

    class Meta:
        model = ExchangeRate
        fields = [
            'id',
            'from_currency',
            'to_currency',
            'rate',
            'date',
        ]
        read_only_fields = fields


# Payment Method Serializers

class PaymentMethodListSerializer(serializers.ModelSerializer):
    """Lightweight payment method list serializer"""
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = PaymentMethod
        fields = [
            'id',
            'user_email',
            'method_type',
            'is_default',
            'is_active',
            'last_four',
            'created_at',
        ]
        read_only_fields = ['id', 'user_email', 'last_four', 'created_at']


class PaymentMethodDetailSerializer(serializers.ModelSerializer):
    """Detailed payment method serializer"""
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = PaymentMethod
        fields = [
            'id',
            'user',
            'user_email',
            'method_type',
            'stripe_payment_method_id',
            'card_brand',
            'last_four',
            'expiry_month',
            'expiry_year',
            'billing_name',
            'billing_email',
            'billing_address',
            'is_default',
            'is_active',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'user_email',
            'card_brand',
            'last_four',
            'expiry_month',
            'expiry_year',
            'created_at',
            'updated_at',
        ]


class PaymentMethodCreateSerializer(serializers.ModelSerializer):
    """Create payment method serializer"""

    class Meta:
        model = PaymentMethod
        fields = [
            'method_type',
            'stripe_payment_method_id',
            'billing_name',
            'billing_email',
            'billing_address',
            'is_default',
        ]

    def validate(self, data):
        """Validate payment method creation"""
        if data.get('is_default'):
            # Check if there's already a default method
            tenant = self.context['request'].tenant
            existing_default = PaymentMethod.objects.filter(
                tenant=tenant,
                user=self.context['request'].user,
                is_default=True
            ).exists()

            if existing_default:
                raise serializers.ValidationError(
                    "You already have a default payment method. "
                    "Please unset it first or set is_default=False."
                )

        return data


# Payment Transaction Serializers

class PaymentTransactionListSerializer(serializers.ModelSerializer):
    """Lightweight payment transaction list serializer"""
    currency_code = serializers.CharField(source='currency.code', read_only=True)
    payer_email = serializers.EmailField(source='payer.email', read_only=True)
    payee_email = serializers.EmailField(source='payee.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = PaymentTransaction
        fields = [
            'id',
            'transaction_id',
            'amount',
            'currency_code',
            'amount_usd',
            'payer_email',
            'payee_email',
            'status',
            'status_display',
            'created_at',
        ]
        read_only_fields = fields


class PaymentTransactionDetailSerializer(serializers.ModelSerializer):
    """Detailed payment transaction serializer"""
    currency = CurrencySerializer(read_only=True)
    exchange_rate = ExchangeRateDetailSerializer(read_only=True)
    payer_email = serializers.EmailField(source='payer.email', read_only=True)
    payee_email = serializers.EmailField(source='payee.email', read_only=True)
    payment_method_details = PaymentMethodDetailSerializer(source='payment_method', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = PaymentTransaction
        fields = [
            'id',
            'transaction_id',
            'amount',
            'currency',
            'exchange_rate',
            'amount_usd',
            'payer',
            'payer_email',
            'payee',
            'payee_email',
            'status',
            'status_display',
            'payment_method_details',
            'stripe_payment_intent_id',
            'stripe_charge_id',
            'content_type',
            'object_id',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = fields


class PaymentTransactionCreateSerializer(serializers.ModelSerializer):
    """Create payment transaction serializer"""

    class Meta:
        model = PaymentTransaction
        fields = [
            'amount',
            'currency',
            'payee',
            'payment_method',
            'content_type',
            'object_id',
            'metadata',
        ]

    def validate(self, data):
        """Validate payment transaction creation"""
        if data['amount'] <= 0:
            raise serializers.ValidationError("Amount must be greater than 0")

        if not data['currency'].is_active:
            raise serializers.ValidationError("Selected currency is not active")

        # Payer is automatically set to request.user
        # Validate payee is not the same as payer
        if data['payee'] == self.context['request'].user:
            raise serializers.ValidationError("Cannot send payment to yourself")

        return data

    def create(self, validated_data):
        """Create payment transaction with payer set to request user"""
        validated_data['payer'] = self.context['request'].user
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)


# Refund Request Serializers

class RefundRequestListSerializer(serializers.ModelSerializer):
    """Lightweight refund request list serializer"""
    transaction_id = serializers.CharField(source='payment_transaction.transaction_id', read_only=True)
    requested_by_email = serializers.EmailField(source='requested_by.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = RefundRequest
        fields = [
            'id',
            'transaction_id',
            'refund_amount',
            'reason',
            'status',
            'status_display',
            'requested_by_email',
            'created_at',
        ]
        read_only_fields = ['id', 'transaction_id', 'requested_by_email', 'created_at']


class RefundRequestDetailSerializer(serializers.ModelSerializer):
    """Detailed refund request serializer"""
    payment_transaction = PaymentTransactionDetailSerializer(read_only=True)
    requested_by_email = serializers.EmailField(source='requested_by.email', read_only=True)
    processed_by_email = serializers.EmailField(source='processed_by.email', read_only=True, allow_null=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = RefundRequest
        fields = [
            'id',
            'payment_transaction',
            'refund_amount',
            'reason',
            'status',
            'status_display',
            'requested_by',
            'requested_by_email',
            'processed_by',
            'processed_by_email',
            'processed_at',
            'stripe_refund_id',
            'admin_notes',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'requested_by',
            'requested_by_email',
            'processed_by',
            'processed_by_email',
            'processed_at',
            'stripe_refund_id',
            'created_at',
            'updated_at',
        ]


class RefundRequestCreateSerializer(serializers.ModelSerializer):
    """Create refund request serializer"""

    class Meta:
        model = RefundRequest
        fields = [
            'payment_transaction',
            'refund_amount',
            'reason',
        ]

    def validate(self, data):
        """Validate refund request creation"""
        payment = data['payment_transaction']

        # Validate payment belongs to tenant
        if payment.tenant != self.context['request'].tenant:
            raise serializers.ValidationError("Payment transaction not found")

        # Validate payment was successful
        if payment.status != 'succeeded':
            raise serializers.ValidationError("Can only refund successful payments")

        # Validate refund amount
        if data['refund_amount'] <= 0:
            raise serializers.ValidationError("Refund amount must be greater than 0")

        if data['refund_amount'] > payment.amount:
            raise serializers.ValidationError("Refund amount cannot exceed payment amount")

        # Check for existing refunds
        existing_refunds = RefundRequest.objects.filter(
            payment_transaction=payment,
            status__in=['pending', 'approved']
        ).aggregate(total=serializers.Sum('refund_amount'))['total'] or 0

        if existing_refunds + data['refund_amount'] > payment.amount:
            raise serializers.ValidationError(
                f"Total refund amount would exceed payment amount. "
                f"Already refunded: {existing_refunds}"
            )

        return data

    def create(self, validated_data):
        """Create refund request with requested_by set to request user"""
        validated_data['requested_by'] = self.context['request'].user
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)


# Payment Intent Serializers

class PaymentIntentSerializer(serializers.ModelSerializer):
    """Payment intent serializer"""
    currency_code = serializers.CharField(source='currency.code', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = PaymentIntent
        fields = [
            'id',
            'intent_id',
            'user',
            'user_email',
            'amount',
            'currency',
            'currency_code',
            'status',
            'status_display',
            'client_secret',
            'stripe_payment_intent_id',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'intent_id',
            'user_email',
            'status',
            'status_display',
            'client_secret',
            'stripe_payment_intent_id',
            'created_at',
            'updated_at',
        ]
