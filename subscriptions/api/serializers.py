"""
Subscriptions API Serializers
"""

from rest_framework import serializers
from django.utils import timezone
from ..models import (
    SubscriptionProduct,
    SubscriptionTier,
    CustomerSubscription,
    SubscriptionInvoice,
    UsageRecord,
)


# ============= SubscriptionProduct Serializers =============

class SubscriptionProductListSerializer(serializers.ModelSerializer):
    """Lightweight subscription product list"""
    yearly_discount = serializers.SerializerMethodField()
    active_subscribers = serializers.SerializerMethodField()
    tier_count = serializers.IntegerField(source='tiers.count', read_only=True)

    class Meta:
        model = SubscriptionProduct
        fields = [
            'id', 'name', 'slug', 'product_type', 'base_price_monthly',
            'base_price_yearly', 'currency', 'trial_period_days', 'is_active',
            'is_public', 'yearly_discount', 'active_subscribers', 'tier_count',
            'created_at',
        ]
        read_only_fields = fields

    def get_yearly_discount(self, obj):
        return obj.get_yearly_discount_percentage()

    def get_active_subscribers(self, obj):
        return obj.customer_subscriptions.filter(status__in=['active', 'trialing']).count()


class SubscriptionTierSerializer(serializers.ModelSerializer):
    """Subscription tier serializer"""
    class Meta:
        model = SubscriptionTier
        fields = [
            'id', 'name', 'min_quantity', 'max_quantity',
            'price_per_unit_monthly', 'price_per_unit_yearly',
            'created_at',
        ]
        read_only_fields = ['id', 'created_at']


class SubscriptionProductDetailSerializer(serializers.ModelSerializer):
    """Full subscription product details"""
    tiers = SubscriptionTierSerializer(many=True, read_only=True)
    yearly_discount = serializers.SerializerMethodField()
    active_subscribers = serializers.SerializerMethodField()
    monthly_revenue = serializers.SerializerMethodField()

    class Meta:
        model = SubscriptionProduct
        fields = [
            'id', 'name', 'slug', 'description', 'product_type',
            'base_price_monthly', 'base_price_yearly', 'currency',
            'trial_period_days', 'features', 'max_users', 'max_storage_gb',
            'max_api_calls_per_month', 'stripe_product_id',
            'stripe_price_id_monthly', 'stripe_price_id_yearly',
            'is_active', 'is_public', 'sort_order', 'tiers',
            'yearly_discount', 'active_subscribers', 'monthly_revenue',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_yearly_discount(self, obj):
        return obj.get_yearly_discount_percentage()

    def get_active_subscribers(self, obj):
        return obj.customer_subscriptions.filter(status__in=['active', 'trialing']).count()

    def get_monthly_revenue(self, obj):
        active_subs = obj.customer_subscriptions.filter(status__in=['active', 'trialing'])
        monthly = active_subs.filter(billing_cycle='monthly').aggregate(
            total=serializers.models.Sum('total_price')
        )['total'] or 0
        yearly = (active_subs.filter(billing_cycle='yearly').aggregate(
            total=serializers.models.Sum('total_price')
        )['total'] or 0) / 12
        return float(monthly + yearly)


class SubscriptionProductCreateSerializer(serializers.ModelSerializer):
    """Create/update subscription product"""
    class Meta:
        model = SubscriptionProduct
        fields = [
            'name', 'slug', 'description', 'product_type',
            'base_price_monthly', 'base_price_yearly', 'currency',
            'trial_period_days', 'features', 'max_users', 'max_storage_gb',
            'max_api_calls_per_month', 'is_active', 'is_public', 'sort_order',
        ]

    def validate_slug(self, value):
        if self.instance:
            # Updating - check slug is unique except for current instance
            if SubscriptionProduct.objects.exclude(pk=self.instance.pk).filter(slug=value).exists():
                raise serializers.ValidationError("Product with this slug already exists")
        else:
            # Creating - check slug is unique
            if SubscriptionProduct.objects.filter(slug=value).exists():
                raise serializers.ValidationError("Product with this slug already exists")
        return value


# ============= CustomerSubscription Serializers =============

class CustomerSubscriptionListSerializer(serializers.ModelSerializer):
    """Lightweight customer subscription list"""
    customer_email = serializers.EmailField(source='customer.email', read_only=True)
    customer_name = serializers.SerializerMethodField()
    product_name = serializers.CharField(source='product.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    billing_cycle_display = serializers.CharField(source='get_billing_cycle_display', read_only=True)
    days_until_renewal = serializers.IntegerField(read_only=True)

    class Meta:
        model = CustomerSubscription
        fields = [
            'id', 'customer_email', 'customer_name', 'product_name',
            'status', 'status_display', 'billing_cycle', 'billing_cycle_display',
            'quantity', 'total_price', 'currency', 'current_period_end',
            'days_until_renewal', 'created_at',
        ]
        read_only_fields = fields

    def get_customer_name(self, obj):
        return obj.customer.get_full_name()


class CustomerSubscriptionDetailSerializer(serializers.ModelSerializer):
    """Full customer subscription details"""
    customer_email = serializers.EmailField(source='customer.email', read_only=True)
    customer_name = serializers.SerializerMethodField()
    product_name = serializers.CharField(source='product.name', read_only=True)
    product = SubscriptionProductListSerializer(read_only=True)
    tier = SubscriptionTierSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    is_trialing = serializers.BooleanField(read_only=True)
    days_until_renewal = serializers.IntegerField(read_only=True)

    class Meta:
        model = CustomerSubscription
        fields = [
            'id', 'customer', 'customer_email', 'customer_name',
            'product', 'product_name', 'tier', 'status', 'status_display',
            'billing_cycle', 'quantity', 'price_per_unit', 'total_price',
            'currency', 'current_period_start', 'current_period_end',
            'trial_start', 'trial_end', 'cancel_at_period_end',
            'canceled_at', 'cancellation_reason', 'ended_at',
            'stripe_subscription_id', 'stripe_customer_id', 'metadata',
            'is_active', 'is_trialing', 'days_until_renewal',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_customer_name(self, obj):
        return obj.customer.get_full_name()


class CustomerSubscriptionCreateSerializer(serializers.ModelSerializer):
    """Create customer subscription"""
    class Meta:
        model = CustomerSubscription
        fields = [
            'customer', 'product', 'tier', 'billing_cycle', 'quantity',
            'price_per_unit', 'current_period_start', 'current_period_end',
            'trial_start', 'trial_end', 'metadata',
        ]

    def validate(self, data):
        # Validate tier belongs to product
        if data.get('tier') and data.get('product'):
            if data['tier'].product != data['product']:
                raise serializers.ValidationError("Selected tier does not belong to the product")

        # Validate quantity is within tier range
        if data.get('tier'):
            tier = data['tier']
            quantity = data.get('quantity', 1)
            if quantity < tier.min_quantity:
                raise serializers.ValidationError(
                    f"Quantity must be at least {tier.min_quantity} for this tier"
                )
            if tier.max_quantity and quantity > tier.max_quantity:
                raise serializers.ValidationError(
                    f"Quantity must not exceed {tier.max_quantity} for this tier"
                )

        return data


# ============= SubscriptionInvoice Serializers =============

class SubscriptionInvoiceListSerializer(serializers.ModelSerializer):
    """Lightweight invoice list"""
    customer_email = serializers.EmailField(source='customer.email', read_only=True)
    customer_name = serializers.SerializerMethodField()
    product_name = serializers.CharField(source='subscription.product.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = SubscriptionInvoice
        fields = [
            'id', 'invoice_number', 'customer_email', 'customer_name',
            'product_name', 'status', 'status_display', 'total', 'amount_due',
            'currency', 'invoice_date', 'due_date', 'is_overdue', 'created_at',
        ]
        read_only_fields = fields

    def get_customer_name(self, obj):
        return obj.customer.get_full_name()


class SubscriptionInvoiceDetailSerializer(serializers.ModelSerializer):
    """Full invoice details"""
    customer_email = serializers.EmailField(source='customer.email', read_only=True)
    customer_name = serializers.SerializerMethodField()
    subscription = CustomerSubscriptionListSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = SubscriptionInvoice
        fields = [
            'id', 'invoice_number', 'subscription', 'customer', 'customer_email',
            'customer_name', 'status', 'status_display', 'subtotal', 'tax',
            'total', 'amount_paid', 'amount_due', 'currency', 'line_items',
            'invoice_date', 'due_date', 'paid_at', 'period_start', 'period_end',
            'stripe_invoice_id', 'stripe_payment_intent_id', 'pdf_url',
            'notes', 'customer_notes', 'is_overdue', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'invoice_number', 'created_at', 'updated_at']

    def get_customer_name(self, obj):
        return obj.customer.get_full_name()


# ============= UsageRecord Serializers =============

class UsageRecordListSerializer(serializers.ModelSerializer):
    """Lightweight usage record list"""
    customer_email = serializers.EmailField(source='subscription.customer.email', read_only=True)
    product_name = serializers.CharField(source='subscription.product.name', read_only=True)
    usage_type_display = serializers.CharField(source='get_usage_type_display', read_only=True)

    class Meta:
        model = UsageRecord
        fields = [
            'id', 'customer_email', 'product_name', 'usage_type',
            'usage_type_display', 'quantity', 'unit_price', 'total_amount',
            'usage_date', 'created_at',
        ]
        read_only_fields = fields


class UsageRecordDetailSerializer(serializers.ModelSerializer):
    """Full usage record details"""
    subscription = CustomerSubscriptionListSerializer(read_only=True)
    usage_type_display = serializers.CharField(source='get_usage_type_display', read_only=True)

    class Meta:
        model = UsageRecord
        fields = [
            'id', 'subscription', 'usage_type', 'usage_type_display',
            'quantity', 'unit_price', 'total_amount', 'usage_date',
            'period_start', 'period_end', 'stripe_usage_record_id',
            'metadata', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'total_amount', 'created_at', 'updated_at']


class UsageRecordCreateSerializer(serializers.ModelSerializer):
    """Create usage record"""
    class Meta:
        model = UsageRecord
        fields = [
            'subscription', 'usage_type', 'quantity', 'unit_price',
            'usage_date', 'period_start', 'period_end', 'metadata',
        ]

    def validate_subscription(self, value):
        if value.product.product_type != 'metered':
            raise serializers.ValidationError(
                "Usage records can only be created for metered subscription products"
            )
        return value
