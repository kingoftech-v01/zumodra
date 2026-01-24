"""
Billing API Serializers
"""

from rest_framework import serializers
from ..models import (
    SubscriptionPlan,
    TenantSubscription,
    PlatformInvoice,
    BillingHistory,
)


# ============= SubscriptionPlan Serializers =============

class SubscriptionPlanListSerializer(serializers.ModelSerializer):
    """Lightweight subscription plan list (public)"""
    tier_display = serializers.CharField(source='get_tier_display', read_only=True)
    yearly_discount = serializers.SerializerMethodField()

    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'slug', 'tier', 'tier_display', 'description',
            'price_monthly', 'price_yearly', 'currency', 'max_users',
            'max_jobs', 'max_storage_gb', 'trial_days', 'features',
            'yearly_discount', 'is_public', 'sort_order',
        ]
        read_only_fields = fields

    def get_yearly_discount(self, obj):
        return obj.get_yearly_discount_percentage()


class SubscriptionPlanDetailSerializer(serializers.ModelSerializer):
    """Full subscription plan details (public)"""
    tier_display = serializers.CharField(source='get_tier_display', read_only=True)
    yearly_discount = serializers.SerializerMethodField()

    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'slug', 'tier', 'tier_display', 'description',
            'price_monthly', 'price_yearly', 'currency', 'max_users',
            'max_jobs', 'max_storage_gb', 'max_api_calls_per_month',
            'features', 'trial_days', 'stripe_price_id_monthly',
            'stripe_price_id_yearly', 'stripe_product_id', 'is_active',
            'is_public', 'sort_order', 'yearly_discount',
            'created_at', 'updated_at',
        ]
        read_only_fields = fields

    def get_yearly_discount(self, obj):
        return obj.get_yearly_discount_percentage()


# ============= TenantSubscription Serializers =============

class TenantSubscriptionListSerializer(serializers.ModelSerializer):
    """Lightweight tenant subscription list"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    plan_name = serializers.CharField(source='plan.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    billing_cycle_display = serializers.CharField(
        source='get_billing_cycle_display',
        read_only=True
    )
    is_trialing = serializers.BooleanField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    days_until_renewal = serializers.IntegerField(read_only=True)

    class Meta:
        model = TenantSubscription
        fields = [
            'id', 'tenant', 'tenant_name', 'plan', 'plan_name',
            'status', 'status_display', 'billing_cycle', 'billing_cycle_display',
            'quantity', 'current_period_start', 'current_period_end',
            'is_trialing', 'is_active', 'days_until_renewal', 'created_at',
        ]
        read_only_fields = fields


class TenantSubscriptionDetailSerializer(serializers.ModelSerializer):
    """Full tenant subscription details"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    plan = SubscriptionPlanListSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    billing_cycle_display = serializers.CharField(
        source='get_billing_cycle_display',
        read_only=True
    )
    is_trialing = serializers.BooleanField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    days_until_renewal = serializers.IntegerField(read_only=True)

    class Meta:
        model = TenantSubscription
        fields = [
            'id', 'tenant', 'tenant_name', 'plan', 'status', 'status_display',
            'billing_cycle', 'billing_cycle_display', 'quantity',
            'current_period_start', 'current_period_end', 'trial_start',
            'trial_end', 'canceled_at', 'ended_at', 'stripe_subscription_id',
            'stripe_customer_id', 'cancel_at_period_end', 'cancellation_reason',
            'metadata', 'is_trialing', 'is_active', 'days_until_renewal',
            'created_at', 'updated_at',
        ]
        read_only_fields = fields


# ============= PlatformInvoice Serializers =============

class PlatformInvoiceListSerializer(serializers.ModelSerializer):
    """Lightweight platform invoice list"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    plan_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = PlatformInvoice
        fields = [
            'id', 'invoice_number', 'tenant', 'tenant_name', 'plan_name',
            'status', 'status_display', 'subtotal', 'tax', 'total',
            'amount_due', 'currency', 'invoice_date', 'due_date',
            'is_overdue', 'created_at',
        ]
        read_only_fields = fields

    def get_plan_name(self, obj):
        if obj.subscription:
            return obj.subscription.plan.name
        return None


class PlatformInvoiceDetailSerializer(serializers.ModelSerializer):
    """Full platform invoice details"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    subscription = TenantSubscriptionListSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = PlatformInvoice
        fields = [
            'id', 'invoice_number', 'tenant', 'tenant_name', 'subscription',
            'status', 'status_display', 'subtotal', 'tax', 'total',
            'amount_paid', 'amount_due', 'currency', 'line_items',
            'invoice_date', 'due_date', 'paid_at', 'stripe_invoice_id',
            'stripe_payment_intent_id', 'pdf_url', 'notes', 'customer_notes',
            'is_overdue', 'created_at', 'updated_at',
        ]
        read_only_fields = fields


# ============= BillingHistory Serializers =============

class BillingHistorySerializer(serializers.ModelSerializer):
    """Billing history serializer"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    change_type_display = serializers.CharField(
        source='get_change_type_display',
        read_only=True
    )
    old_plan_name = serializers.SerializerMethodField()
    new_plan_name = serializers.SerializerMethodField()
    changed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = BillingHistory
        fields = [
            'id', 'tenant', 'tenant_name', 'subscription', 'change_type',
            'change_type_display', 'description', 'old_plan', 'old_plan_name',
            'new_plan', 'new_plan_name', 'old_status', 'new_status',
            'metadata', 'changed_by', 'changed_by_name', 'created_at',
        ]
        read_only_fields = fields

    def get_old_plan_name(self, obj):
        return obj.old_plan.name if obj.old_plan else None

    def get_new_plan_name(self, obj):
        return obj.new_plan.name if obj.new_plan else None

    def get_changed_by_name(self, obj):
        return obj.changed_by.get_full_name() if obj.changed_by else 'System'
