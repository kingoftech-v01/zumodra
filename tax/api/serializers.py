"""
Tax API Serializers
"""

from rest_framework import serializers
from django.utils import timezone
from ..models import (
    AvalaraConfig,
    TaxRate,
    TaxCalculation,
    TaxExemption,
    TaxRemittance,
    TaxReport,
)


# ============= AvalaraConfig Serializers =============

class AvalaraConfigSerializer(serializers.ModelSerializer):
    """Avalara configuration serializer (admin only)"""
    # Exclude sensitive fields from read
    class Meta:
        model = AvalaraConfig
        fields = [
            'id', 'company_code', 'company_name', 'tax_id',
            'default_tax_code', 'commit_transactions', 'is_sandbox',
            'is_active', 'last_sync', 'metadata', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'last_sync', 'created_at', 'updated_at']
        extra_kwargs = {
            # These are write-only for security
            'account_id': {'write_only': True},
            'license_key': {'write_only': True},
        }


# ============= TaxRate Serializers =============

class TaxRateListSerializer(serializers.ModelSerializer):
    """Lightweight tax rate list"""
    tax_type_display = serializers.CharField(source='get_tax_type_display', read_only=True)
    rate_percentage = serializers.DecimalField(
        max_digits=7,
        decimal_places=2,
        read_only=True
    )

    class Meta:
        model = TaxRate
        fields = [
            'id', 'country', 'state_province', 'city', 'tax_type',
            'tax_type_display', 'rate', 'rate_percentage',
            'effective_start', 'effective_end', 'is_active',
        ]
        read_only_fields = fields


class TaxRateDetailSerializer(serializers.ModelSerializer):
    """Full tax rate details"""
    tax_type_display = serializers.CharField(source='get_tax_type_display', read_only=True)
    rate_percentage = serializers.DecimalField(
        max_digits=7,
        decimal_places=2,
        read_only=True
    )

    class Meta:
        model = TaxRate
        fields = [
            'id', 'country', 'state_province', 'county', 'city',
            'postal_code', 'tax_type', 'tax_type_display', 'rate',
            'rate_percentage', 'effective_start', 'effective_end',
            'avalara_jurisdiction_id', 'is_active', 'notes',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


# ============= TaxCalculation Serializers =============

class TaxCalculationListSerializer(serializers.ModelSerializer):
    """Lightweight tax calculation list"""
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    effective_tax_rate = serializers.DecimalField(
        max_digits=7,
        decimal_places=4,
        read_only=True
    )

    class Meta:
        model = TaxCalculation
        fields = [
            'id', 'source', 'source_display', 'subtotal', 'tax_amount',
            'total', 'currency', 'effective_tax_rate', 'calculated_at',
        ]
        read_only_fields = fields


class TaxCalculationDetailSerializer(serializers.ModelSerializer):
    """Full tax calculation details"""
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    effective_tax_rate = serializers.DecimalField(
        max_digits=7,
        decimal_places=4,
        read_only=True
    )

    class Meta:
        model = TaxCalculation
        fields = [
            'id', 'payment_transaction', 'subscription_invoice', 'source',
            'source_display', 'subtotal', 'tax_amount', 'total', 'currency',
            'tax_breakdown', 'tax_address', 'avalara_transaction_code',
            'avalara_response', 'effective_tax_rate', 'calculated_at', 'metadata',
        ]
        read_only_fields = fields


# ============= TaxExemption Serializers =============

class TaxExemptionListSerializer(serializers.ModelSerializer):
    """Lightweight tax exemption list"""
    customer_email = serializers.EmailField(source='customer.email', read_only=True)
    customer_name = serializers.SerializerMethodField()
    exemption_type_display = serializers.CharField(
        source='get_exemption_type_display',
        read_only=True
    )
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_valid = serializers.BooleanField(read_only=True)

    class Meta:
        model = TaxExemption
        fields = [
            'id', 'customer', 'customer_email', 'customer_name',
            'exemption_type', 'exemption_type_display', 'exemption_number',
            'status', 'status_display', 'expiration_date', 'is_valid',
            'created_at',
        ]
        read_only_fields = fields

    def get_customer_name(self, obj):
        return obj.customer.get_full_name()


class TaxExemptionDetailSerializer(serializers.ModelSerializer):
    """Full tax exemption details"""
    customer_email = serializers.EmailField(source='customer.email', read_only=True)
    customer_name = serializers.SerializerMethodField()
    exemption_type_display = serializers.CharField(
        source='get_exemption_type_display',
        read_only=True
    )
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_valid = serializers.BooleanField(read_only=True)

    class Meta:
        model = TaxExemption
        fields = [
            'id', 'customer', 'customer_email', 'customer_name',
            'exemption_type', 'exemption_type_display', 'exemption_number',
            'country', 'state_province', 'status', 'status_display',
            'issue_date', 'expiration_date', 'verified_at',
            'certificate_file', 'notes', 'is_valid',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_customer_name(self, obj):
        return obj.customer.get_full_name()


# ============= TaxRemittance Serializers =============

class TaxRemittanceListSerializer(serializers.ModelSerializer):
    """Lightweight tax remittance list"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = TaxRemittance
        fields = [
            'id', 'remittance_id', 'country', 'state_province',
            'authority_name', 'period_start', 'period_end', 'tax_collected',
            'tax_owed', 'amount_paid', 'currency', 'status', 'status_display',
            'due_date', 'paid_at',
        ]
        read_only_fields = fields


class TaxRemittanceDetailSerializer(serializers.ModelSerializer):
    """Full tax remittance details"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = TaxRemittance
        fields = [
            'id', 'remittance_id', 'country', 'state_province',
            'authority_name', 'period_start', 'period_end', 'tax_collected',
            'tax_owed', 'amount_paid', 'currency', 'status', 'status_display',
            'due_date', 'paid_at', 'filing_frequency', 'filing_reference',
            'payment_transaction', 'notes', 'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'remittance_id', 'created_at', 'updated_at',
        ]


# ============= TaxReport Serializers =============

class TaxReportListSerializer(serializers.ModelSerializer):
    """Lightweight tax report list"""
    report_type_display = serializers.CharField(
        source='get_report_type_display',
        read_only=True
    )
    generated_by_name = serializers.SerializerMethodField()

    class Meta:
        model = TaxReport
        fields = [
            'id', 'report_number', 'report_type', 'report_type_display',
            'period_start', 'period_end', 'total_taxable_sales',
            'total_tax_collected', 'total_tax_remitted', 'currency',
            'generated_by', 'generated_by_name', 'generated_at',
        ]
        read_only_fields = fields

    def get_generated_by_name(self, obj):
        return obj.generated_by.get_full_name() if obj.generated_by else None


class TaxReportDetailSerializer(serializers.ModelSerializer):
    """Full tax report details"""
    report_type_display = serializers.CharField(
        source='get_report_type_display',
        read_only=True
    )
    generated_by_name = serializers.SerializerMethodField()

    class Meta:
        model = TaxReport
        fields = [
            'id', 'report_number', 'report_type', 'report_type_display',
            'period_start', 'period_end', 'total_taxable_sales',
            'total_exempt_sales', 'total_tax_collected', 'total_tax_remitted',
            'currency', 'jurisdiction_breakdown', 'generated_by',
            'generated_by_name', 'generated_at', 'pdf_file', 'notes',
        ]
        read_only_fields = ['id', 'report_number', 'generated_at']

    def get_generated_by_name(self, obj):
        return obj.generated_by.get_full_name() if obj.generated_by else None
