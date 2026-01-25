"""
Payroll API Serializers
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from ..models import (
    PayrollRun,
    EmployeePayment,
    DirectDeposit,
    PayStub,
    PayrollDeduction,
    PayrollTax,
)

User = get_user_model()


# Payroll Run Serializers

class PayrollRunListSerializer(serializers.ModelSerializer):
    """Lightweight payroll run list serializer"""
    created_by_email = serializers.EmailField(source='created_by.email', read_only=True)
    approved_by_email = serializers.EmailField(source='approved_by.email', read_only=True, allow_null=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    frequency_display = serializers.CharField(source='get_frequency_display', read_only=True)

    class Meta:
        model = PayrollRun
        fields = [
            'id',
            'run_number',
            'frequency',
            'frequency_display',
            'pay_period_start',
            'pay_period_end',
            'pay_date',
            'status',
            'status_display',
            'employee_count',
            'total_gross',
            'total_net',
            'total_taxes',
            'created_by_email',
            'approved_by_email',
            'created_at',
        ]
        read_only_fields = fields


class PayrollRunDetailSerializer(serializers.ModelSerializer):
    """Detailed payroll run serializer"""
    created_by_email = serializers.EmailField(source='created_by.email', read_only=True)
    approved_by_email = serializers.EmailField(source='approved_by.email', read_only=True, allow_null=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    frequency_display = serializers.CharField(source='get_frequency_display', read_only=True)

    class Meta:
        model = PayrollRun
        fields = [
            'id',
            'run_number',
            'frequency',
            'frequency_display',
            'pay_period_start',
            'pay_period_end',
            'pay_date',
            'status',
            'status_display',
            'employee_count',
            'total_gross',
            'total_net',
            'total_taxes',
            'total_deductions',
            'created_by',
            'created_by_email',
            'approved_by',
            'approved_by_email',
            'approved_at',
            'paid_at',
            'notes',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'run_number',
            'created_by_email',
            'approved_by',
            'approved_by_email',
            'approved_at',
            'paid_at',
            'created_at',
            'updated_at',
        ]


class PayrollRunCreateSerializer(serializers.ModelSerializer):
    """Create payroll run serializer"""

    class Meta:
        model = PayrollRun
        fields = [
            'frequency',
            'pay_period_start',
            'pay_period_end',
            'pay_date',
            'notes',
            'metadata',
        ]

    def validate(self, data):
        """Validate payroll run creation"""
        if data['pay_period_end'] < data['pay_period_start']:
            raise serializers.ValidationError("Pay period end must be after start")

        if data['pay_date'] < data['pay_period_end']:
            raise serializers.ValidationError("Pay date must be after pay period end")

        return data

    def create(self, validated_data):
        """Create payroll run with created_by set to request user"""
        validated_data['created_by'] = self.context['request'].user
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)


# Employee Payment Serializers

class EmployeePaymentListSerializer(serializers.ModelSerializer):
    """Lightweight employee payment list serializer"""
    employee_name = serializers.CharField(source='employee.user.get_full_name', read_only=True)
    payroll_run_number = serializers.CharField(source='payroll_run.run_number', read_only=True)

    class Meta:
        model = EmployeePayment
        fields = [
            'id',
            'payroll_run_number',
            'employee_name',
            'gross_amount',
            'total_taxes',
            'total_deductions',
            'net_amount',
            'payment_method',
            'paid',
            'paid_at',
            'created_at',
        ]
        read_only_fields = fields


class EmployeePaymentDetailSerializer(serializers.ModelSerializer):
    """Detailed employee payment serializer"""
    employee_name = serializers.CharField(source='employee.user.get_full_name', read_only=True)
    payroll_run_number = serializers.CharField(source='payroll_run.run_number', read_only=True)

    class Meta:
        model = EmployeePayment
        fields = [
            'id',
            'payroll_run',
            'payroll_run_number',
            'employee',
            'employee_name',
            'gross_amount',
            'regular_hours',
            'overtime_hours',
            'hourly_rate',
            'bonus_amount',
            'adjustment_amount',
            'federal_tax',
            'state_tax',
            'local_tax',
            'social_security',
            'medicare',
            'total_taxes',
            'total_deductions',
            'net_amount',
            'payment_method',
            'direct_deposit',
            'payment_transaction',
            'paid',
            'paid_at',
            'ytd_gross',
            'ytd_taxes',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'payroll_run_number',
            'employee_name',
            'total_taxes',
            'net_amount',
            'paid',
            'paid_at',
            'created_at',
            'updated_at',
        ]


# Direct Deposit Serializers

class DirectDepositListSerializer(serializers.ModelSerializer):
    """Lightweight direct deposit list serializer"""
    employee_name = serializers.CharField(source='employee.user.get_full_name', read_only=True)
    account_type_display = serializers.CharField(source='get_account_type_display', read_only=True)

    class Meta:
        model = DirectDeposit
        fields = [
            'id',
            'employee_name',
            'account_type',
            'account_type_display',
            'account_number_last4',
            'bank_name',
            'is_active',
            'is_primary',
            'verified',
            'created_at',
        ]
        read_only_fields = ['id', 'employee_name', 'created_at']


class DirectDepositDetailSerializer(serializers.ModelSerializer):
    """Detailed direct deposit serializer"""
    employee_name = serializers.CharField(source='employee.user.get_full_name', read_only=True)
    account_type_display = serializers.CharField(source='get_account_type_display', read_only=True)

    class Meta:
        model = DirectDeposit
        fields = [
            'id',
            'employee',
            'employee_name',
            'account_type',
            'account_type_display',
            'routing_number',
            'account_number_last4',
            'bank_name',
            'allocation_type',
            'allocation_value',
            'is_active',
            'is_primary',
            'verified',
            'verified_at',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'employee_name',
            'account_number_last4',
            'verified',
            'verified_at',
            'created_at',
            'updated_at',
        ]


class DirectDepositCreateSerializer(serializers.ModelSerializer):
    """Create direct deposit serializer"""

    class Meta:
        model = DirectDeposit
        fields = [
            'employee',
            'account_type',
            'routing_number',
            'account_number',
            'bank_name',
            'allocation_type',
            'allocation_value',
            'is_primary',
        ]

    def validate(self, data):
        """Validate direct deposit creation"""
        if len(data.get('routing_number', '')) != 9:
            raise serializers.ValidationError("Routing number must be 9 digits")

        if data.get('is_primary'):
            # Check if there's already a primary account
            employee = data['employee']
            existing_primary = DirectDeposit.objects.filter(
                employee=employee,
                is_primary=True
            ).exists()

            if existing_primary:
                raise serializers.ValidationError(
                    "Employee already has a primary direct deposit account. "
                    "Please unset it first or set is_primary=False."
                )

        return data

    def create(self, validated_data):
        """Create direct deposit with last4 extraction"""
        account_number = validated_data['account_number']
        validated_data['account_number_last4'] = account_number[-4:]
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)


# Pay Stub Serializers

class PayStubSerializer(serializers.ModelSerializer):
    """Pay stub serializer (read-only)"""
    employee_name = serializers.CharField(source='employee_payment.employee.user.get_full_name', read_only=True)
    payroll_run_number = serializers.CharField(source='employee_payment.payroll_run.run_number', read_only=True)

    class Meta:
        model = PayStub
        fields = [
            'id',
            'stub_number',
            'employee_payment',
            'employee_name',
            'payroll_run_number',
            'pdf_file',
            'pdf_url',
            'employee_viewed',
            'employee_viewed_at',
            'generated_at',
            'metadata',
        ]
        read_only_fields = fields


# Payroll Deduction Serializers

class PayrollDeductionSerializer(serializers.ModelSerializer):
    """Payroll deduction serializer (read-only)"""
    deduction_type_display = serializers.CharField(source='get_deduction_type_display', read_only=True)

    class Meta:
        model = PayrollDeduction
        fields = [
            'id',
            'employee_payment',
            'deduction_type',
            'deduction_type_display',
            'description',
            'amount',
            'pre_tax',
            'created_at',
        ]
        read_only_fields = fields


# Payroll Tax Serializers

class PayrollTaxSerializer(serializers.ModelSerializer):
    """Payroll tax serializer (read-only)"""
    tax_type_display = serializers.CharField(source='get_tax_type_display', read_only=True)

    class Meta:
        model = PayrollTax
        fields = [
            'id',
            'employee_payment',
            'tax_type',
            'tax_type_display',
            'taxable_amount',
            'tax_rate',
            'tax_amount',
            'jurisdiction',
            'calculation_data',
            'created_at',
        ]
        read_only_fields = fields
