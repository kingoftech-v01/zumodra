"""
Expenses API Serializers
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from ..models import (
    ExpenseCategory,
    ExpenseReport,
    ExpenseLineItem,
    ExpenseApproval,
    Reimbursement,
    MileageRate,
)

User = get_user_model()


# Expense Category Serializers

class ExpenseCategorySerializer(serializers.ModelSerializer):
    """Expense category serializer (read-only)"""
    parent_name = serializers.CharField(source='parent.name', read_only=True, allow_null=True)

    class Meta:
        model = ExpenseCategory
        fields = [
            'id',
            'name',
            'slug',
            'description',
            'parent',
            'parent_name',
            'requires_receipt',
            'requires_justification',
            'daily_limit',
            'monthly_limit',
            'is_taxable',
            'gl_code',
            'is_active',
            'created_at',
        ]
        read_only_fields = fields


# Expense Report Serializers

class ExpenseReportListSerializer(serializers.ModelSerializer):
    """Lightweight expense report list serializer"""
    employee_name = serializers.CharField(source='employee.user.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    line_item_count = serializers.IntegerField(source='line_items.count', read_only=True)

    class Meta:
        model = ExpenseReport
        fields = [
            'id',
            'report_number',
            'employee_name',
            'title',
            'status',
            'status_display',
            'period_start',
            'period_end',
            'total_amount',
            'reimbursable_amount',
            'line_item_count',
            'submitted_at',
            'created_at',
        ]
        read_only_fields = fields


class ExpenseReportDetailSerializer(serializers.ModelSerializer):
    """Detailed expense report serializer"""
    employee_name = serializers.CharField(source='employee.user.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = ExpenseReport
        fields = [
            'id',
            'report_number',
            'employee',
            'employee_name',
            'title',
            'description',
            'purpose',
            'status',
            'status_display',
            'period_start',
            'period_end',
            'total_amount',
            'reimbursable_amount',
            'non_reimbursable_amount',
            'submitted_at',
            'approved_at',
            'rejected_at',
            'paid_at',
            'employee_notes',
            'approver_notes',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'report_number',
            'employee_name',
            'status_display',
            'total_amount',
            'reimbursable_amount',
            'non_reimbursable_amount',
            'submitted_at',
            'approved_at',
            'rejected_at',
            'paid_at',
            'created_at',
            'updated_at',
        ]


class ExpenseReportCreateSerializer(serializers.ModelSerializer):
    """Create expense report serializer"""

    class Meta:
        model = ExpenseReport
        fields = [
            'title',
            'description',
            'purpose',
            'period_start',
            'period_end',
            'employee_notes',
        ]

    def validate(self, data):
        """Validate expense report creation"""
        if data['period_end'] < data['period_start']:
            raise serializers.ValidationError("Period end must be after period start")

        return data

    def create(self, validated_data):
        """Create expense report with employee set to request user's employee record"""
        from hr_core.models import Employee

        try:
            employee = Employee.objects.get(
                user=self.context['request'].user,
                tenant=self.context['request'].tenant
            )
        except Employee.DoesNotExist:
            raise serializers.ValidationError("Employee record not found for current user")

        validated_data['employee'] = employee
        validated_data['tenant'] = self.context['request'].tenant
        return super().create(validated_data)


# Expense Line Item Serializers

class ExpenseLineItemListSerializer(serializers.ModelSerializer):
    """Lightweight expense line item list serializer"""
    category_name = serializers.CharField(source='category.name', read_only=True)
    expense_type_display = serializers.CharField(source='get_expense_type_display', read_only=True)

    class Meta:
        model = ExpenseLineItem
        fields = [
            'id',
            'expense_report',
            'expense_type',
            'expense_type_display',
            'category',
            'category_name',
            'description',
            'expense_date',
            'amount',
            'currency',
            'merchant',
            'is_reimbursable',
            'created_at',
        ]
        read_only_fields = ['id', 'created_at']


class ExpenseLineItemDetailSerializer(serializers.ModelSerializer):
    """Detailed expense line item serializer"""
    category_name = serializers.CharField(source='category.name', read_only=True)
    expense_type_display = serializers.CharField(source='get_expense_type_display', read_only=True)

    class Meta:
        model = ExpenseLineItem
        fields = [
            'id',
            'expense_report',
            'expense_type',
            'expense_type_display',
            'category',
            'category_name',
            'description',
            'expense_date',
            'amount',
            'currency',
            'merchant',
            'location',
            'mileage_distance',
            'mileage_rate',
            'mileage_start_location',
            'mileage_end_location',
            'receipt_file',
            'receipt_url',
            'is_reimbursable',
            'is_billable',
            'client_name',
            'notes',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


# Expense Approval Serializers

class ExpenseApprovalListSerializer(serializers.ModelSerializer):
    """Lightweight expense approval list serializer"""
    expense_report_number = serializers.CharField(source='expense_report.report_number', read_only=True)
    approver_name = serializers.CharField(source='approver.get_full_name', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = ExpenseApproval
        fields = [
            'id',
            'expense_report',
            'expense_report_number',
            'approver',
            'approver_name',
            'approver_role',
            'approval_level',
            'action',
            'action_display',
            'requested_at',
            'responded_at',
        ]
        read_only_fields = fields


class ExpenseApprovalDetailSerializer(serializers.ModelSerializer):
    """Detailed expense approval serializer"""
    expense_report_number = serializers.CharField(source='expense_report.report_number', read_only=True)
    approver_name = serializers.CharField(source='approver.get_full_name', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = ExpenseApproval
        fields = [
            'id',
            'expense_report',
            'expense_report_number',
            'approver',
            'approver_name',
            'approver_role',
            'approval_level',
            'action',
            'action_display',
            'comments',
            'requested_at',
            'responded_at',
            'metadata',
        ]
        read_only_fields = [
            'id',
            'expense_report_number',
            'approver_name',
            'action_display',
            'requested_at',
            'responded_at',
        ]


# Reimbursement Serializers

class ReimbursementSerializer(serializers.ModelSerializer):
    """Reimbursement serializer"""
    expense_report_number = serializers.CharField(source='expense_report.report_number', read_only=True)
    employee_name = serializers.CharField(source='employee.user.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Reimbursement
        fields = [
            'id',
            'reimbursement_id',
            'expense_report',
            'expense_report_number',
            'employee',
            'employee_name',
            'amount',
            'currency',
            'status',
            'status_display',
            'payment_method',
            'payment_transaction',
            'payroll_run',
            'approved_at',
            'paid_at',
            'notes',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'reimbursement_id',
            'expense_report_number',
            'employee_name',
            'status_display',
            'approved_at',
            'paid_at',
            'created_at',
            'updated_at',
        ]


# Mileage Rate Serializers

class MileageRateSerializer(serializers.ModelSerializer):
    """Mileage rate serializer (read-only)"""

    class Meta:
        model = MileageRate
        fields = [
            'id',
            'country',
            'region',
            'rate',
            'unit',
            'purpose',
            'effective_start',
            'effective_end',
            'is_active',
            'notes',
            'created_at',
        ]
        read_only_fields = fields
