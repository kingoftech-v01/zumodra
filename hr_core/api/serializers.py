"""
HR Core API Serializers - Human Resources REST API Serializers

This module provides DRF serializers for:
- Employee records and onboarding
- Time-off/absence management
- Document management with e-signatures
- Performance reviews
- Employee offboarding
"""

from decimal import Decimal
from rest_framework import serializers
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from django.utils import timezone
from django.db import transaction

from ..models import (
    Employee, TimeOffType, TimeOffRequest,
    OnboardingChecklist, OnboardingTask, EmployeeOnboarding,
    OnboardingTaskProgress, DocumentTemplate, EmployeeDocument,
    Offboarding, PerformanceReview,
    # New models
    EmployeeCompensation, TimeOffBalance, TimeOffAccrualLog,
    TimeOffBlackoutDate, SkillCategory, Skill, EmployeeSkill,
    Certification, EmployeeActivityLog, EmployeeGoal,
    # PIP models
    PerformanceImprovementPlan, PIPMilestone, PIPProgressNote,
)
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from configurations.models import Department


# ==================== USER SERIALIZERS ====================

class UserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user information for nested representations"""
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name']
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_full_name(self, obj):
        return obj.get_full_name()


# ==================== DEPARTMENT SERIALIZERS ====================

class DepartmentMinimalSerializer(serializers.ModelSerializer):
    """Minimal department information for nested representations"""
    company_name = serializers.CharField(source='company.company.name', read_only=True)

    class Meta:
        model = Department
        fields = ['id', 'name', 'company_name']
        read_only_fields = fields


# ==================== EMPLOYEE SERIALIZERS ====================

class EmployeeMinimalSerializer(serializers.ModelSerializer):
    """
    Minimal employee information for dropdowns and references.
    Used in foreign key fields and quick lookups.
    """
    full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = Employee
        # Note: Employee uses 'id' as UUID primary key (inherited from TenantAwareModel)
        fields = ['id', 'employee_id', 'full_name', 'email', 'job_title', 'status']
        read_only_fields = fields


class EmployeeListSerializer(serializers.ModelSerializer):
    """
    Employee list serializer with essential information.
    Optimized for list views with minimal nested data.
    """
    full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True, allow_null=True)
    manager_name = serializers.SerializerMethodField()
    is_active_employee = serializers.BooleanField(read_only=True)

    class Meta:
        model = Employee
        # Note: Employee uses 'id' as UUID primary key (inherited from TenantAwareModel)
        fields = [
            'id', 'employee_id', 'full_name', 'email',
            'job_title', 'department_name', 'manager_name', 'status',
            'employment_type', 'hire_date', 'start_date', 'work_location',
            'is_active_employee', 'created_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_manager_name(self, obj):
        if obj.manager:
            return obj.manager.full_name
        return None


class EmployeeDetailSerializer(serializers.ModelSerializer):
    """
    Full employee detail serializer with nested relationships - COMPANY ONLY.
    Used for retrieve and update operations.
    """
    user = UserMinimalSerializer(read_only=True)
    department = DepartmentMinimalSerializer(read_only=True)
    department_id = serializers.PrimaryKeyRelatedField(
        queryset=Department.objects.all(),
        source='department',
        write_only=True,
        required=False,
        allow_null=True
    )
    manager = EmployeeMinimalSerializer(read_only=True)
    manager_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='manager',
        write_only=True,
        required=False,
        allow_null=True
    )
    direct_reports = EmployeeMinimalSerializer(many=True, read_only=True)
    direct_reports_count = serializers.SerializerMethodField()
    years_of_service = serializers.FloatField(read_only=True)
    is_active_employee = serializers.BooleanField(read_only=True)
    full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)
    can_have_employees = serializers.SerializerMethodField()

    class Meta:
        model = Employee
        # Note: Employee uses 'id' as UUID primary key (inherited from TenantAwareModel)
        fields = [
            'id', 'user', 'employee_id', 'full_name',
            'status', 'employment_type',
            # Position
            'job_title', 'department', 'department_id', 'manager', 'manager_id',
            'team', 'work_location', 'direct_reports', 'direct_reports_count',
            # Dates
            'hire_date', 'start_date', 'probation_end_date',
            'termination_date', 'last_working_day',
            # Compensation (sensitive - may need permission check)
            'base_salary', 'salary_currency', 'pay_frequency',
            # Benefits & PTO
            'pto_balance', 'sick_leave_balance', 'benefits_enrolled',
            # Emergency Contact
            'emergency_contact_name', 'emergency_contact_phone',
            'emergency_contact_relationship',
            # Computed
            'years_of_service', 'is_active_employee',
            # Tenant type
            'tenant_type', 'can_have_employees',
            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'years_of_service', 'is_active_employee',
            'created_at', 'updated_at', 'direct_reports', 'direct_reports_count'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_direct_reports_count(self, obj):
        return obj.direct_reports.count()

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_have_employees(self, obj):
        """Check if tenant can have employees (COMPANY only)."""
        return obj.tenant.can_have_employees() if hasattr(obj, 'tenant') and obj.tenant else False

    def validate_manager_id(self, value):
        """Prevent circular manager relationships"""
        if self.instance and value:
            if value.id == self.instance.id:
                raise serializers.ValidationError("An employee cannot be their own manager.")
            # Check for circular reference
            current = value
            while current.manager:
                if current.manager.id == self.instance.id:
                    raise serializers.ValidationError(
                        "Circular manager relationship detected."
                    )
                current = current.manager
        return value


class EmployeeCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new employees.
    Links to an existing user account.
    """
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='user',
        write_only=True
    )
    department_id = serializers.PrimaryKeyRelatedField(
        queryset=Department.objects.all(),
        source='department',
        write_only=True,
        required=False,
        allow_null=True
    )
    manager_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='manager',
        write_only=True,
        required=False,
        allow_null=True
    )

    class Meta:
        model = Employee
        fields = [
            'user_id', 'employee_id', 'status', 'employment_type',
            'job_title', 'department_id', 'manager_id', 'team', 'work_location',
            'hire_date', 'start_date', 'probation_end_date',
            'base_salary', 'salary_currency', 'pay_frequency',
            'pto_balance', 'sick_leave_balance',
            'emergency_contact_name', 'emergency_contact_phone',
            'emergency_contact_relationship'
        ]

    def validate_user_id(self, value):
        """Ensure user doesn't already have an employee record"""
        if Employee.objects.filter(user=value).exists():
            raise serializers.ValidationError(
                "This user already has an employee record."
            )
        return value

    def validate_employee_id(self, value):
        """Ensure employee ID is unique"""
        if Employee.objects.filter(employee_id=value).exists():
            raise serializers.ValidationError(
                "An employee with this ID already exists."
            )
        return value


class EmployeeOrgChartSerializer(serializers.ModelSerializer):
    """
    Serializer for organizational chart representation.
    Includes hierarchical direct reports structure.
    """
    full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    avatar_url = serializers.SerializerMethodField()
    direct_reports = serializers.SerializerMethodField()

    class Meta:
        model = Employee
        # Note: Employee uses 'id' as UUID primary key (inherited from TenantAwareModel)
        fields = [
            'id', 'employee_id', 'full_name', 'email',
            'job_title', 'department', 'avatar_url', 'direct_reports'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_avatar_url(self, obj):
        # Placeholder - can be extended to include actual avatar
        return None

    @extend_schema_field(OpenApiTypes.STR)
    def get_direct_reports(self, obj):
        # Recursive serialization for org chart
        depth = self.context.get('depth', 3)
        if depth <= 0:
            return []
        context = {**self.context, 'depth': depth - 1}
        return EmployeeOrgChartSerializer(
            obj.direct_reports.filter(status__in=['active', 'probation']),
            many=True,
            context=context
        ).data


# ==================== TIME OFF SERIALIZERS ====================

class TimeOffTypeSerializer(serializers.ModelSerializer):
    """Serializer for time off types (vacation, sick, personal, etc.)"""

    class Meta:
        model = TimeOffType
        fields = [
            'id', 'name', 'code', 'description', 'color',
            'is_accrued', 'accrual_rate', 'max_balance', 'max_carryover',
            'requires_approval', 'requires_documentation', 'min_notice_days',
            'is_paid', 'is_active'
        ]
        read_only_fields = ['id']


class TimeOffRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for time off requests with balance validation - COMPANY ONLY.
    Includes approval workflow fields.
    """
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    time_off_type = TimeOffTypeSerializer(read_only=True)
    time_off_type_id = serializers.PrimaryKeyRelatedField(
        queryset=TimeOffType.objects.filter(is_active=True),
        source='time_off_type',
        write_only=True
    )
    approver = UserMinimalSerializer(read_only=True)
    can_approve = serializers.SerializerMethodField()
    can_cancel = serializers.SerializerMethodField()
    tenant_type = serializers.CharField(source='employee.tenant.tenant_type', read_only=True)

    class Meta:
        model = TimeOffRequest
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            'time_off_type', 'time_off_type_id',
            'start_date', 'end_date', 'is_half_day', 'half_day_period',
            'total_days', 'reason', 'notes', 'status',
            'approver', 'approved_at', 'rejection_reason',
            'supporting_document',
            'can_approve', 'can_cancel',
            'created_at', 'updated_at', 'tenant_type'
        ]
        read_only_fields = [
            'id', 'uuid', 'status', 'approver', 'approved_at',
            'rejection_reason', 'created_at', 'updated_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_approve(self, obj):
        """Check if current user can approve this request"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        if obj.status != TimeOffRequest.RequestStatus.PENDING:
            return False
        # Manager or HR can approve
        try:
            user_employee = request.user.employee_record
            return (
                obj.employee.manager == user_employee or
                request.user.is_staff
            )
        except Employee.DoesNotExist:
            return request.user.is_staff

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_cancel(self, obj):
        """Check if current user can cancel this request"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        if obj.status not in [
            TimeOffRequest.RequestStatus.PENDING,
            TimeOffRequest.RequestStatus.APPROVED
        ]:
            return False
        # Own request or manager/HR can cancel
        return (
            obj.employee.user == request.user or
            request.user.is_staff
        )

    def validate(self, data):
        """Validate time off request data"""
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        time_off_type = data.get('time_off_type')
        employee = data.get('employee')
        is_half_day = data.get('is_half_day', False)

        # Validate date range
        if start_date and end_date:
            if start_date > end_date:
                raise serializers.ValidationError({
                    'end_date': 'End date must be after start date.'
                })

            # Calculate total days
            if is_half_day:
                data['total_days'] = Decimal('0.5')
            else:
                delta = (end_date - start_date).days + 1
                data['total_days'] = Decimal(str(delta))

        # Validate notice period
        if time_off_type and start_date:
            days_until = (start_date - timezone.now().date()).days
            if days_until < time_off_type.min_notice_days:
                raise serializers.ValidationError({
                    'start_date': f'This time off type requires at least {time_off_type.min_notice_days} days notice.'
                })

        # Validate balance for accrued time off
        if time_off_type and time_off_type.is_accrued and employee:
            total_days = data.get('total_days', Decimal('0'))
            if employee.pto_balance < total_days:
                raise serializers.ValidationError({
                    'total_days': f'Insufficient PTO balance. Available: {employee.pto_balance} days.'
                })

        # Validate documentation requirement
        if time_off_type and time_off_type.requires_documentation:
            if not data.get('supporting_document') and not self.instance:
                raise serializers.ValidationError({
                    'supporting_document': 'This time off type requires supporting documentation.'
                })

        return data


class TimeOffRequestApprovalSerializer(serializers.Serializer):
    """Serializer for approving/rejecting time off requests"""
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    rejection_reason = serializers.CharField(required=False, allow_blank=True)

    def validate(self, data):
        if data['action'] == 'reject' and not data.get('rejection_reason'):
            raise serializers.ValidationError({
                'rejection_reason': 'Rejection reason is required when rejecting a request.'
            })
        return data


# ==================== ONBOARDING SERIALIZERS ====================

class OnboardingTaskSerializer(serializers.ModelSerializer):
    """Serializer for individual onboarding tasks"""
    document_template_name = serializers.CharField(
        source='document_template.name',
        read_only=True,
        allow_null=True
    )

    class Meta:
        model = OnboardingTask
        fields = [
            'id', 'title', 'description', 'category', 'order',
            'assigned_to_role', 'due_days', 'is_required',
            'requires_signature', 'document_template', 'document_template_name'
        ]
        read_only_fields = ['id']


class OnboardingChecklistSerializer(serializers.ModelSerializer):
    """Serializer for onboarding checklist templates - COMPANY ONLY"""
    tasks = OnboardingTaskSerializer(many=True, read_only=True)
    tasks_count = serializers.SerializerMethodField()
    department_name = serializers.CharField(
        source='department.name',
        read_only=True,
        allow_null=True
    )
    tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)

    class Meta:
        model = OnboardingChecklist
        fields = [
            'id', 'name', 'description', 'employment_type',
            'department', 'department_name', 'is_active',
            'tasks', 'tasks_count',
            'created_at', 'updated_at', 'tenant_type'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    @extend_schema_field(OpenApiTypes.STR)
    def get_tasks_count(self, obj):
        return obj.tasks.count()


class OnboardingTaskProgressSerializer(serializers.ModelSerializer):
    """Serializer for tracking onboarding task completion"""
    task = OnboardingTaskSerializer(read_only=True)
    completed_by = UserMinimalSerializer(read_only=True)
    is_overdue = serializers.SerializerMethodField()

    class Meta:
        model = OnboardingTaskProgress
        fields = [
            'id', 'task', 'is_completed', 'completed_at',
            'completed_by', 'notes', 'due_date', 'is_overdue'
        ]
        read_only_fields = ['id', 'completed_at', 'completed_by']

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_overdue(self, obj):
        if obj.is_completed or not obj.due_date:
            return False
        return timezone.now().date() > obj.due_date


class EmployeeOnboardingSerializer(serializers.ModelSerializer):
    """
    Serializer for employee-specific onboarding progress.
    Includes task completion tracking.
    """
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    checklist = OnboardingChecklistSerializer(read_only=True)
    checklist_id = serializers.PrimaryKeyRelatedField(
        queryset=OnboardingChecklist.objects.filter(is_active=True),
        source='checklist',
        write_only=True
    )
    task_progress = OnboardingTaskProgressSerializer(many=True, read_only=True)
    completion_percentage = serializers.IntegerField(read_only=True)
    completed_tasks_count = serializers.SerializerMethodField()
    total_tasks_count = serializers.SerializerMethodField()
    is_complete = serializers.SerializerMethodField()

    class Meta:
        model = EmployeeOnboarding
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            'checklist', 'checklist_id',
            'start_date', 'target_completion_date', 'completed_at', 'notes',
            'task_progress', 'completion_percentage',
            'completed_tasks_count', 'total_tasks_count', 'is_complete'
        ]
        read_only_fields = ['id', 'uuid', 'completed_at']

    @extend_schema_field(OpenApiTypes.STR)
    def get_completed_tasks_count(self, obj):
        return obj.task_progress.filter(is_completed=True).count()

    @extend_schema_field(OpenApiTypes.STR)
    def get_total_tasks_count(self, obj):
        return obj.task_progress.count()

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_complete(self, obj):
        return obj.completion_percentage == 100

    @transaction.atomic
    def create(self, validated_data):
        """Create onboarding and initialize task progress entries"""
        onboarding = super().create(validated_data)

        # Create task progress entries for each task in the checklist
        if onboarding.checklist:
            for task in onboarding.checklist.tasks.all():
                due_date = None
                if onboarding.start_date and task.due_days:
                    from datetime import timedelta
                    due_date = onboarding.start_date + timedelta(days=task.due_days)

                OnboardingTaskProgress.objects.create(
                    onboarding=onboarding,
                    task=task,
                    due_date=due_date
                )

        return onboarding


class CompleteOnboardingTaskSerializer(serializers.Serializer):
    """Serializer for completing an onboarding task"""
    task_progress_id = serializers.IntegerField()
    notes = serializers.CharField(required=False, allow_blank=True)


# ==================== DOCUMENT SERIALIZERS ====================

class DocumentTemplateSerializer(serializers.ModelSerializer):
    """Serializer for HR document templates"""

    class Meta:
        model = DocumentTemplate
        fields = [
            'id', 'name', 'category', 'description', 'content',
            'placeholders', 'requires_signature', 'is_active', 'version',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class EmployeeDocumentSerializer(serializers.ModelSerializer):
    """
    Serializer for employee documents with file upload support.
    Handles e-signature workflow.
    """
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    template = DocumentTemplateSerializer(read_only=True)
    template_id = serializers.PrimaryKeyRelatedField(
        queryset=DocumentTemplate.objects.filter(is_active=True),
        source='template',
        write_only=True,
        required=False,
        allow_null=True
    )
    uploaded_by = UserMinimalSerializer(read_only=True)
    can_sign = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = EmployeeDocument
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            'template', 'template_id',
            'title', 'category', 'description',
            'file', 'file_type', 'file_size',
            'status', 'requires_signature',
            'signature_provider', 'signature_envelope_id',
            'signed_at', 'signed_document_url',
            'expires_at', 'is_expired',
            'uploaded_by', 'can_sign',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'uuid', 'file_type', 'file_size',
            'signature_envelope_id', 'signed_at', 'signed_document_url',
            'uploaded_by', 'created_at', 'updated_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_sign(self, obj):
        """Check if current user can sign this document"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        if obj.status != EmployeeDocument.DocumentStatus.PENDING_SIGNATURE:
            return False
        return obj.employee.user == request.user

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_expired(self, obj):
        if not obj.expires_at:
            return False
        return timezone.now().date() > obj.expires_at

    def validate_file(self, value):
        """Validate uploaded file"""
        if value:
            # Check file size (max 10MB)
            if value.size > 10 * 1024 * 1024:
                raise serializers.ValidationError(
                    "File size must be less than 10MB."
                )
            # Check file type
            allowed_types = [
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'image/jpeg',
                'image/png'
            ]
            if hasattr(value, 'content_type') and value.content_type not in allowed_types:
                raise serializers.ValidationError(
                    "Only PDF, Word documents, JPEG, and PNG files are allowed."
                )
        return value

    def create(self, validated_data):
        """Set file metadata on create"""
        file = validated_data.get('file')
        if file:
            validated_data['file_type'] = getattr(file, 'content_type', '')
            validated_data['file_size'] = file.size

        # Set uploaded_by from request
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['uploaded_by'] = request.user

        return super().create(validated_data)


class DocumentGenerateSerializer(serializers.Serializer):
    """Serializer for generating documents from templates"""
    template_id = serializers.PrimaryKeyRelatedField(
        queryset=DocumentTemplate.objects.filter(is_active=True)
    )
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all()
    )
    custom_data = serializers.JSONField(required=False, default=dict)


class DocumentSignatureSerializer(serializers.Serializer):
    """Serializer for document signing actions"""
    signature_data = serializers.CharField(required=False, help_text="Base64 signature image")
    signature_provider = serializers.ChoiceField(
        choices=['internal', 'docusign', 'hellosign'],
        default='internal'
    )


# ==================== OFFBOARDING SERIALIZERS ====================

class OffboardingSerializer(serializers.ModelSerializer):
    """
    Serializer for employee offboarding/separation process.
    Tracks completion of offboarding checklist items.
    """
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    processed_by = UserMinimalSerializer(read_only=True)
    is_complete = serializers.BooleanField(read_only=True)
    checklist_status = serializers.SerializerMethodField()
    days_until_last_day = serializers.SerializerMethodField()

    class Meta:
        model = Offboarding
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            'separation_type', 'reason', 'notice_date', 'last_working_day',
            'exit_interview_date', 'exit_interview_notes',
            # Checklist
            'knowledge_transfer_complete', 'equipment_returned',
            'access_revoked', 'final_paycheck_processed',
            'benefits_terminated', 'exit_interview_completed',
            'checklist_status',
            # Final Details
            'severance_offered', 'severance_amount', 'pto_payout_days',
            'eligible_for_rehire', 'rehire_notes',
            # Meta
            'processed_by', 'is_complete', 'days_until_last_day',
            'created_at', 'updated_at', 'completed_at'
        ]
        read_only_fields = [
            'id', 'uuid', 'processed_by', 'is_complete',
            'created_at', 'updated_at', 'completed_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_checklist_status(self, obj):
        """Return checklist completion status"""
        checklist_items = [
            ('knowledge_transfer', obj.knowledge_transfer_complete),
            ('equipment_returned', obj.equipment_returned),
            ('access_revoked', obj.access_revoked),
            ('final_paycheck', obj.final_paycheck_processed),
            ('benefits_terminated', obj.benefits_terminated),
            ('exit_interview', obj.exit_interview_completed),
        ]
        completed = sum(1 for _, status in checklist_items if status)
        return {
            'completed': completed,
            'total': len(checklist_items),
            'percentage': int((completed / len(checklist_items)) * 100),
            'items': {name: status for name, status in checklist_items}
        }

    @extend_schema_field(OpenApiTypes.STR)
    def get_days_until_last_day(self, obj):
        if not obj.last_working_day:
            return None
        delta = (obj.last_working_day - timezone.now().date()).days
        return max(0, delta)

    def validate(self, data):
        """Validate offboarding data"""
        notice_date = data.get('notice_date')
        last_working_day = data.get('last_working_day')

        if notice_date and last_working_day:
            if last_working_day < notice_date:
                raise serializers.ValidationError({
                    'last_working_day': 'Last working day must be after notice date.'
                })

        return data

    def create(self, validated_data):
        """Set processed_by from request"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['processed_by'] = request.user
        return super().create(validated_data)


class OffboardingStepSerializer(serializers.Serializer):
    """Serializer for completing individual offboarding steps"""
    step = serializers.ChoiceField(choices=[
        'knowledge_transfer',
        'equipment_returned',
        'access_revoked',
        'final_paycheck',
        'benefits_terminated',
        'exit_interview'
    ])
    completed = serializers.BooleanField()
    notes = serializers.CharField(required=False, allow_blank=True)


# ==================== PERFORMANCE REVIEW SERIALIZERS ====================

class PerformanceReviewSerializer(serializers.ModelSerializer):
    """
    Serializer for performance reviews - COMPANY ONLY.
    Supports different review workflows and states.
    """
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    reviewer = UserMinimalSerializer(read_only=True)
    reviewer_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(),
        source='reviewer',
        write_only=True,
        required=False,
        allow_null=True
    )
    can_submit_self_assessment = serializers.SerializerMethodField()
    can_submit_manager_review = serializers.SerializerMethodField()
    can_complete = serializers.SerializerMethodField()
    tenant_type = serializers.CharField(source='employee.tenant.tenant_type', read_only=True)

    class Meta:
        model = PerformanceReview
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            'reviewer', 'reviewer_id',
            'review_type', 'review_period_start', 'review_period_end', 'status',
            # Ratings
            'overall_rating', 'goals_met_percentage', 'competency_ratings',
            # Written Feedback
            'self_assessment', 'manager_feedback',
            'accomplishments', 'areas_for_improvement', 'goals_for_next_period',
            # Outcome
            'promotion_recommended', 'salary_increase_recommended',
            'salary_increase_percentage', 'pip_recommended',
            # Signatures
            'employee_signed_at', 'manager_signed_at',
            # Workflow
            'can_submit_self_assessment', 'can_submit_manager_review', 'can_complete',
            # Timestamps
            'created_at', 'updated_at', 'completed_at', 'tenant_type'
        ]
        read_only_fields = [
            'id', 'uuid', 'status', 'employee_signed_at', 'manager_signed_at',
            'created_at', 'updated_at', 'completed_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_submit_self_assessment(self, obj):
        """Check if employee can submit self-assessment"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return (
            obj.status == PerformanceReview.ReviewStatus.PENDING_SELF and
            obj.employee.user == request.user
        )

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_submit_manager_review(self, obj):
        """Check if manager can submit review"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        if obj.status != PerformanceReview.ReviewStatus.PENDING_MANAGER:
            return False
        try:
            user_employee = request.user.employee_record
            return obj.employee.manager == user_employee or request.user.is_staff
        except Employee.DoesNotExist:
            return request.user.is_staff

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_complete(self, obj):
        """Check if review can be completed"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return (
            obj.status == PerformanceReview.ReviewStatus.PENDING_APPROVAL and
            request.user.is_staff
        )

    def validate(self, data):
        """Validate performance review data"""
        start_date = data.get('review_period_start')
        end_date = data.get('review_period_end')

        if start_date and end_date:
            if start_date > end_date:
                raise serializers.ValidationError({
                    'review_period_end': 'End date must be after start date.'
                })

        # Validate rating range
        overall_rating = data.get('overall_rating')
        if overall_rating is not None and (overall_rating < 1 or overall_rating > 5):
            raise serializers.ValidationError({
                'overall_rating': 'Rating must be between 1 and 5.'
            })

        return data


class PerformanceReviewSubmitSerializer(serializers.Serializer):
    """Serializer for submitting self-assessment"""
    self_assessment = serializers.CharField()
    accomplishments = serializers.CharField(required=False, allow_blank=True)


class PerformanceReviewCompleteSerializer(serializers.Serializer):
    """Serializer for completing manager review"""
    overall_rating = serializers.IntegerField(min_value=1, max_value=5)
    goals_met_percentage = serializers.IntegerField(min_value=0, max_value=100)
    manager_feedback = serializers.CharField()
    areas_for_improvement = serializers.CharField(required=False, allow_blank=True)
    goals_for_next_period = serializers.CharField(required=False, allow_blank=True)
    promotion_recommended = serializers.BooleanField(default=False)
    salary_increase_recommended = serializers.BooleanField(default=False)
    salary_increase_percentage = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False, allow_null=True
    )
    pip_recommended = serializers.BooleanField(default=False)


# ==================== CALENDAR SERIALIZERS ====================

class TeamCalendarEventSerializer(serializers.Serializer):
    """Serializer for team calendar events"""
    id = serializers.IntegerField()
    title = serializers.CharField()
    start = serializers.DateField()
    end = serializers.DateField()
    type = serializers.ChoiceField(choices=['time_off', 'review', 'onboarding', 'offboarding'])
    employee = EmployeeMinimalSerializer()
    status = serializers.CharField()
    color = serializers.CharField(required=False)


# ==================== COMPENSATION SERIALIZERS ====================

class EmployeeCompensationSerializer(serializers.ModelSerializer):
    """
    Serializer for employee compensation records.
    Tracks salary history, bonuses, and equity.
    """
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    approved_by = UserMinimalSerializer(read_only=True)
    created_by = UserMinimalSerializer(read_only=True)
    salary_change_percentage = serializers.FloatField(read_only=True)
    total_target_compensation = serializers.DecimalField(
        max_digits=12, decimal_places=2, read_only=True
    )

    class Meta:
        model = EmployeeCompensation
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            # Dates
            'effective_date', 'end_date',
            # Base Compensation
            'base_salary', 'currency', 'pay_frequency',
            # Variable Compensation
            'bonus_target_percentage', 'bonus_type', 'commission_percentage',
            # Equity
            'equity_shares', 'equity_vest_start', 'equity_vest_end', 'equity_cliff_months',
            # Change Details
            'change_reason', 'change_notes', 'previous_salary',
            'salary_change_percentage', 'total_target_compensation',
            # Approval
            'approved_by', 'approved_at',
            # Audit
            'created_by', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'uuid', 'approved_by', 'approved_at',
            'created_by', 'created_at', 'updated_at'
        ]

    def create(self, validated_data):
        """Set created_by and calculate previous salary"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user

        # Get previous salary from most recent record
        employee = validated_data.get('employee')
        if employee:
            latest = EmployeeCompensation.objects.filter(
                employee=employee
            ).order_by('-effective_date').first()
            if latest:
                validated_data['previous_salary'] = latest.base_salary

        return super().create(validated_data)


class EmployeeCompensationListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing compensation history"""
    employee_name = serializers.CharField(source='employee.full_name', read_only=True)
    salary_change_percentage = serializers.FloatField(read_only=True)

    class Meta:
        model = EmployeeCompensation
        fields = [
            'id', 'uuid', 'employee_name', 'effective_date',
            'base_salary', 'currency', 'change_reason',
            'salary_change_percentage'
        ]
        read_only_fields = fields


# ==================== TIME OFF BALANCE SERIALIZERS ====================

class TimeOffBalanceSerializer(serializers.ModelSerializer):
    """Serializer for time off balance tracking"""
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    time_off_type = TimeOffTypeSerializer(read_only=True)
    time_off_type_id = serializers.PrimaryKeyRelatedField(
        queryset=TimeOffType.objects.filter(is_active=True),
        source='time_off_type',
        write_only=True
    )
    available_balance = serializers.SerializerMethodField()

    class Meta:
        model = TimeOffBalance
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            'time_off_type', 'time_off_type_id',
            'balance', 'accrued_this_year', 'used_this_year',
            'carried_over', 'pending', 'available_balance',
            'last_accrual_date', 'accrual_rate_override',
            'year', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'uuid', 'created_at', 'updated_at']

    @extend_schema_field(OpenApiTypes.STR)
    def get_available_balance(self, obj):
        """Calculate available balance (balance - pending)"""
        return obj.balance - obj.pending


class TimeOffBalanceSummarySerializer(serializers.Serializer):
    """Summary of all time off balances for an employee"""
    employee_id = serializers.IntegerField()
    employee_name = serializers.CharField()
    balances = serializers.ListField(child=serializers.DictField())
    total_available = serializers.DecimalField(max_digits=6, decimal_places=2)
    total_pending = serializers.DecimalField(max_digits=6, decimal_places=2)


class TimeOffAccrualLogSerializer(serializers.ModelSerializer):
    """Serializer for time off accrual audit logs"""
    employee_name = serializers.CharField(
        source='balance.employee.full_name', read_only=True
    )
    time_off_type = serializers.CharField(
        source='balance.time_off_type.name', read_only=True
    )

    class Meta:
        model = TimeOffAccrualLog
        fields = [
            'id', 'balance', 'employee_name', 'time_off_type',
            'accrual_date', 'amount', 'balance_after',
            'notes', 'created_at'
        ]
        read_only_fields = fields


class TimeOffBlackoutDateSerializer(serializers.ModelSerializer):
    """Serializer for time off blackout periods"""
    departments_list = serializers.SerializerMethodField()

    class Meta:
        model = TimeOffBlackoutDate
        fields = [
            'id', 'name', 'description',
            'start_date', 'end_date',
            'applies_to_all', 'departments', 'departments_list',
            'restriction_type', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    @extend_schema_field(OpenApiTypes.STR)
    def get_departments_list(self, obj):
        return list(obj.departments.values_list('name', flat=True))


# ==================== SKILL SERIALIZERS ====================

class SkillCategorySerializer(serializers.ModelSerializer):
    """Serializer for skill categories"""
    skills_count = serializers.SerializerMethodField()

    class Meta:
        model = SkillCategory
        fields = ['id', 'name', 'description', 'order', 'is_active', 'skills_count']
        read_only_fields = ['id']

    @extend_schema_field(OpenApiTypes.STR)
    def get_skills_count(self, obj):
        return obj.skills.filter(is_active=True).count()


class SkillSerializer(serializers.ModelSerializer):
    """Serializer for skills"""
    category_name = serializers.CharField(source='category.name', read_only=True, allow_null=True)

    class Meta:
        model = Skill
        fields = ['id', 'name', 'category', 'category_name', 'description', 'is_active']
        read_only_fields = ['id']


class EmployeeSkillSerializer(serializers.ModelSerializer):
    """Serializer for employee-skill associations"""
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    skill = SkillSerializer(read_only=True)
    skill_id = serializers.PrimaryKeyRelatedField(
        queryset=Skill.objects.filter(is_active=True),
        source='skill',
        write_only=True
    )
    verified_by = UserMinimalSerializer(read_only=True)
    proficiency_display = serializers.CharField(
        source='get_proficiency_display', read_only=True
    )

    class Meta:
        model = EmployeeSkill
        fields = [
            'id', 'employee', 'employee_id', 'skill', 'skill_id',
            'proficiency', 'proficiency_display', 'years_of_experience',
            'last_used_date', 'is_primary', 'verified', 'verified_by',
            'verified_date', 'notes', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'verified_by', 'verified_date', 'created_at', 'updated_at']

    def validate(self, data):
        """Ensure unique employee-skill combination"""
        employee = data.get('employee')
        skill = data.get('skill')
        if employee and skill:
            existing = EmployeeSkill.objects.filter(
                employee=employee, skill=skill
            )
            if self.instance:
                existing = existing.exclude(pk=self.instance.pk)
            if existing.exists():
                raise serializers.ValidationError({
                    'skill': 'This employee already has this skill recorded.'
                })
        return data


class EmployeeSkillListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing employee skills"""
    skill_name = serializers.CharField(source='skill.name', read_only=True)
    category = serializers.CharField(source='skill.category.name', read_only=True, allow_null=True)

    class Meta:
        model = EmployeeSkill
        fields = [
            'id', 'skill_name', 'category', 'proficiency',
            'years_of_experience', 'is_primary', 'verified'
        ]
        read_only_fields = fields


# ==================== CERTIFICATION SERIALIZERS ====================

class CertificationSerializer(serializers.ModelSerializer):
    """Serializer for employee certifications"""
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    verified_by = UserMinimalSerializer(read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    days_until_expiry = serializers.IntegerField(read_only=True)

    class Meta:
        model = Certification
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            'name', 'issuing_organization', 'credential_id', 'credential_url',
            'issue_date', 'expiry_date', 'is_expired', 'days_until_expiry',
            'is_verified', 'verified_by', 'verified_date',
            'certificate_file', 'is_active', 'notes',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'uuid', 'verified_by', 'verified_date',
            'created_at', 'updated_at'
        ]


class CertificationListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing certifications"""
    employee_name = serializers.CharField(source='employee.full_name', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    days_until_expiry = serializers.IntegerField(read_only=True)

    class Meta:
        model = Certification
        fields = [
            'id', 'employee_name', 'name', 'issuing_organization',
            'issue_date', 'expiry_date', 'is_expired', 'days_until_expiry',
            'is_verified'
        ]
        read_only_fields = fields


# ==================== ACTIVITY LOG SERIALIZERS ====================

class EmployeeActivityLogSerializer(serializers.ModelSerializer):
    """Serializer for employee activity audit logs"""
    employee = EmployeeMinimalSerializer(read_only=True)
    performed_by = UserMinimalSerializer(read_only=True)
    activity_type_display = serializers.CharField(
        source='get_activity_type_display', read_only=True
    )

    class Meta:
        model = EmployeeActivityLog
        fields = [
            'id', 'uuid', 'employee', 'activity_type', 'activity_type_display',
            'description', 'old_value', 'new_value', 'metadata',
            'performed_by', 'created_at'
        ]
        read_only_fields = fields


# ==================== GOAL SERIALIZERS ====================

class EmployeeGoalSerializer(serializers.ModelSerializer):
    """Serializer for employee goals and objectives"""
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    approved_by = UserMinimalSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)
    days_remaining = serializers.IntegerField(read_only=True)

    class Meta:
        model = EmployeeGoal
        fields = [
            'id', 'uuid', 'employee', 'employee_id',
            'title', 'description', 'key_results',
            'category', 'priority', 'priority_display',
            'start_date', 'target_date', 'completed_date',
            'status', 'status_display', 'progress_percentage',
            'weight', 'performance_review',
            'is_overdue', 'days_remaining',
            'approved_by', 'approved_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'uuid', 'approved_by', 'approved_at',
            'created_at', 'updated_at'
        ]

    def validate(self, data):
        """Validate goal data"""
        start_date = data.get('start_date')
        target_date = data.get('target_date')

        if start_date and target_date:
            if target_date < start_date:
                raise serializers.ValidationError({
                    'target_date': 'Target date must be after start date.'
                })

        return data


class EmployeeGoalListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing goals"""
    employee_name = serializers.CharField(source='employee.full_name', read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = EmployeeGoal
        fields = [
            'id', 'uuid', 'employee_name', 'title',
            'category', 'priority', 'status',
            'progress_percentage', 'target_date', 'is_overdue'
        ]
        read_only_fields = fields


class GoalProgressUpdateSerializer(serializers.Serializer):
    """Serializer for updating goal progress"""
    progress_percentage = serializers.IntegerField(min_value=0, max_value=100)
    key_results = serializers.JSONField(required=False)
    notes = serializers.CharField(required=False, allow_blank=True)


# ==================== ANALYTICS SERIALIZERS ====================

class TurnoverMetricsSerializer(serializers.Serializer):
    """Serializer for turnover analytics"""
    period_start = serializers.DateField()
    period_end = serializers.DateField()
    total_separations = serializers.IntegerField()
    voluntary_separations = serializers.IntegerField()
    involuntary_separations = serializers.IntegerField()
    average_headcount = serializers.FloatField()
    turnover_rate = serializers.FloatField()
    voluntary_turnover_rate = serializers.FloatField()
    retention_rate = serializers.FloatField()
    separations_by_department = serializers.DictField()
    separations_by_tenure = serializers.DictField()
    average_tenure_at_separation = serializers.FloatField()


class HeadcountTrendsSerializer(serializers.Serializer):
    """Serializer for headcount analytics"""
    period_start = serializers.DateField()
    period_end = serializers.DateField()
    current_headcount = serializers.IntegerField()
    headcount_change = serializers.IntegerField()
    new_hires = serializers.IntegerField()
    separations = serializers.IntegerField()
    net_change = serializers.IntegerField()
    trend_data = serializers.ListField()
    by_department = serializers.DictField()
    by_employment_type = serializers.DictField()


class CompensationAnalysisSerializer(serializers.Serializer):
    """Serializer for compensation analytics"""
    total_payroll = serializers.DecimalField(max_digits=14, decimal_places=2)
    average_salary = serializers.DecimalField(max_digits=12, decimal_places=2)
    median_salary = serializers.DecimalField(max_digits=12, decimal_places=2)
    min_salary = serializers.DecimalField(max_digits=12, decimal_places=2)
    max_salary = serializers.DecimalField(max_digits=12, decimal_places=2)
    salary_by_department = serializers.DictField()
    salary_ranges = serializers.DictField()
    recent_increases = serializers.IntegerField()
    average_increase_percentage = serializers.FloatField()


class TimeOffUtilizationSerializer(serializers.Serializer):
    """Serializer for time off utilization analytics"""
    period_start = serializers.DateField()
    period_end = serializers.DateField()
    total_days_taken = serializers.DecimalField(max_digits=10, decimal_places=2)
    total_days_available = serializers.DecimalField(max_digits=10, decimal_places=2)
    utilization_rate = serializers.FloatField()
    average_days_per_employee = serializers.DecimalField(max_digits=6, decimal_places=2)
    by_type = serializers.DictField()
    by_department = serializers.DictField()
    by_month = serializers.DictField()
    pending_requests = serializers.IntegerField()
    pending_days = serializers.DecimalField(max_digits=10, decimal_places=2)


class OnboardingMetricsSerializer(serializers.Serializer):
    """Serializer for onboarding analytics"""
    period_start = serializers.DateField()
    period_end = serializers.DateField()
    new_hires_count = serializers.IntegerField()
    onboarding_in_progress = serializers.IntegerField()
    onboarding_completed = serializers.IntegerField()
    average_completion_time_days = serializers.FloatField()
    completion_rate = serializers.FloatField()
    task_completion_rate = serializers.FloatField()
    overdue_tasks = serializers.IntegerField()
    by_department = serializers.DictField()


class WorkforceSummarySerializer(serializers.Serializer):
    """Serializer for workforce summary dashboard"""
    total_employees = serializers.IntegerField()
    active_employees = serializers.IntegerField()
    on_probation = serializers.IntegerField()
    on_leave = serializers.IntegerField()
    new_hires_30_days = serializers.IntegerField()
    upcoming_anniversaries = serializers.IntegerField()
    probation_ends_30_days = serializers.IntegerField()
    employees_off_today = serializers.IntegerField()
    pending_time_off_requests = serializers.IntegerField()
    average_tenure_years = serializers.FloatField()
    as_of_date = serializers.DateField()


# ==================== EXTENDED EMPLOYEE SERIALIZERS ====================

class EmployeeExtendedDetailSerializer(EmployeeDetailSerializer):
    """
    Extended employee detail serializer with all new fields.
    Includes skills, certifications, work authorization, etc.
    """
    emergency_contacts = serializers.JSONField(required=False)
    work_authorization_status = serializers.CharField(required=False, allow_blank=True)
    visa_type = serializers.CharField(required=False, allow_blank=True)
    visa_expiry = serializers.DateField(required=False, allow_null=True)
    work_permit_number = serializers.CharField(required=False, allow_blank=True)
    work_permit_expiry = serializers.DateField(required=False, allow_null=True)
    right_to_work_verified = serializers.BooleanField(required=False)
    skills_list = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    certifications_json = serializers.JSONField(source='certifications', required=False)
    next_review_date = serializers.DateField(required=False, allow_null=True)
    review_frequency_months = serializers.IntegerField(required=False)

    # Nested relations
    employee_skills = EmployeeSkillListSerializer(many=True, read_only=True)
    certification_records = CertificationListSerializer(many=True, read_only=True)
    goals = EmployeeGoalListSerializer(many=True, read_only=True)
    compensation_history = EmployeeCompensationListSerializer(many=True, read_only=True)

    class Meta(EmployeeDetailSerializer.Meta):
        fields = EmployeeDetailSerializer.Meta.fields + [
            # Extended emergency contacts
            'emergency_contacts',
            # Work authorization
            'work_authorization_status', 'visa_type', 'visa_expiry',
            'work_permit_number', 'work_permit_expiry',
            'right_to_work_verified',
            # Skills and certifications
            'skills_list', 'certifications_json',
            'employee_skills', 'certification_records',
            # Performance
            'next_review_date', 'review_frequency_months',
            'goals',
            # Compensation
            'compensation_history',
        ]


# ==================== PIP (PERFORMANCE IMPROVEMENT PLAN) SERIALIZERS ====================

class PIPMilestoneSerializer(serializers.ModelSerializer):
    """Serializer for PIP milestones/goals"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_overdue = serializers.SerializerMethodField()
    days_until_due = serializers.SerializerMethodField()

    class Meta:
        model = PIPMilestone
        fields = [
            'id', 'pip', 'title', 'description',
            'success_criteria', 'due_date', 'weight',
            'status', 'status_display', 'progress_notes',
            'completed_date', 'is_overdue', 'days_until_due',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'completed_date', 'created_at', 'updated_at']

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_overdue(self, obj):
        if obj.status in ['achieved', 'deferred'] or not obj.due_date:
            return False
        return timezone.now().date() > obj.due_date

    @extend_schema_field(OpenApiTypes.STR)
    def get_days_until_due(self, obj):
        if not obj.due_date:
            return None
        delta = (obj.due_date - timezone.now().date()).days
        return delta


class PIPMilestoneCreateSerializer(serializers.Serializer):
    """Serializer for creating milestones during PIP creation"""
    title = serializers.CharField(max_length=255)
    description = serializers.CharField(required=False, allow_blank=True)
    success_criteria = serializers.CharField()
    due_date = serializers.DateField(required=False, allow_null=True)
    weight = serializers.DecimalField(
        max_digits=4, decimal_places=2, default=1.0,
        min_value=Decimal('0.1'), max_value=Decimal('10.0')
    )


class PIPProgressNoteSerializer(serializers.ModelSerializer):
    """Serializer for PIP progress notes and check-ins"""
    author = UserMinimalSerializer(read_only=True)
    note_type_display = serializers.CharField(source='get_note_type_display', read_only=True)

    class Meta:
        model = PIPProgressNote
        fields = [
            'id', 'pip', 'note_type', 'note_type_display',
            'content', 'meeting_date', 'attendees', 'action_items',
            'employee_response', 'employee_responded_at',
            'attachments', 'author', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']


class PIPProgressNoteCreateSerializer(serializers.Serializer):
    """Serializer for creating progress notes"""
    note_type = serializers.ChoiceField(choices=[
        ('check_in', 'Check-in Meeting'),
        ('progress_update', 'Progress Update'),
        ('concern', 'Concern Raised'),
        ('achievement', 'Achievement'),
        ('extension', 'Extension'),
        ('formal_warning', 'Formal Warning'),
        ('other', 'Other'),
    ])
    content = serializers.CharField()
    meeting_date = serializers.DateField(required=False, allow_null=True)
    attendees = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    action_items = serializers.ListField(child=serializers.CharField(), required=False, default=list)


class PerformanceImprovementPlanListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing PIPs"""
    employee = EmployeeMinimalSerializer(read_only=True)
    initiated_by = UserMinimalSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    outcome_display = serializers.CharField(source='get_outcome_display', read_only=True)
    milestones_count = serializers.SerializerMethodField()
    progress_percentage = serializers.SerializerMethodField()
    days_remaining = serializers.SerializerMethodField()

    class Meta:
        model = PerformanceImprovementPlan
        fields = [
            'id', 'uuid', 'employee', 'status', 'status_display',
            'outcome', 'outcome_display', 'start_date', 'target_end_date',
            'next_check_in', 'initiated_by', 'milestones_count',
            'progress_percentage', 'days_remaining', 'created_at'
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_milestones_count(self, obj):
        return obj.milestones.count()

    @extend_schema_field(OpenApiTypes.STR)
    def get_progress_percentage(self, obj):
        total = obj.milestones.count()
        if total == 0:
            return 0
        completed = obj.milestones.filter(status='completed').count()
        return int((completed / total) * 100)

    @extend_schema_field(OpenApiTypes.STR)
    def get_days_remaining(self, obj):
        if not obj.target_end_date:
            return None
        delta = (obj.target_end_date - timezone.now().date()).days
        return max(0, delta)


class PerformanceImprovementPlanSerializer(serializers.ModelSerializer):
    """
    Full serializer for Performance Improvement Plans.
    Includes milestones and progress notes.
    """
    employee = EmployeeMinimalSerializer(read_only=True)
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all(),
        source='employee',
        write_only=True
    )
    initiated_by = UserMinimalSerializer(read_only=True)
    hr_representative = UserMinimalSerializer(read_only=True)
    milestones = PIPMilestoneSerializer(many=True, read_only=True)
    progress_notes = PIPProgressNoteSerializer(many=True, read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    outcome_display = serializers.CharField(source='get_outcome_display', read_only=True)

    # Computed fields
    progress_percentage = serializers.SerializerMethodField()
    days_remaining = serializers.SerializerMethodField()
    is_overdue = serializers.SerializerMethodField()
    can_activate = serializers.SerializerMethodField()
    can_extend = serializers.SerializerMethodField()
    can_complete = serializers.SerializerMethodField()

    class Meta:
        model = PerformanceImprovementPlan
        fields = [
            'id', 'uuid', 'employee', 'employee_id', 'initiated_by', 'hr_representative',
            # Details
            'reason', 'performance_concerns', 'goals', 'support_provided', 'expectations',
            # Timeline
            'start_date', 'target_end_date', 'actual_end_date',
            'check_in_frequency_days', 'next_check_in',
            # Status
            'status', 'status_display', 'outcome', 'outcome_display', 'final_rating',
            # Completion
            'final_assessment',
            # Signatures
            'employee_acknowledged_at', 'manager_signed_at', 'hr_signed_at',
            # Related
            'milestones', 'progress_notes',
            # Computed
            'progress_percentage', 'days_remaining', 'is_overdue',
            'can_activate', 'can_extend', 'can_complete',
            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'uuid', 'initiated_by', 'hr_representative',
            'actual_end_date', 'created_at', 'updated_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_progress_percentage(self, obj):
        total = obj.milestones.count()
        if total == 0:
            return 0
        achieved = obj.milestones.filter(status='achieved').count()
        return int((achieved / total) * 100)

    @extend_schema_field(OpenApiTypes.STR)
    def get_days_remaining(self, obj):
        if not obj.target_end_date:
            return None
        delta = (obj.target_end_date - timezone.now().date()).days
        return max(0, delta)

    @extend_schema_field(OpenApiTypes.STR)
    def get_is_overdue(self, obj):
        if obj.status in ['completed_success', 'completed_fail', 'terminated', 'cancelled']:
            return False
        if not obj.target_end_date:
            return False
        return timezone.now().date() > obj.target_end_date

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_activate(self, obj):
        return obj.status == 'draft'

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_extend(self, obj):
        return obj.status in ['active', 'extended']

    @extend_schema_field(OpenApiTypes.STR)
    def get_can_complete(self, obj):
        return obj.status in ['active', 'extended']

    def validate(self, data):
        """Validate PIP data"""
        start_date = data.get('start_date')
        target_end_date = data.get('target_end_date')

        if start_date and target_end_date:
            if target_end_date <= start_date:
                raise serializers.ValidationError({
                    'target_end_date': 'Target end date must be after start date.'
                })

        return data


class PIPCreateSerializer(serializers.Serializer):
    """Serializer for creating a new PIP with milestones"""
    employee_id = serializers.PrimaryKeyRelatedField(
        queryset=Employee.objects.all()
    )
    reason = serializers.CharField()
    performance_concerns = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list
    )
    support_provided = serializers.CharField(required=False, allow_blank=True, default='')
    expectations = serializers.CharField(required=False, allow_blank=True, default='')
    start_date = serializers.DateField()
    duration_days = serializers.IntegerField(min_value=14, max_value=365)
    check_in_frequency_days = serializers.IntegerField(
        min_value=1, max_value=30, default=7
    )
    goals = PIPMilestoneCreateSerializer(many=True, required=False, default=list)


class PIPActivateSerializer(serializers.Serializer):
    """Serializer for activating a PIP"""
    send_notification = serializers.BooleanField(default=True)
    notification_message = serializers.CharField(required=False, allow_blank=True)


class PIPExtendSerializer(serializers.Serializer):
    """Serializer for extending a PIP"""
    additional_days = serializers.IntegerField(min_value=7, max_value=90)
    reason = serializers.CharField()


class PIPCompleteSerializer(serializers.Serializer):
    """Serializer for completing a PIP"""
    outcome = serializers.ChoiceField(choices=[
        ('improved', 'Improved - Goals Met'),
        ('terminated', 'Terminated - Goals Not Met'),
        ('resigned', 'Employee Resigned'),
    ])
    final_assessment = serializers.CharField()
    final_rating = serializers.IntegerField(
        required=False, allow_null=True, min_value=1, max_value=5
    )


class PIPCheckInSerializer(serializers.Serializer):
    """Serializer for recording a PIP check-in"""
    content = serializers.CharField()
    meeting_date = serializers.DateField(required=False, allow_null=True)
    attendees = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    action_items = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    milestone_updates = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        default=list
    )


class PIPMilestoneUpdateSerializer(serializers.Serializer):
    """Serializer for updating milestone progress"""
    milestone_id = serializers.IntegerField()
    status = serializers.ChoiceField(
        choices=['pending', 'in_progress', 'completed', 'missed'],
        required=False
    )
    progress_notes = serializers.CharField(required=False, allow_blank=True)


class PIPSummarySerializer(serializers.Serializer):
    """Serializer for PIP summary data"""
    pip = PerformanceImprovementPlanListSerializer()
    total_milestones = serializers.IntegerField()
    completed_milestones = serializers.IntegerField()
    missed_milestones = serializers.IntegerField()
    in_progress_milestones = serializers.IntegerField()
    total_check_ins = serializers.IntegerField()
    average_rating = serializers.FloatField(allow_null=True)
    last_check_in_date = serializers.DateTimeField(allow_null=True)
    days_in_pip = serializers.IntegerField()
    days_remaining = serializers.IntegerField(allow_null=True)


class ManagerPIPDashboardSerializer(serializers.Serializer):
    """Serializer for manager's PIP dashboard"""
    active_pips = PerformanceImprovementPlanListSerializer(many=True)
    overdue_pips = PerformanceImprovementPlanListSerializer(many=True)
    upcoming_check_ins = serializers.ListField(child=serializers.DictField())
    recently_completed = PerformanceImprovementPlanListSerializer(many=True)
    stats = serializers.DictField()
