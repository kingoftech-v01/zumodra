"""
HR Core API Views - Human Resources REST API ViewSets and Views

This module provides DRF ViewSets for:
- Employee management with org chart and direct reports
- Time-off requests with approval workflows
- Onboarding checklists and task progress
- Document management with e-signatures
- Performance reviews with submission workflows
- Offboarding process tracking
"""

from datetime import timedelta
from decimal import Decimal

from django.db.models import Q, Count, Avg
from django.db import transaction
from django.utils import timezone
from django.shortcuts import get_object_or_404

from rest_framework import viewsets, permissions, status, filters, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend

from .models import (
    Employee, TimeOffType, TimeOffRequest,
    OnboardingChecklist, OnboardingTask, EmployeeOnboarding,
    OnboardingTaskProgress, DocumentTemplate, EmployeeDocument,
    Offboarding, PerformanceReview,
    # PIP models
    PerformanceImprovementPlan, PIPMilestone, PIPProgressNote,
)
from .serializers import (
    EmployeeMinimalSerializer, EmployeeListSerializer,
    EmployeeDetailSerializer, EmployeeCreateSerializer,
    EmployeeOrgChartSerializer,
    TimeOffTypeSerializer, TimeOffRequestSerializer,
    TimeOffRequestApprovalSerializer,
    OnboardingChecklistSerializer, OnboardingTaskSerializer,
    EmployeeOnboardingSerializer, OnboardingTaskProgressSerializer,
    CompleteOnboardingTaskSerializer,
    DocumentTemplateSerializer, EmployeeDocumentSerializer,
    DocumentGenerateSerializer, DocumentSignatureSerializer,
    OffboardingSerializer, OffboardingStepSerializer,
    PerformanceReviewSerializer, PerformanceReviewSubmitSerializer,
    PerformanceReviewCompleteSerializer,
    TeamCalendarEventSerializer,
    # PIP Serializers
    PerformanceImprovementPlanSerializer, PerformanceImprovementPlanListSerializer,
    PIPMilestoneSerializer, PIPProgressNoteSerializer,
    PIPCreateSerializer, PIPActivateSerializer, PIPExtendSerializer,
    PIPCompleteSerializer, PIPCheckInSerializer, PIPMilestoneUpdateSerializer,
    PIPSummarySerializer, ManagerPIPDashboardSerializer,
)
from .filters import (
    EmployeeFilter, TimeOffRequestFilter,
    EmployeeDocumentFilter, PerformanceReviewFilter
)
from tenants.decorators import require_tenant_type_api


# ==================== CUSTOM PERMISSIONS ====================

class IsHROrManager(permissions.BasePermission):
    """
    Permission for HR staff or direct managers.
    HR staff have full access; managers can access their direct reports.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True

        # For employee objects, check if user is the manager
        if isinstance(obj, Employee):
            try:
                user_employee = request.user.employee_record
                return obj.manager == user_employee or obj.user == request.user
            except Employee.DoesNotExist:
                return obj.user == request.user

        # For objects with employee field
        if hasattr(obj, 'employee'):
            try:
                user_employee = request.user.employee_record
                return (
                    obj.employee.manager == user_employee or
                    obj.employee.user == request.user
                )
            except Employee.DoesNotExist:
                return obj.employee.user == request.user

        return False


class IsEmployeeOrManager(permissions.BasePermission):
    """
    Permission for the employee themselves or their manager.
    """

    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True

        employee = obj if isinstance(obj, Employee) else getattr(obj, 'employee', None)
        if not employee:
            return False

        # Employee accessing their own data
        if employee.user == request.user:
            return True

        # Manager accessing direct report
        try:
            user_employee = request.user.employee_record
            return employee.manager == user_employee
        except Employee.DoesNotExist:
            return False


# ==================== EMPLOYEE VIEWSETS ====================

@require_tenant_type_api('company')
class EmployeeViewSet(viewsets.ModelViewSet):
    """
    API endpoint for employee management - COMPANY ONLY.

    Provides:
    - CRUD operations for employee records
    - Org chart representation
    - Direct reports listing
    - Employee termination workflow

    Filters:
    - status: Filter by employment status
    - employment_type: Filter by employment type
    - department: Filter by department ID
    - manager: Filter by manager ID
    - search: Search by name, email, employee_id
    """
    queryset = Employee.objects.select_related(
        'user', 'department', 'manager', 'manager__user'
    ).prefetch_related('direct_reports')
    permission_classes = [permissions.IsAuthenticated, IsHROrManager]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = EmployeeFilter
    search_fields = [
        'user__first_name', 'user__last_name', 'user__email',
        'employee_id', 'job_title'
    ]
    ordering_fields = ['hire_date', 'start_date', 'created_at', 'employee_id']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return EmployeeListSerializer
        if self.action == 'create':
            return EmployeeCreateSerializer
        if self.action == 'minimal':
            return EmployeeMinimalSerializer
        if self.action == 'org_chart':
            return EmployeeOrgChartSerializer
        return EmployeeDetailSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user

        # HR/Admin can see all employees
        if user.is_staff:
            return queryset

        # Regular users can only see themselves and direct reports
        try:
            user_employee = user.employee_record
            return queryset.filter(
                Q(id=user_employee.id) |
                Q(manager=user_employee)
            )
        except Employee.DoesNotExist:
            return queryset.filter(user=user)

    @action(detail=False, methods=['get'])
    def minimal(self, request):
        """
        Get minimal employee list for dropdowns and references.
        Only active employees are included.
        """
        queryset = self.get_queryset().filter(
            status__in=['active', 'probation']
        )
        serializer = EmployeeMinimalSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Get current user's employee record.
        """
        try:
            employee = request.user.employee_record
            serializer = EmployeeDetailSerializer(
                employee,
                context={'request': request}
            )
            return Response(serializer.data)
        except Employee.DoesNotExist:
            return Response(
                {'detail': 'No employee record found for current user.'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['get'])
    def direct_reports(self, request, pk=None):
        """
        Get direct reports for an employee.
        """
        employee = self.get_object()
        reports = employee.direct_reports.filter(
            status__in=['active', 'probation', 'on_leave']
        )
        serializer = EmployeeListSerializer(
            reports,
            many=True,
            context={'request': request}
        )
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def org_chart(self, request):
        """
        Get organizational chart starting from top-level employees.
        Returns hierarchical structure of employees.
        """
        # Get top-level employees (no manager)
        top_employees = self.get_queryset().filter(
            manager__isnull=True,
            status__in=['active', 'probation']
        )
        serializer = EmployeeOrgChartSerializer(
            top_employees,
            many=True,
            context={'request': request, 'depth': 5}
        )
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def terminate(self, request, pk=None):
        """
        Initiate employee termination.
        Creates offboarding record and updates employee status.
        """
        employee = self.get_object()

        # Validate request data
        separation_type = request.data.get('separation_type')
        last_working_day = request.data.get('last_working_day')
        reason = request.data.get('reason', '')

        if not separation_type or not last_working_day:
            return Response(
                {'detail': 'separation_type and last_working_day are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if already terminated or has offboarding
        if employee.status in ['terminated', 'resigned']:
            return Response(
                {'detail': 'Employee is already terminated.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if hasattr(employee, 'offboarding'):
            return Response(
                {'detail': 'Offboarding already exists for this employee.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            # Update employee status
            employee.status = Employee.EmploymentStatus.NOTICE_PERIOD
            employee.last_working_day = last_working_day
            employee.save()

            # Create offboarding record
            offboarding = Offboarding.objects.create(
                employee=employee,
                separation_type=separation_type,
                reason=reason,
                notice_date=timezone.now().date(),
                last_working_day=last_working_day,
                processed_by=request.user
            )

        serializer = OffboardingSerializer(
            offboarding,
            context={'request': request}
        )
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'])
    def transfer(self, request, pk=None):
        """
        Transfer employee to new department/location/team/manager.
        Records the transfer in activity log.
        """
        employee = self.get_object()

        from .serializers import EmployeeTransferSerializer
        serializer = EmployeeTransferSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        effective_date = serializer.validated_data['effective_date']
        reason = serializer.validated_data['reason']

        # Record old values for audit
        old_values = {
            'department': employee.department.name if employee.department else None,
            'manager': employee.manager.full_name if employee.manager else None,
            'work_location': employee.work_location,
            'team': employee.team
        }

        # Apply changes
        new_values = {}
        if serializer.validated_data.get('new_department_id'):
            employee.department = serializer.validated_data['new_department_id']
            new_values['department'] = employee.department.name

        if serializer.validated_data.get('new_manager_id'):
            employee.manager = serializer.validated_data['new_manager_id']
            new_values['manager'] = employee.manager.full_name

        if serializer.validated_data.get('new_work_location'):
            employee.work_location = serializer.validated_data['new_work_location']
            new_values['work_location'] = employee.work_location

        if serializer.validated_data.get('new_team'):
            employee.team = serializer.validated_data['new_team']
            new_values['team'] = employee.team

        employee.save()

        # Return updated employee
        detail_serializer = EmployeeDetailSerializer(
            employee,
            context={'request': request}
        )
        return Response({
            'employee': detail_serializer.data,
            'transfer_details': {
                'effective_date': effective_date,
                'reason': reason,
                'old_values': old_values,
                'new_values': new_values
            }
        })

    @action(detail=True, methods=['post'])
    def promote(self, request, pk=None):
        """
        Promote employee with optional salary adjustment.
        Records the promotion in activity log.
        """
        employee = self.get_object()

        from .serializers import EmployeePromoteSerializer
        serializer = EmployeePromoteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        effective_date = serializer.validated_data['effective_date']
        reason = serializer.validated_data['reason']

        # Record old values
        old_values = {
            'job_title': employee.job_title,
            'base_salary': str(employee.base_salary) if employee.base_salary else None,
            'department': employee.department.name if employee.department else None,
            'manager': employee.manager.full_name if employee.manager else None
        }

        # Apply promotion changes
        employee.job_title = serializer.validated_data['new_job_title']

        if serializer.validated_data.get('new_department_id'):
            employee.department = serializer.validated_data['new_department_id']

        if serializer.validated_data.get('new_manager_id'):
            employee.manager = serializer.validated_data['new_manager_id']

        if serializer.validated_data.get('new_base_salary'):
            employee.base_salary = serializer.validated_data['new_base_salary']

        employee.save()

        new_values = {
            'job_title': employee.job_title,
            'base_salary': str(employee.base_salary) if employee.base_salary else None,
            'department': employee.department.name if employee.department else None,
            'manager': employee.manager.full_name if employee.manager else None
        }

        # Return updated employee
        detail_serializer = EmployeeDetailSerializer(
            employee,
            context={'request': request}
        )
        return Response({
            'employee': detail_serializer.data,
            'promotion_details': {
                'effective_date': effective_date,
                'reason': reason,
                'old_values': old_values,
                'new_values': new_values,
                'performance_review_id': serializer.validated_data.get('performance_review_id')
            }
        })

    @action(detail=True, methods=['get', 'post'])
    def compensation(self, request, pk=None):
        """
        GET: Retrieve employee compensation details.
        POST: Update employee compensation (requires HR permission).
        """
        employee = self.get_object()

        if request.method == 'GET':
            from .serializers import EmployeeCompensationSerializer
            serializer = EmployeeCompensationSerializer(
                employee,
                context={'request': request}
            )
            return Response(serializer.data)

        # POST - Update compensation
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only HR staff can update compensation.'},
                status=status.HTTP_403_FORBIDDEN
            )

        from .serializers import CompensationUpdateSerializer
        serializer = CompensationUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        old_salary = employee.base_salary
        employee.base_salary = serializer.validated_data['new_base_salary']
        employee.save(update_fields=['base_salary'])

        return Response({
            'employee_id': employee.id,
            'previous_salary': str(old_salary) if old_salary else None,
            'new_salary': str(employee.base_salary),
            'effective_date': serializer.validated_data['effective_date'],
            'change_reason': serializer.validated_data['change_reason'],
            'change_type': serializer.validated_data['change_type']
        })

    @action(detail=True, methods=['get', 'post'])
    def documents(self, request, pk=None):
        """
        GET: List all documents for the employee.
        POST: Upload a new document for the employee.
        """
        employee = self.get_object()

        if request.method == 'GET':
            documents = EmployeeDocument.objects.filter(
                employee=employee
            ).select_related('template', 'uploaded_by')
            serializer = EmployeeDocumentSerializer(
                documents,
                many=True,
                context={'request': request}
            )
            return Response(serializer.data)

        # POST - Upload new document
        serializer = EmployeeDocumentSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save(employee=employee, uploaded_by=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)



# ==================== TIME OFF VIEWSETS ====================

@require_tenant_type_api('company')
class TimeOffTypeViewSet(viewsets.ModelViewSet):
    """
    API endpoint for time off types - COMPANY ONLY.
    Only HR/Admin can create/update/delete.
    """
    queryset = TimeOffType.objects.all()
    serializer_class = TimeOffTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'code']
    ordering_fields = ['name', 'code']
    ordering = ['name']

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAdminUser()]
        return super().get_permissions()

    def get_queryset(self):
        queryset = super().get_queryset()
        # Only show active types for non-staff
        if not self.request.user.is_staff:
            queryset = queryset.filter(is_active=True)
        return queryset


@require_tenant_type_api('company')
class TimeOffRequestViewSet(viewsets.ModelViewSet):
    """
    API endpoint for time off requests - COMPANY ONLY.

    Provides:
    - CRUD operations for time off requests
    - Approval/rejection workflow
    - Cancellation support
    - Balance validation

    Filters:
    - status: Filter by request status
    - employee: Filter by employee ID
    - time_off_type: Filter by time off type
    - start_date_from/to: Filter by date range
    """
    queryset = TimeOffRequest.objects.select_related(
        'employee', 'employee__user', 'time_off_type', 'approver'
    )
    serializer_class = TimeOffRequestSerializer
    permission_classes = [permissions.IsAuthenticated, IsEmployeeOrManager]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_class = TimeOffRequestFilter
    ordering_fields = ['start_date', 'created_at', 'status']
    ordering = ['-created_at']

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user

        # HR/Admin can see all requests
        if user.is_staff:
            return queryset

        # Regular users see their own requests and direct reports' requests
        try:
            user_employee = user.employee_record
            return queryset.filter(
                Q(employee=user_employee) |
                Q(employee__manager=user_employee)
            )
        except Employee.DoesNotExist:
            return queryset.none()

    def perform_create(self, serializer):
        # Set employee to current user's employee record
        try:
            employee = self.request.user.employee_record
            serializer.save(employee=employee)
        except Employee.DoesNotExist:
            raise serializers.ValidationError(
                "You must have an employee record to create time off requests."
            )

    @action(detail=False, methods=['get'])
    def my_requests(self, request):
        """Get current user's time off requests."""
        try:
            employee = request.user.employee_record
            queryset = self.get_queryset().filter(employee=employee)
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Employee.DoesNotExist:
            return Response([])

    @action(detail=False, methods=['get'])
    def pending_approval(self, request):
        """Get requests pending approval by current user (manager)."""
        try:
            user_employee = request.user.employee_record
            queryset = self.get_queryset().filter(
                employee__manager=user_employee,
                status=TimeOffRequest.RequestStatus.PENDING
            )
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Employee.DoesNotExist:
            return Response([])

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve a time off request."""
        time_off_request = self.get_object()

        if time_off_request.status != TimeOffRequest.RequestStatus.PENDING:
            return Response(
                {'detail': 'Only pending requests can be approved.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check permission
        try:
            user_employee = request.user.employee_record
            is_manager = time_off_request.employee.manager == user_employee
        except Employee.DoesNotExist:
            is_manager = False

        if not (is_manager or request.user.is_staff):
            return Response(
                {'detail': 'You do not have permission to approve this request.'},
                status=status.HTTP_403_FORBIDDEN
            )

        time_off_request.approve(request.user)
        serializer = self.get_serializer(time_off_request)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject a time off request."""
        time_off_request = self.get_object()

        if time_off_request.status != TimeOffRequest.RequestStatus.PENDING:
            return Response(
                {'detail': 'Only pending requests can be rejected.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate rejection reason
        approval_serializer = TimeOffRequestApprovalSerializer(data={
            'action': 'reject',
            'rejection_reason': request.data.get('rejection_reason', '')
        })
        approval_serializer.is_valid(raise_exception=True)

        # Check permission
        try:
            user_employee = request.user.employee_record
            is_manager = time_off_request.employee.manager == user_employee
        except Employee.DoesNotExist:
            is_manager = False

        if not (is_manager or request.user.is_staff):
            return Response(
                {'detail': 'You do not have permission to reject this request.'},
                status=status.HTTP_403_FORBIDDEN
            )

        time_off_request.reject(
            request.user,
            approval_serializer.validated_data.get('rejection_reason', '')
        )
        serializer = self.get_serializer(time_off_request)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a time off request."""
        time_off_request = self.get_object()

        if time_off_request.status not in [
            TimeOffRequest.RequestStatus.PENDING,
            TimeOffRequest.RequestStatus.APPROVED
        ]:
            return Response(
                {'detail': 'This request cannot be cancelled.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Only the employee or manager/HR can cancel
        is_own_request = time_off_request.employee.user == request.user
        if not (is_own_request or request.user.is_staff):
            return Response(
                {'detail': 'You do not have permission to cancel this request.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # If approved, restore PTO balance
        if time_off_request.status == TimeOffRequest.RequestStatus.APPROVED:
            if time_off_request.time_off_type.is_accrued:
                time_off_request.employee.pto_balance += time_off_request.total_days
                time_off_request.employee.save(update_fields=['pto_balance'])

        time_off_request.status = TimeOffRequest.RequestStatus.CANCELLED
        time_off_request.save()

        serializer = self.get_serializer(time_off_request)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def balance(self, request):
        """Get current user's time off balances."""
        try:
            employee = request.user.employee_record
            return Response({
                'pto_balance': float(employee.pto_balance),
                'sick_leave_balance': float(employee.sick_leave_balance)
            })
        except Employee.DoesNotExist:
            return Response(
                {'detail': 'No employee record found.'},
                status=status.HTTP_404_NOT_FOUND
            )


# ==================== ONBOARDING VIEWSETS ====================

@require_tenant_type_api('company')
class OnboardingChecklistViewSet(viewsets.ModelViewSet):
    """
    API endpoint for onboarding checklist templates - COMPANY ONLY.
    Only HR/Admin can create/update/delete.
    """
    queryset = OnboardingChecklist.objects.prefetch_related('tasks')
    serializer_class = OnboardingChecklistSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['is_active', 'employment_type', 'department']
    search_fields = ['name', 'description']

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAdminUser()]
        return super().get_permissions()

    @action(detail=True, methods=['post'])
    def add_task(self, request, pk=None):
        """Add a task to the checklist."""
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only HR staff can add tasks.'},
                status=status.HTTP_403_FORBIDDEN
            )

        checklist = self.get_object()
        serializer = OnboardingTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(checklist=checklist)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


@require_tenant_type_api('company')
class OnboardingTaskViewSet(viewsets.ModelViewSet):
    """
    API endpoint for onboarding tasks.
    """
    queryset = OnboardingTask.objects.select_related('checklist', 'document_template')
    serializer_class = OnboardingTaskSerializer
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['checklist', 'category', 'is_required']
    ordering_fields = ['order', 'due_days']
    ordering = ['checklist', 'order']


@require_tenant_type_api('company')
class EmployeeOnboardingViewSet(viewsets.ModelViewSet):
    """
    API endpoint for employee onboarding progress.

    Provides:
    - CRUD operations for employee onboarding
    - Task completion tracking
    - Progress reporting
    """
    queryset = EmployeeOnboarding.objects.select_related(
        'employee', 'employee__user', 'checklist'
    ).prefetch_related('task_progress', 'task_progress__task')
    serializer_class = EmployeeOnboardingSerializer
    permission_classes = [permissions.IsAuthenticated, IsEmployeeOrManager]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['employee', 'checklist']
    ordering_fields = ['start_date', 'target_completion_date']
    ordering = ['-start_date']

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user

        # HR/Admin can see all
        if user.is_staff:
            return queryset

        # Regular users see their own and direct reports
        try:
            user_employee = user.employee_record
            return queryset.filter(
                Q(employee=user_employee) |
                Q(employee__manager=user_employee)
            )
        except Employee.DoesNotExist:
            return queryset.none()

    @action(detail=True, methods=['post'])
    def complete_task(self, request, pk=None):
        """Complete an onboarding task."""
        onboarding = self.get_object()

        serializer = CompleteOnboardingTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        task_progress_id = serializer.validated_data['task_progress_id']
        notes = serializer.validated_data.get('notes', '')

        try:
            task_progress = onboarding.task_progress.get(id=task_progress_id)
        except OnboardingTaskProgress.DoesNotExist:
            return Response(
                {'detail': 'Task not found in this onboarding.'},
                status=status.HTTP_404_NOT_FOUND
            )

        if task_progress.is_completed:
            return Response(
                {'detail': 'Task is already completed.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        task_progress.complete(request.user)
        if notes:
            task_progress.notes = notes
            task_progress.save()

        # Check if all tasks are complete
        if onboarding.completion_percentage == 100:
            onboarding.completed_at = timezone.now()
            onboarding.save()

        serializer = OnboardingTaskProgressSerializer(task_progress)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def progress(self, request, pk=None):
        """Get detailed progress for an onboarding."""
        onboarding = self.get_object()
        task_progress = onboarding.task_progress.select_related('task').all()

        return Response({
            'completion_percentage': onboarding.completion_percentage,
            'completed_tasks': task_progress.filter(is_completed=True).count(),
            'total_tasks': task_progress.count(),
            'overdue_tasks': sum(1 for tp in task_progress if not tp.is_completed and tp.due_date and tp.due_date < timezone.now().date()),
            'tasks': OnboardingTaskProgressSerializer(task_progress, many=True).data
        })


# ==================== DOCUMENT VIEWSETS ====================

@require_tenant_type_api('company')
class DocumentTemplateViewSet(viewsets.ModelViewSet):
    """
    API endpoint for document templates - COMPANY ONLY.
    Only HR/Admin can create/update/delete.
    """
    queryset = DocumentTemplate.objects.all()
    serializer_class = DocumentTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['category', 'is_active', 'requires_signature']
    search_fields = ['name', 'description']

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAdminUser()]
        return super().get_permissions()

    @action(detail=True, methods=['post'])
    def generate_for_employee(self, request, pk=None):
        """
        Generate a document from template for a specific employee.
        """
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only HR staff can generate documents.'},
                status=status.HTTP_403_FORBIDDEN
            )

        template = self.get_object()

        serializer = DocumentGenerateSerializer(data={
            'template_id': template.id,
            'employee_id': request.data.get('employee_id'),
            'custom_data': request.data.get('custom_data', {})
        })
        serializer.is_valid(raise_exception=True)

        employee = serializer.validated_data['employee_id']
        custom_data = serializer.validated_data.get('custom_data', {})

        # Build placeholder context
        context = {
            'employee_name': employee.full_name,
            'employee_id': employee.employee_id,
            'job_title': employee.job_title,
            'department': employee.department.name if employee.department else '',
            'hire_date': str(employee.hire_date),
            'start_date': str(employee.start_date) if employee.start_date else '',
            **custom_data
        }

        # Replace placeholders in content
        content = template.content
        for key, value in context.items():
            content = content.replace(f'{{{{{key}}}}}', str(value))

        # Create employee document
        document = EmployeeDocument.objects.create(
            employee=employee,
            template=template,
            title=f"{template.name} - {employee.full_name}",
            category=template.category,
            description=f"Generated from template: {template.name}",
            requires_signature=template.requires_signature,
            status=EmployeeDocument.DocumentStatus.DRAFT,
            uploaded_by=request.user
        )

        # In production, you would generate a PDF here and save it
        # For now, return the document record
        doc_serializer = EmployeeDocumentSerializer(
            document,
            context={'request': request}
        )
        return Response(doc_serializer.data, status=status.HTTP_201_CREATED)


@require_tenant_type_api('company')
class EmployeeDocumentViewSet(viewsets.ModelViewSet):
    """
    API endpoint for employee documents - COMPANY ONLY.

    Provides:
    - CRUD operations for documents
    - File upload support
    - E-signature workflow (sign, request_signature)
    """
    queryset = EmployeeDocument.objects.select_related(
        'employee', 'employee__user', 'template', 'uploaded_by'
    )
    serializer_class = EmployeeDocumentSerializer
    permission_classes = [permissions.IsAuthenticated, IsEmployeeOrManager]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = EmployeeDocumentFilter
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'title', 'status']
    ordering = ['-created_at']

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user

        # HR/Admin can see all
        if user.is_staff:
            return queryset

        # Regular users see their own documents
        try:
            user_employee = user.employee_record
            return queryset.filter(
                Q(employee=user_employee) |
                Q(employee__manager=user_employee)
            )
        except Employee.DoesNotExist:
            return queryset.none()

    @action(detail=False, methods=['get'])
    def my_documents(self, request):
        """Get current user's documents."""
        try:
            employee = request.user.employee_record
            queryset = self.get_queryset().filter(employee=employee)
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Employee.DoesNotExist:
            return Response([])

    @action(detail=False, methods=['get'])
    def pending_signatures(self, request):
        """Get documents pending user's signature."""
        try:
            employee = request.user.employee_record
            queryset = self.get_queryset().filter(
                employee=employee,
                status=EmployeeDocument.DocumentStatus.PENDING_SIGNATURE
            )
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Employee.DoesNotExist:
            return Response([])

    @action(detail=True, methods=['post'])
    def sign(self, request, pk=None):
        """Sign a document."""
        document = self.get_object()

        if document.status != EmployeeDocument.DocumentStatus.PENDING_SIGNATURE:
            return Response(
                {'detail': 'Document is not pending signature.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if document.employee.user != request.user:
            return Response(
                {'detail': 'Only the employee can sign this document.'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = DocumentSignatureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        document.status = EmployeeDocument.DocumentStatus.SIGNED
        document.signed_at = timezone.now()
        document.signature_provider = serializer.validated_data.get(
            'signature_provider', 'internal'
        )
        document.save()

        doc_serializer = self.get_serializer(document)
        return Response(doc_serializer.data)

    @action(detail=True, methods=['post'])
    def request_signature(self, request, pk=None):
        """Request signature from employee."""
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only HR staff can request signatures.'},
                status=status.HTTP_403_FORBIDDEN
            )

        document = self.get_object()

        if document.status != EmployeeDocument.DocumentStatus.DRAFT:
            return Response(
                {'detail': 'Only draft documents can be sent for signature.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not document.requires_signature:
            return Response(
                {'detail': 'This document does not require a signature.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        document.status = EmployeeDocument.DocumentStatus.PENDING_SIGNATURE
        document.save()

        # In production, send notification email to employee
        serializer = self.get_serializer(document)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def archive(self, request, pk=None):
        """Archive a document."""
        document = self.get_object()
        document.status = EmployeeDocument.DocumentStatus.ARCHIVED
        document.save()

        serializer = self.get_serializer(document)
        return Response(serializer.data)


# ==================== OFFBOARDING VIEWSETS ====================

@require_tenant_type_api('company')
class OffboardingViewSet(viewsets.ModelViewSet):
    """
    API endpoint for employee offboarding.

    Provides:
    - CRUD operations for offboarding records
    - Checklist step completion
    - Progress tracking
    """
    queryset = Offboarding.objects.select_related(
        'employee', 'employee__user', 'processed_by'
    )
    serializer_class = OffboardingSerializer
    permission_classes = [permissions.IsAuthenticated, IsHROrManager]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['separation_type', 'eligible_for_rehire']
    ordering_fields = ['last_working_day', 'created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        queryset = super().get_queryset()

        # Only HR/Admin should access offboarding records
        if not self.request.user.is_staff:
            return queryset.none()

        return queryset

    @action(detail=True, methods=['post'])
    def complete_step(self, request, pk=None):
        """Complete an offboarding checklist step."""
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only HR staff can complete offboarding steps.'},
                status=status.HTTP_403_FORBIDDEN
            )

        offboarding = self.get_object()

        serializer = OffboardingStepSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        step = serializer.validated_data['step']
        completed = serializer.validated_data['completed']

        step_field_map = {
            'knowledge_transfer': 'knowledge_transfer_complete',
            'equipment_returned': 'equipment_returned',
            'access_revoked': 'access_revoked',
            'final_paycheck': 'final_paycheck_processed',
            'benefits_terminated': 'benefits_terminated',
            'exit_interview': 'exit_interview_completed',
        }

        field_name = step_field_map.get(step)
        if field_name:
            setattr(offboarding, field_name, completed)
            offboarding.save()

            # Check if all steps complete
            if offboarding.is_complete and not offboarding.completed_at:
                offboarding.completed_at = timezone.now()
                offboarding.employee.status = Employee.EmploymentStatus.TERMINATED
                offboarding.employee.termination_date = timezone.now().date()
                offboarding.employee.save()
                offboarding.save()

        off_serializer = self.get_serializer(offboarding)
        return Response(off_serializer.data)

    @action(detail=True, methods=['post'])
    def record_exit_interview(self, request, pk=None):
        """Record exit interview notes."""
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only HR staff can record exit interviews.'},
                status=status.HTTP_403_FORBIDDEN
            )

        offboarding = self.get_object()

        notes = request.data.get('notes', '')
        interview_date = request.data.get('interview_date')

        if interview_date:
            offboarding.exit_interview_date = interview_date
        else:
            offboarding.exit_interview_date = timezone.now().date()

        offboarding.exit_interview_notes = notes
        offboarding.exit_interview_completed = True
        offboarding.save()

        serializer = self.get_serializer(offboarding)
        return Response(serializer.data)


# ==================== PERFORMANCE REVIEW VIEWSETS ====================

@require_tenant_type_api('company')
class PerformanceReviewViewSet(viewsets.ModelViewSet):
    """
    API endpoint for performance reviews.

    Provides:
    - CRUD operations for reviews
    - Self-assessment submission
    - Manager review completion
    - HR approval workflow
    """
    queryset = PerformanceReview.objects.select_related(
        'employee', 'employee__user', 'reviewer'
    )
    serializer_class = PerformanceReviewSerializer
    permission_classes = [permissions.IsAuthenticated, IsEmployeeOrManager]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_class = PerformanceReviewFilter
    ordering_fields = ['review_period_end', 'created_at', 'status']
    ordering = ['-review_period_end']

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user

        # HR/Admin can see all
        if user.is_staff:
            return queryset

        # Regular users see their own and direct reports
        try:
            user_employee = user.employee_record
            return queryset.filter(
                Q(employee=user_employee) |
                Q(employee__manager=user_employee) |
                Q(reviewer=user)
            )
        except Employee.DoesNotExist:
            return queryset.filter(reviewer=user)

    @action(detail=False, methods=['get'])
    def my_reviews(self, request):
        """Get current user's performance reviews."""
        try:
            employee = request.user.employee_record
            queryset = self.get_queryset().filter(employee=employee)
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Employee.DoesNotExist:
            return Response([])

    @action(detail=False, methods=['get'])
    def pending_my_action(self, request):
        """Get reviews pending action from current user."""
        try:
            user_employee = request.user.employee_record
        except Employee.DoesNotExist:
            user_employee = None

        queryset = self.get_queryset()

        # Self-assessment pending
        pending_self = []
        if user_employee:
            pending_self = queryset.filter(
                employee=user_employee,
                status=PerformanceReview.ReviewStatus.PENDING_SELF
            )

        # Manager review pending
        pending_manager = []
        if user_employee:
            pending_manager = queryset.filter(
                employee__manager=user_employee,
                status=PerformanceReview.ReviewStatus.PENDING_MANAGER
            )

        # HR approval pending (staff only)
        pending_approval = []
        if request.user.is_staff:
            pending_approval = queryset.filter(
                status=PerformanceReview.ReviewStatus.PENDING_APPROVAL
            )

        return Response({
            'pending_self_assessment': self.get_serializer(pending_self, many=True).data,
            'pending_manager_review': self.get_serializer(pending_manager, many=True).data,
            'pending_hr_approval': self.get_serializer(pending_approval, many=True).data
        })

    @action(detail=True, methods=['post'])
    def submit(self, request, pk=None):
        """Submit self-assessment."""
        review = self.get_object()

        if review.status != PerformanceReview.ReviewStatus.PENDING_SELF:
            return Response(
                {'detail': 'Review is not pending self-assessment.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if review.employee.user != request.user:
            return Response(
                {'detail': 'Only the employee can submit self-assessment.'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = PerformanceReviewSubmitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        review.self_assessment = serializer.validated_data['self_assessment']
        review.accomplishments = serializer.validated_data.get('accomplishments', '')
        review.status = PerformanceReview.ReviewStatus.PENDING_MANAGER
        review.employee_signed_at = timezone.now()
        review.save()

        review_serializer = self.get_serializer(review)
        return Response(review_serializer.data)

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Complete manager review."""
        review = self.get_object()

        if review.status != PerformanceReview.ReviewStatus.PENDING_MANAGER:
            return Response(
                {'detail': 'Review is not pending manager review.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if user is manager or HR
        try:
            user_employee = request.user.employee_record
            is_manager = review.employee.manager == user_employee
        except Employee.DoesNotExist:
            is_manager = False

        if not (is_manager or request.user.is_staff):
            return Response(
                {'detail': 'Only the manager or HR can complete this review.'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = PerformanceReviewCompleteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        review.overall_rating = serializer.validated_data['overall_rating']
        review.goals_met_percentage = serializer.validated_data['goals_met_percentage']
        review.manager_feedback = serializer.validated_data['manager_feedback']
        review.areas_for_improvement = serializer.validated_data.get('areas_for_improvement', '')
        review.goals_for_next_period = serializer.validated_data.get('goals_for_next_period', '')
        review.promotion_recommended = serializer.validated_data.get('promotion_recommended', False)
        review.salary_increase_recommended = serializer.validated_data.get('salary_increase_recommended', False)
        review.salary_increase_percentage = serializer.validated_data.get('salary_increase_percentage')
        review.pip_recommended = serializer.validated_data.get('pip_recommended', False)
        review.reviewer = request.user
        review.manager_signed_at = timezone.now()
        review.status = PerformanceReview.ReviewStatus.PENDING_APPROVAL
        review.save()

        review_serializer = self.get_serializer(review)
        return Response(review_serializer.data)

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """HR approval of performance review."""
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only HR staff can approve reviews.'},
                status=status.HTTP_403_FORBIDDEN
            )

        review = self.get_object()

        if review.status != PerformanceReview.ReviewStatus.PENDING_APPROVAL:
            return Response(
                {'detail': 'Review is not pending HR approval.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        review.status = PerformanceReview.ReviewStatus.COMPLETED
        review.completed_at = timezone.now()
        review.save()

        serializer = self.get_serializer(review)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def send_back(self, request, pk=None):
        """Send review back for revision."""
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only HR staff can send reviews back.'},
                status=status.HTTP_403_FORBIDDEN
            )

        review = self.get_object()
        target_status = request.data.get('target_status', 'pending_manager')

        if target_status == 'pending_self':
            review.status = PerformanceReview.ReviewStatus.PENDING_SELF
        else:
            review.status = PerformanceReview.ReviewStatus.PENDING_MANAGER

        review.save()

        serializer = self.get_serializer(review)
        return Response(serializer.data)


# ==================== SPECIAL VIEWS ====================

@require_tenant_type_api('company')
class OrgChartView(APIView):
    """
    Dedicated view for organizational chart - COMPANY ONLY.
    Returns hierarchical structure of employees.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Get optional root employee
        root_id = request.query_params.get('root')
        max_depth = int(request.query_params.get('depth', 5))

        if root_id:
            try:
                root_employee = Employee.objects.get(id=root_id)
                employees = [root_employee]
            except Employee.DoesNotExist:
                return Response(
                    {'detail': 'Employee not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Get top-level employees
            employees = Employee.objects.filter(
                manager__isnull=True,
                status__in=['active', 'probation']
            )

        serializer = EmployeeOrgChartSerializer(
            employees,
            many=True,
            context={'request': request, 'depth': max_depth}
        )
        return Response(serializer.data)


@require_tenant_type_api('company')
class TeamCalendarView(APIView):
    """
    Team calendar view showing time-off, reviews, and other HR events - COMPANY ONLY.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Date range parameters
        start_date_str = request.query_params.get('start')
        end_date_str = request.query_params.get('end')
        team_id = request.query_params.get('team')  # Manager's employee ID

        # Get tenant context if available
        tenant = getattr(request, 'tenant', None)

        # Default to current month
        today = timezone.now().date()
        if not start_date_str:
            start_date = today.replace(day=1)
        else:
            from datetime import datetime
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()

        if not end_date_str:
            if start_date.month == 12:
                end_date = start_date.replace(year=start_date.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                end_date = start_date.replace(month=start_date.month + 1, day=1) - timedelta(days=1)
        else:
            from datetime import datetime
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

        events = []

        # Get employees in scope
        if team_id:
            try:
                manager = Employee.objects.get(id=team_id)
                employees = Employee.objects.filter(
                    Q(manager=manager) | Q(id=manager.id)
                )
                if tenant:
                    employees = employees.filter(tenant=tenant)
            except Employee.DoesNotExist:
                employees = Employee.objects.none()
        elif request.user.is_staff:
            employees = Employee.objects.filter(status__in=['active', 'probation', 'on_leave'])
            if tenant:
                employees = employees.filter(tenant=tenant)
        else:
            try:
                user_employee = request.user.employee_record
                employees = Employee.objects.filter(
                    Q(id=user_employee.id) | Q(manager=user_employee)
                )
                if tenant:
                    employees = employees.filter(tenant=tenant)
            except Employee.DoesNotExist:
                employees = Employee.objects.none()

        # Get time-off events
        time_offs = TimeOffRequest.objects.filter(
            employee__in=employees,
            status=TimeOffRequest.RequestStatus.APPROVED,
            start_date__lte=end_date,
            end_date__gte=start_date
        ).select_related('employee', 'employee__user', 'time_off_type')

        for to in time_offs:
            events.append({
                'id': to.id,
                'title': f"{to.employee.full_name} - {to.time_off_type.name}",
                'start': to.start_date,
                'end': to.end_date,
                'type': 'time_off',
                'employee': EmployeeMinimalSerializer(to.employee).data,
                'status': to.status,
                'color': to.time_off_type.color
            })

        # Get performance review events
        reviews = PerformanceReview.objects.filter(
            employee__in=employees,
            review_period_end__gte=start_date,
            review_period_end__lte=end_date
        ).select_related('employee', 'employee__user')

        for review in reviews:
            events.append({
                'id': review.id,
                'title': f"{review.employee.full_name} - {review.get_review_type_display()}",
                'start': review.review_period_end,
                'end': review.review_period_end,
                'type': 'review',
                'employee': EmployeeMinimalSerializer(review.employee).data,
                'status': review.status,
                'color': '#10B981'  # Green
            })

        # Get onboarding events
        onboardings = EmployeeOnboarding.objects.filter(
            employee__in=employees,
            start_date__lte=end_date,
            completed_at__isnull=True
        ).select_related('employee', 'employee__user')

        for onb in onboardings:
            target_date = onb.target_completion_date or (onb.start_date + timedelta(days=30))
            if target_date >= start_date:
                events.append({
                    'id': onb.id,
                    'title': f"{onb.employee.full_name} - Onboarding",
                    'start': onb.start_date,
                    'end': target_date,
                    'type': 'onboarding',
                    'employee': EmployeeMinimalSerializer(onb.employee).data,
                    'status': f"{onb.completion_percentage}% complete",
                    'color': '#3B82F6'  # Blue
                })

        # Get offboarding events
        offboardings = Offboarding.objects.filter(
            employee__in=employees,
            last_working_day__gte=start_date,
            last_working_day__lte=end_date,
            completed_at__isnull=True
        ).select_related('employee', 'employee__user')

        for off in offboardings:
            events.append({
                'id': off.id,
                'title': f"{off.employee.full_name} - Last Day",
                'start': off.last_working_day,
                'end': off.last_working_day,
                'type': 'offboarding',
                'employee': EmployeeMinimalSerializer(off.employee).data,
                'status': off.separation_type,
                'color': '#EF4444'  # Red
            })

        # Sort events by start date
        events.sort(key=lambda x: x['start'])

        return Response({
            'start_date': start_date,
            'end_date': end_date,
            'events': events
        })


@require_tenant_type_api('company')
class HRDashboardStatsView(APIView):
    """
    HR Dashboard statistics and metrics.
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]

    def get(self, request):
        today = timezone.now().date()

        # Get tenant context if available
        tenant = getattr(request, 'tenant', None)

        # Employee counts by status
        queryset = Employee.objects.all()
        if tenant:
            queryset = queryset.filter(tenant=tenant)

        employee_counts = queryset.values('status').annotate(
            count=Count('id')
        )
        employee_by_status = {item['status']: item['count'] for item in employee_counts}

        # Active employees
        active_emp_qs = queryset.filter(
            status__in=['active', 'probation']
        )
        active_employees = active_emp_qs.count()

        # Pending time-off requests
        time_off_qs = TimeOffRequest.objects.all()
        if tenant:
            time_off_qs = time_off_qs.filter(employee__tenant=tenant)
        pending_time_off = time_off_qs.filter(
            status=TimeOffRequest.RequestStatus.PENDING
        ).count()

        # Employees on leave today
        on_leave_today = time_off_qs.filter(
            status=TimeOffRequest.RequestStatus.APPROVED,
            start_date__lte=today,
            end_date__gte=today
        ).count()

        # Pending performance reviews
        review_qs = PerformanceReview.objects.all()
        if tenant:
            review_qs = review_qs.filter(employee__tenant=tenant)
        pending_reviews = review_qs.filter(
            status__in=[
                PerformanceReview.ReviewStatus.PENDING_SELF,
                PerformanceReview.ReviewStatus.PENDING_MANAGER,
                PerformanceReview.ReviewStatus.PENDING_APPROVAL
            ]
        ).count()

        # Active onboardings
        onboard_qs = EmployeeOnboarding.objects.all()
        if tenant:
            onboard_qs = onboard_qs.filter(employee__tenant=tenant)
        active_onboardings = onboard_qs.filter(
            completed_at__isnull=True
        ).count()

        # Upcoming offboardings (next 30 days)
        offboard_qs = Offboarding.objects.all()
        if tenant:
            offboard_qs = offboard_qs.filter(employee__tenant=tenant)
        upcoming_offboardings = offboard_qs.filter(
            last_working_day__gte=today,
            last_working_day__lte=today + timedelta(days=30),
            completed_at__isnull=True
        ).count()

        # Documents pending signature
        doc_qs = EmployeeDocument.objects.all()
        if tenant:
            doc_qs = doc_qs.filter(employee__tenant=tenant)
        pending_signatures = doc_qs.filter(
            status=EmployeeDocument.DocumentStatus.PENDING_SIGNATURE
        ).count()

        # Average rating from completed reviews
        avg_rating = review_qs.filter(
            status=PerformanceReview.ReviewStatus.COMPLETED,
            overall_rating__isnull=False
        ).aggregate(avg=Avg('overall_rating'))['avg']

        return Response({
            'employee_counts': {
                'total': sum(employee_by_status.values()),
                'active': active_employees,
                'by_status': employee_by_status
            },
            'time_off': {
                'pending_requests': pending_time_off,
                'on_leave_today': on_leave_today
            },
            'performance': {
                'pending_reviews': pending_reviews,
                'average_rating': round(avg_rating, 2) if avg_rating else None
            },
            'onboarding': {
                'active': active_onboardings
            },
            'offboarding': {
                'upcoming_30_days': upcoming_offboardings
            },
            'documents': {
                'pending_signatures': pending_signatures
            }
        })


# ==================== HR REPORTS VIEW ====================

@require_tenant_type_api('company')
class HRReportsView(APIView):
    """
    HR reporting endpoints for headcount, turnover, and time off utilization.
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]

    def get(self, request):
        report_type = request.query_params.get('report_type', 'headcount')
        from datetime import datetime
        today = timezone.now().date()
        period_start_str = request.query_params.get('period_start')
        period_end_str = request.query_params.get('period_end')
        if period_start_str:
            period_start = datetime.strptime(period_start_str, '%Y-%m-%d').date()
        else:
            period_start = today.replace(month=1, day=1)
        if period_end_str:
            period_end = datetime.strptime(period_end_str, '%Y-%m-%d').date()
        else:
            period_end = today

        if report_type == 'headcount':
            return self._headcount_report(period_start, period_end)
        elif report_type == 'turnover':
            return self._turnover_report(period_start, period_end)
        elif report_type == 'time_off_utilization':
            return self._time_off_utilization_report(period_start, period_end)
        else:
            return Response({'detail': f'Unknown report type: {report_type}'}, status=status.HTTP_400_BAD_REQUEST)

    def _headcount_report(self, period_start, period_end):
        total_employees = Employee.objects.count()
        active_employees = Employee.objects.filter(status__in=['active', 'probation']).count()
        on_leave = Employee.objects.filter(status='on_leave').count()
        on_probation = Employee.objects.filter(status='probation').count()
        terminated_this_period = Employee.objects.filter(termination_date__gte=period_start, termination_date__lte=period_end).count()
        hired_this_period = Employee.objects.filter(hire_date__gte=period_start, hire_date__lte=period_end).count()
        by_department = list(Employee.objects.filter(status__in=['active', 'probation']).values('department__name').annotate(count=Count('id')).order_by('-count'))
        by_employment_type = dict(Employee.objects.filter(status__in=['active', 'probation']).values_list('employment_type').annotate(count=Count('id')))
        by_location = list(Employee.objects.filter(status__in=['active', 'probation'], work_location__isnull=False).values('work_location').annotate(count=Count('id')).order_by('-count')[:10])
        return Response({'total_employees': total_employees, 'active_employees': active_employees, 'on_leave': on_leave, 'on_probation': on_probation, 'terminated_this_period': terminated_this_period, 'hired_this_period': hired_this_period, 'by_department': by_department, 'by_employment_type': by_employment_type, 'by_location': by_location, 'as_of_date': period_end})

    def _turnover_report(self, period_start, period_end):
        offboardings = Offboarding.objects.filter(last_working_day__gte=period_start, last_working_day__lte=period_end)
        total_terminations = offboardings.count()
        voluntary_terminations = offboardings.filter(separation_type__in=['resignation', 'retirement']).count()
        involuntary_terminations = offboardings.filter(separation_type__in=['termination', 'layoff']).count()
        start_headcount = Employee.objects.filter(hire_date__lte=period_start, status__in=['active', 'probation', 'on_leave']).count()
        end_headcount = Employee.objects.filter(status__in=['active', 'probation', 'on_leave']).count()
        average_headcount = (start_headcount + end_headcount) / 2 if start_headcount else end_headcount
        turnover_rate = (total_terminations / average_headcount * 100) if average_headcount else 0
        voluntary_turnover_rate = (voluntary_terminations / average_headcount * 100) if average_headcount else 0
        by_department = list(offboardings.values('employee__department__name').annotate(count=Count('id')).order_by('-count'))
        top_reasons = list(offboardings.exclude(reason='').values('reason').annotate(count=Count('id')).order_by('-count')[:5])
        return Response({'period_start': period_start, 'period_end': period_end, 'total_terminations': total_terminations, 'voluntary_terminations': voluntary_terminations, 'involuntary_terminations': involuntary_terminations, 'average_headcount': round(average_headcount, 1), 'turnover_rate': round(turnover_rate, 2), 'voluntary_turnover_rate': round(voluntary_turnover_rate, 2), 'by_department': by_department, 'top_reasons': top_reasons})

    def _time_off_utilization_report(self, period_start, period_end):
        from django.db.models import Sum
        time_off_requests = TimeOffRequest.objects.filter(status=TimeOffRequest.RequestStatus.APPROVED, start_date__lte=period_end, end_date__gte=period_start)
        total_days_taken = time_off_requests.aggregate(total=Sum('total_days'))['total'] or Decimal('0')
        total_days_available = Employee.objects.filter(status__in=['active', 'probation']).aggregate(total=Sum('pto_balance'))['total'] or Decimal('0')
        utilization_rate = (float(total_days_taken) / float(total_days_available) * 100) if total_days_available else 0
        by_leave_type = list(time_off_requests.values('time_off_type__name').annotate(days=Sum('total_days'), count=Count('id')).order_by('-days'))
        by_department = list(time_off_requests.values('employee__department__name').annotate(days=Sum('total_days'), count=Count('id')).order_by('-days'))
        active_employee_count = Employee.objects.filter(status__in=['active', 'probation']).count()
        average_days_per_employee = float(total_days_taken) / active_employee_count if active_employee_count else 0
        pending_requests = TimeOffRequest.objects.filter(status=TimeOffRequest.RequestStatus.PENDING)
        pending_requests_count = pending_requests.count()
        pending_requests_days = pending_requests.aggregate(total=Sum('total_days'))['total'] or Decimal('0')
        return Response({'period_start': period_start, 'period_end': period_end, 'total_days_taken': float(total_days_taken), 'total_days_available': float(total_days_available), 'utilization_rate': round(utilization_rate, 2), 'by_leave_type': by_leave_type, 'by_department': by_department, 'average_days_per_employee': round(average_days_per_employee, 2), 'pending_requests_count': pending_requests_count, 'pending_requests_days': float(pending_requests_days)})


# ==================== PIP (PERFORMANCE IMPROVEMENT PLAN) VIEWSETS ====================

@require_tenant_type_api('company')
class PerformanceImprovementPlanViewSet(viewsets.ModelViewSet):
    """
    API endpoint for Performance Improvement Plans.

    Provides:
    - CRUD operations for PIPs
    - PIP activation workflow
    - Check-in recording
    - Extension requests
    - Completion with outcomes

    Filters:
    - status: Filter by PIP status
    - employee: Filter by employee ID
    - outcome: Filter by outcome
    """
    queryset = PerformanceImprovementPlan.objects.select_related(
        'employee', 'employee__user', 'initiated_by'
    ).prefetch_related('milestones', 'progress_notes')
    permission_classes = [permissions.IsAuthenticated, IsHROrManager]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'outcome', 'employee']
    search_fields = ['employee__first_name', 'employee__last_name', 'reason']
    ordering_fields = ['start_date', 'target_end_date', 'created_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return PerformanceImprovementPlanListSerializer
        if self.action == 'create_pip':
            return PIPCreateSerializer
        return PerformanceImprovementPlanSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user

        # HR/Admin can see all PIPs
        if user.is_staff:
            return queryset

        # Managers can see PIPs for their direct reports
        try:
            user_employee = user.employee_record
            return queryset.filter(
                Q(employee__manager=user_employee) |
                Q(initiated_by=user)
            )
        except Employee.DoesNotExist:
            return queryset.filter(initiated_by=user)

    @action(detail=False, methods=['post'])
    def create_pip(self, request):
        """Create a new PIP with milestones."""
        serializer = PIPCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from .services import PIPService
        result = PIPService.create_pip(
            employee=serializer.validated_data['employee_id'],
            initiated_by=request.user,
            reason=serializer.validated_data['reason'],
            performance_concerns=serializer.validated_data.get('performance_concerns', []),
            support_provided=serializer.validated_data.get('support_provided', ''),
            start_date=serializer.validated_data['start_date'],
            duration_days=serializer.validated_data['duration_days'],
            check_in_frequency_days=serializer.validated_data.get('check_in_frequency_days', 7),
            goals=serializer.validated_data.get('goals', []),
        )

        if not result.success:
            return Response(
                {'detail': result.message},
                status=status.HTTP_400_BAD_REQUEST
            )

        pip_serializer = PerformanceImprovementPlanSerializer(
            result.data,
            context={'request': request}
        )
        return Response(pip_serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Activate a draft PIP."""
        pip = self.get_object()

        if pip.status != 'draft':
            return Response(
                {'detail': 'Only draft PIPs can be activated.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        from .services import PIPService
        result = PIPService.activate_pip(pip.id, request.user)

        if not result.success:
            return Response(
                {'detail': result.message},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(result.data)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def record_check_in(self, request, pk=None):
        """Record a check-in meeting for a PIP."""
        pip = self.get_object()

        if pip.status not in ['active', 'extended']:
            return Response(
                {'detail': 'Check-ins can only be recorded for active PIPs.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = PIPCheckInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from .services import PIPService
        result = PIPService.record_check_in(
            pip_id=pip.id,
            content=serializer.validated_data['content'],
            meeting_date=serializer.validated_data.get('meeting_date'),
            author=request.user,
        )

        if not result.success:
            return Response(
                {'detail': result.message},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Process milestone updates if provided
        milestone_updates = serializer.validated_data.get('milestone_updates', [])
        for update in milestone_updates:
            PIPService.update_milestone(
                milestone_id=update.get('milestone_id'),
                status=update.get('status'),
                progress_notes=update.get('progress_notes'),
                author=request.user,
            )

        pip.refresh_from_db()
        pip_serializer = self.get_serializer(pip)
        return Response(pip_serializer.data)

    @action(detail=True, methods=['post'])
    def extend(self, request, pk=None):
        """Extend a PIP deadline."""
        pip = self.get_object()

        if pip.status not in ['active', 'extended']:
            return Response(
                {'detail': 'Only active PIPs can be extended.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = PIPExtendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from .services import PIPService
        result = PIPService.extend_pip(
            pip_id=pip.id,
            additional_days=serializer.validated_data['additional_days'],
            reason=serializer.validated_data['reason'],
            author=request.user,
        )

        if not result.success:
            return Response(
                {'detail': result.message},
                status=status.HTTP_400_BAD_REQUEST
            )

        pip_serializer = self.get_serializer(result.data)
        return Response(pip_serializer.data)

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Complete a PIP with an outcome."""
        pip = self.get_object()

        if pip.status not in ['active', 'extended']:
            return Response(
                {'detail': 'Only active PIPs can be completed.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = PIPCompleteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from .services import PIPService
        result = PIPService.complete_pip(
            pip_id=pip.id,
            outcome=serializer.validated_data['outcome'],
            final_assessment=serializer.validated_data['final_assessment'],
            final_rating=serializer.validated_data.get('final_rating'),
            author=request.user,
        )

        if not result.success:
            return Response(
                {'detail': result.message},
                status=status.HTTP_400_BAD_REQUEST
            )

        pip_serializer = self.get_serializer(result.data)
        return Response(pip_serializer.data)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a PIP."""
        pip = self.get_object()

        if pip.status in ['completed_success', 'completed_failure']:
            return Response(
                {'detail': 'Completed PIPs cannot be cancelled.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        reason = request.data.get('reason', '')

        pip.status = 'cancelled'
        pip.save()

        # Record cancellation note
        PIPProgressNote.objects.create(
            pip=pip,
            note_type='other',
            content=f"PIP cancelled. Reason: {reason}" if reason else "PIP cancelled.",
            author=request.user,
        )

        serializer = self.get_serializer(pip)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def summary(self, request, pk=None):
        """Get comprehensive PIP summary."""
        pip = self.get_object()

        from .services import PIPService
        result = PIPService.get_pip_summary(pip.id)

        if not result.success:
            return Response(
                {'detail': result.message},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(result.data)

    @action(detail=False, methods=['get'])
    def dashboard(self, request):
        """Get manager's PIP dashboard."""
        user = request.user

        # Get PIPs for direct reports
        try:
            user_employee = user.employee_record
            base_queryset = self.get_queryset().filter(
                Q(employee__manager=user_employee) |
                Q(initiated_by=user)
            )
        except Employee.DoesNotExist:
            base_queryset = self.get_queryset().filter(initiated_by=user)

        today = timezone.now().date()

        # Active PIPs
        active_pips = base_queryset.filter(status__in=['active', 'extended'])

        # Overdue PIPs
        overdue_pips = active_pips.filter(target_end_date__lt=today)

        # Upcoming check-ins (next 7 days)
        upcoming_check_ins = []
        for pip in active_pips.filter(next_check_in__lte=today + timedelta(days=7)):
            upcoming_check_ins.append({
                'pip_id': pip.id,
                'employee_name': pip.employee.full_name,
                'next_check_in': pip.next_check_in,
                'days_until': (pip.next_check_in - today).days if pip.next_check_in else None,
            })

        # Recently completed (last 30 days)
        recently_completed = base_queryset.filter(
            status__in=['completed_success', 'completed_failure'],
            actual_end_date__gte=today - timedelta(days=30)
        )

        # Stats
        stats = {
            'total_active': active_pips.count(),
            'overdue': overdue_pips.count(),
            'completed_success': base_queryset.filter(status='completed_success').count(),
            'completed_failure': base_queryset.filter(status='completed_failure').count(),
        }

        return Response({
            'active_pips': PerformanceImprovementPlanListSerializer(active_pips, many=True).data,
            'overdue_pips': PerformanceImprovementPlanListSerializer(overdue_pips, many=True).data,
            'upcoming_check_ins': upcoming_check_ins,
            'recently_completed': PerformanceImprovementPlanListSerializer(recently_completed, many=True).data,
            'stats': stats,
        })

    @action(detail=False, methods=['get'])
    def for_employee(self, request):
        """Get PIPs for a specific employee."""
        employee_id = request.query_params.get('employee_id')
        if not employee_id:
            return Response(
                {'detail': 'employee_id is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset().filter(employee_id=employee_id)
        serializer = PerformanceImprovementPlanListSerializer(queryset, many=True)
        return Response(serializer.data)


@require_tenant_type_api('company')
class PIPMilestoneViewSet(viewsets.ModelViewSet):
    """
    API endpoint for PIP milestones - COMPANY ONLY.
    """
    queryset = PIPMilestone.objects.select_related('pip', 'pip__employee')
    serializer_class = PIPMilestoneSerializer
    permission_classes = [permissions.IsAuthenticated, IsHROrManager]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['pip', 'status']
    ordering_fields = ['due_date', 'created_at']
    ordering = ['due_date']

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user

        if user.is_staff:
            return queryset

        try:
            user_employee = user.employee_record
            return queryset.filter(
                Q(pip__employee__manager=user_employee) |
                Q(pip__initiated_by=user)
            )
        except Employee.DoesNotExist:
            return queryset.filter(pip__initiated_by=user)

    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update milestone status."""
        milestone = self.get_object()

        serializer = PIPMilestoneUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_status = serializer.validated_data.get('status')
        progress_notes = serializer.validated_data.get('progress_notes', '')

        if new_status:
            milestone.status = new_status
            if new_status == 'achieved':
                milestone.completed_date = timezone.now().date()

        if progress_notes:
            milestone.progress_notes = (milestone.progress_notes or '') + f"\n\n{timezone.now().strftime('%Y-%m-%d')}: {progress_notes}"

        milestone.save()

        # Create progress note
        PIPProgressNote.objects.create(
            pip=milestone.pip,
            note_type='progress_update',
            content=f"Milestone '{milestone.title}' updated to {new_status}. {progress_notes}".strip(),
            author=request.user,
        )

        serializer = self.get_serializer(milestone)
        return Response(serializer.data)


@require_tenant_type_api('company')
class PIPProgressNoteViewSet(viewsets.ModelViewSet):
    """
    API endpoint for PIP progress notes - COMPANY ONLY.
    """
    queryset = PIPProgressNote.objects.select_related(
        'pip', 'pip__employee', 'author'
    )
    serializer_class = PIPProgressNoteSerializer
    permission_classes = [permissions.IsAuthenticated, IsHROrManager]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['pip', 'note_type']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user

        if user.is_staff:
            return queryset

        try:
            user_employee = user.employee_record
            return queryset.filter(
                Q(pip__employee__manager=user_employee) |
                Q(pip__initiated_by=user) |
                Q(author=user)
            )
        except Employee.DoesNotExist:
            return queryset.filter(Q(pip__initiated_by=user) | Q(author=user))

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

