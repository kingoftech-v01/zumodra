"""
HR Core Services - Business Logic Layer

This module provides service classes that encapsulate business logic
for the HR Core module:

- EmployeeService: Employee lifecycle management
- TimeOffService: Time off request management
- OnboardingService: Onboarding workflow management
- CompensationService: Compensation and salary management
- PerformanceService: Performance review management

Services provide a clean separation between views/serializers and models,
making the business logic testable and reusable.
"""

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple, Union

from django.core.exceptions import ValidationError, PermissionDenied
from django.db import transaction
from django.db.models import Avg, Count, F, Q, Sum, QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .models import (
    Employee,
    TimeOffType,
    TimeOffRequest,
    OnboardingChecklist,
    OnboardingTask,
    EmployeeOnboarding,
    OnboardingTaskProgress,
    DocumentTemplate,
    EmployeeDocument,
    Offboarding,
    PerformanceReview,
)

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES FOR SERVICE RESULTS
# =============================================================================

@dataclass
class ServiceResult:
    """Base result class for service operations."""
    success: bool
    message: str = ''
    data: Any = None
    errors: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OrgChartNode:
    """Node in organizational chart."""
    employee_id: int
    employee_uuid: str
    full_name: str
    job_title: str
    department: Optional[str]
    email: str
    direct_reports: List['OrgChartNode'] = field(default_factory=list)
    direct_reports_count: int = 0


@dataclass
class TimeOffBalance:
    """Employee time off balance."""
    employee_id: int
    time_off_type: str
    available_balance: Decimal
    used_this_year: Decimal
    pending_requests: Decimal
    accrued_this_year: Decimal
    carried_over: Decimal


@dataclass
class OnboardingProgress:
    """Employee onboarding progress."""
    employee_id: int
    checklist_name: str
    total_tasks: int
    completed_tasks: int
    completion_percentage: int
    overdue_tasks: int
    tasks_by_category: Dict[str, Dict[str, int]]
    estimated_completion_date: Optional[date]


@dataclass
class WelcomePacket:
    """Welcome packet for new employees."""
    employee_name: str
    job_title: str
    start_date: date
    manager_name: Optional[str]
    department_name: Optional[str]
    onboarding_tasks: List[Dict[str, Any]]
    required_documents: List[Dict[str, Any]]
    company_policies: List[Dict[str, Any]]


# =============================================================================
# PERMISSION CHECKING UTILITIES
# =============================================================================

class HRPermissions:
    """
    Permission checking utilities for HR operations.
    """

    # Permission codenames
    CAN_VIEW_EMPLOYEE = 'hr_core.view_employee'
    CAN_CREATE_EMPLOYEE = 'hr_core.add_employee'
    CAN_CHANGE_EMPLOYEE = 'hr_core.change_employee'
    CAN_DELETE_EMPLOYEE = 'hr_core.delete_employee'
    CAN_TERMINATE_EMPLOYEE = 'hr_core.terminate_employee'
    CAN_VIEW_COMPENSATION = 'hr_core.view_compensation'
    CAN_CHANGE_COMPENSATION = 'hr_core.change_compensation'
    CAN_APPROVE_TIME_OFF = 'hr_core.approve_timeoff'
    CAN_VIEW_PERFORMANCE = 'hr_core.view_performance'
    CAN_REVIEW_PERFORMANCE = 'hr_core.review_performance'

    @staticmethod
    def check_permission(user, permission: str, raise_exception: bool = True) -> bool:
        """Check if user has the specified permission."""
        if user is None or not user.is_authenticated:
            if raise_exception:
                raise PermissionDenied(_('Authentication required.'))
            return False

        if user.is_superuser:
            return True

        has_perm = user.has_perm(permission)

        if not has_perm and raise_exception:
            logger.warning(f"Permission denied: user={user.id}, permission={permission}")
            raise PermissionDenied(_('You do not have permission to perform this action.'))

        return has_perm

    @staticmethod
    def is_hr_staff(user) -> bool:
        """Check if user is HR staff."""
        if user is None or not user.is_authenticated:
            return False
        return user.is_staff or user.has_perm('hr_core.hr_staff')

    @staticmethod
    def is_manager_of(user, employee: 'Employee') -> bool:
        """Check if user is manager of the employee."""
        if user is None or not user.is_authenticated:
            return False
        try:
            user_employee = user.employee_record
            return employee.manager == user_employee
        except Employee.DoesNotExist:
            return False

    @staticmethod
    def can_view_employee(user, employee: 'Employee') -> bool:
        """Check if user can view employee data."""
        if HRPermissions.is_hr_staff(user):
            return True
        if employee.user == user:
            return True
        return HRPermissions.is_manager_of(user, employee)


# =============================================================================
# EMPLOYEE SERVICE
# =============================================================================

class EmployeeService:
    """
    Service for employee lifecycle management.

    Handles:
    - Employee onboarding
    - Termination
    - Transfers
    - Promotions
    - Compensation changes
    - Org chart generation
    """

    @staticmethod
    @transaction.atomic
    def onboard(
        employee: Employee,
        user=None,
        checklist: OnboardingChecklist = None,
        start_date: date = None
    ) -> ServiceResult:
        """
        Initiate employee onboarding process.

        Args:
            employee: The employee to onboard
            user: User performing the action
            checklist: Onboarding checklist to use
            start_date: Employee start date

        Returns:
            ServiceResult with onboarding record
        """
        try:
            # Update employee start date if provided
            if start_date:
                employee.start_date = start_date
                employee.save(update_fields=['start_date'])

            # Find applicable checklist if not provided
            if not checklist:
                checklist = OnboardingChecklist.objects.filter(
                    is_active=True,
                    department=employee.department
                ).first() or OnboardingChecklist.objects.filter(
                    is_active=True,
                    department__isnull=True,
                    employment_type=employee.employment_type
                ).first() or OnboardingChecklist.objects.filter(
                    is_active=True,
                    department__isnull=True,
                    employment_type=''
                ).first()

            if not checklist:
                return ServiceResult(
                    success=False,
                    message=_('No applicable onboarding checklist found.'),
                    errors={'checklist': _('No checklist available for this employee.')}
                )

            # Check if onboarding already exists
            if hasattr(employee, 'onboarding'):
                return ServiceResult(
                    success=False,
                    message=_('Employee already has an onboarding record.'),
                    errors={'onboarding': _('Onboarding already exists.')},
                    data=employee.onboarding
                )

            # Create onboarding record
            onboarding = EmployeeOnboarding.objects.create(
                employee=employee,
                checklist=checklist,
                start_date=employee.start_date or timezone.now().date(),
                target_completion_date=employee.start_date + timedelta(days=30) if employee.start_date else None
            )

            # Create task progress entries
            for task in checklist.tasks.all():
                due_date = None
                if onboarding.start_date and task.due_days:
                    due_date = onboarding.start_date + timedelta(days=task.due_days)

                OnboardingTaskProgress.objects.create(
                    onboarding=onboarding,
                    task=task,
                    due_date=due_date
                )

            logger.info(f"Onboarding started for employee {employee.employee_id}")

            return ServiceResult(
                success=True,
                message=_('Onboarding initiated successfully.'),
                data=onboarding
            )

        except Exception as e:
            logger.exception(f"Error starting onboarding: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to start onboarding.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def terminate(
        employee: Employee,
        reason: str,
        last_day: date,
        user=None,
        separation_type: str = 'termination',
        eligible_for_rehire: bool = True,
        notes: str = ''
    ) -> ServiceResult:
        """
        Terminate an employee.

        Args:
            employee: The employee to terminate
            reason: Reason for termination
            last_day: Last working day
            user: User performing the action
            separation_type: Type of separation
            eligible_for_rehire: Whether employee can be rehired
            notes: Additional notes

        Returns:
            ServiceResult with offboarding record
        """
        try:
            # Validate employee can be terminated
            if employee.status in ['terminated', 'resigned']:
                return ServiceResult(
                    success=False,
                    message=_('Employee is already terminated.'),
                    errors={'status': _('Employee is not active.')}
                )

            if hasattr(employee, 'offboarding'):
                return ServiceResult(
                    success=False,
                    message=_('Offboarding already exists for this employee.'),
                    errors={'offboarding': _('Offboarding in progress.')},
                    data=employee.offboarding
                )

            # Update employee status
            employee.status = Employee.EmploymentStatus.NOTICE_PERIOD
            employee.last_working_day = last_day
            employee.save(update_fields=['status', 'last_working_day'])

            # Create offboarding record
            offboarding = Offboarding.objects.create(
                employee=employee,
                separation_type=separation_type,
                reason=notes or reason,
                notice_date=timezone.now().date(),
                last_working_day=last_day,
                eligible_for_rehire=eligible_for_rehire,
                processed_by=user
            )

            logger.info(f"Termination initiated for employee {employee.employee_id}")

            return ServiceResult(
                success=True,
                message=_('Termination initiated successfully.'),
                data=offboarding
            )

        except Exception as e:
            logger.exception(f"Error terminating employee: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to initiate termination.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def transfer(
        employee: Employee,
        new_department,
        new_manager: Optional[Employee],
        user=None,
        effective_date: date = None,
        notes: str = ''
    ) -> ServiceResult:
        """
        Transfer an employee to a new department/manager.

        Args:
            employee: The employee to transfer
            new_department: New department
            new_manager: New manager (optional)
            user: User performing the action
            effective_date: When transfer takes effect
            notes: Additional notes

        Returns:
            ServiceResult indicating success
        """
        try:
            old_department = employee.department
            old_manager = employee.manager

            # Update employee
            employee.department = new_department
            if new_manager is not None:
                employee.manager = new_manager
            employee.save(update_fields=['department', 'manager'])

            logger.info(
                f"Employee {employee.employee_id} transferred from "
                f"{old_department} to {new_department}"
            )

            return ServiceResult(
                success=True,
                message=_('Employee transferred successfully.'),
                data={
                    'employee_id': employee.employee_id,
                    'old_department': str(old_department) if old_department else None,
                    'new_department': str(new_department) if new_department else None,
                    'old_manager': old_manager.full_name if old_manager else None,
                    'new_manager': new_manager.full_name if new_manager else None,
                }
            )

        except Exception as e:
            logger.exception(f"Error transferring employee: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to transfer employee.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def promote(
        employee: Employee,
        new_position: str,
        new_salary: Decimal,
        effective_date: date,
        user=None,
        notes: str = ''
    ) -> ServiceResult:
        """
        Promote an employee.

        Args:
            employee: The employee to promote
            new_position: New job title
            new_salary: New base salary
            effective_date: When promotion takes effect
            user: User performing the action
            notes: Additional notes

        Returns:
            ServiceResult indicating success
        """
        try:
            old_position = employee.job_title
            old_salary = employee.base_salary

            # Update employee
            employee.job_title = new_position
            employee.base_salary = new_salary
            employee.save(update_fields=['job_title', 'base_salary'])

            logger.info(
                f"Employee {employee.employee_id} promoted from "
                f"{old_position} to {new_position}"
            )

            return ServiceResult(
                success=True,
                message=_('Employee promoted successfully.'),
                data={
                    'employee_id': employee.employee_id,
                    'old_position': old_position,
                    'new_position': new_position,
                    'old_salary': float(old_salary) if old_salary else None,
                    'new_salary': float(new_salary),
                    'effective_date': effective_date.isoformat(),
                }
            )

        except Exception as e:
            logger.exception(f"Error promoting employee: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to promote employee.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def update_compensation(
        employee: Employee,
        changes: Dict[str, Any],
        effective_date: date,
        user=None,
        reason: str = ''
    ) -> ServiceResult:
        """
        Update employee compensation.

        Args:
            employee: The employee
            changes: Dictionary of compensation changes
            effective_date: When changes take effect
            user: User performing the action
            reason: Reason for change

        Returns:
            ServiceResult indicating success
        """
        try:
            old_values = {
                'base_salary': employee.base_salary,
                'salary_currency': employee.salary_currency,
                'pay_frequency': employee.pay_frequency,
            }

            # Apply changes
            if 'base_salary' in changes:
                employee.base_salary = Decimal(str(changes['base_salary']))
            if 'salary_currency' in changes:
                employee.salary_currency = changes['salary_currency']
            if 'pay_frequency' in changes:
                employee.pay_frequency = changes['pay_frequency']

            employee.save(update_fields=['base_salary', 'salary_currency', 'pay_frequency'])

            logger.info(f"Compensation updated for employee {employee.employee_id}")

            return ServiceResult(
                success=True,
                message=_('Compensation updated successfully.'),
                data={
                    'employee_id': employee.employee_id,
                    'old_values': {k: float(v) if isinstance(v, Decimal) else v for k, v in old_values.items()},
                    'new_values': changes,
                    'effective_date': effective_date.isoformat(),
                    'reason': reason,
                }
            )

        except Exception as e:
            logger.exception(f"Error updating compensation: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to update compensation.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    def get_org_chart(
        tenant=None,
        root_employee: Employee = None,
        max_depth: int = 5
    ) -> List[OrgChartNode]:
        """
        Get organizational chart.

        Args:
            tenant: Tenant to filter by (optional)
            root_employee: Starting employee (optional)
            max_depth: Maximum depth of hierarchy

        Returns:
            List of OrgChartNode objects
        """
        def build_node(employee: Employee, depth: int) -> OrgChartNode:
            direct_reports = []
            if depth < max_depth:
                reports = employee.direct_reports.filter(
                    status__in=['active', 'probation']
                )
                for report in reports:
                    direct_reports.append(build_node(report, depth + 1))

            return OrgChartNode(
                employee_id=employee.id,
                employee_uuid=str(employee.uuid),
                full_name=employee.full_name,
                job_title=employee.job_title,
                department=employee.department.name if employee.department else None,
                email=employee.user.email,
                direct_reports=direct_reports,
                direct_reports_count=len(direct_reports)
            )

        if root_employee:
            return [build_node(root_employee, 0)]

        # Get top-level employees (no manager)
        queryset = Employee.objects.filter(
            manager__isnull=True,
            status__in=['active', 'probation']
        ).select_related('user', 'department')

        return [build_node(emp, 0) for emp in queryset]

    @staticmethod
    def get_headcount_by_department(tenant=None) -> Dict[str, int]:
        """
        Get employee headcount by department.

        Args:
            tenant: Tenant to filter by (optional)

        Returns:
            Dictionary of department -> headcount
        """
        queryset = Employee.objects.filter(
            status__in=['active', 'probation', 'on_leave']
        )

        counts = queryset.values('department__name').annotate(
            count=Count('id')
        )

        return {
            item['department__name'] or 'Unassigned': item['count']
            for item in counts
        }


# =============================================================================
# TIME OFF SERVICE
# =============================================================================

class TimeOffService:
    """
    Service for time off request management.

    Handles:
    - Request creation
    - Approval/rejection workflows
    - Balance calculations
    - Team calendar generation
    """

    @staticmethod
    @transaction.atomic
    def request(
        employee: Employee,
        time_off_type: TimeOffType,
        start_date: date,
        end_date: date,
        notes: str = '',
        is_half_day: bool = False,
        half_day_period: str = ''
    ) -> ServiceResult:
        """
        Create a time off request.

        Args:
            employee: The employee requesting time off
            time_off_type: Type of time off
            start_date: Start date
            end_date: End date
            notes: Additional notes
            is_half_day: Whether this is a half-day request
            half_day_period: 'am' or 'pm' for half-day

        Returns:
            ServiceResult with the created request
        """
        try:
            # Validate dates
            if start_date > end_date:
                return ServiceResult(
                    success=False,
                    message=_('End date must be after start date.'),
                    errors={'end_date': _('Invalid date range.')}
                )

            # Calculate total days
            if is_half_day:
                total_days = Decimal('0.5')
            else:
                total_days = Decimal(str((end_date - start_date).days + 1))

            # Check notice period requirement
            days_until_start = (start_date - timezone.now().date()).days
            if days_until_start < time_off_type.min_notice_days:
                return ServiceResult(
                    success=False,
                    message=_(f'This time off type requires at least {time_off_type.min_notice_days} days notice.'),
                    errors={'start_date': _('Insufficient notice period.')}
                )

            # Check balance for accrued time off
            if time_off_type.is_accrued:
                if employee.pto_balance < total_days:
                    return ServiceResult(
                        success=False,
                        message=_(f'Insufficient PTO balance. Available: {employee.pto_balance} days.'),
                        errors={'total_days': _('Insufficient balance.')}
                    )

            # Check for overlapping requests
            overlapping = TimeOffRequest.objects.filter(
                employee=employee,
                status__in=['pending', 'approved'],
                start_date__lte=end_date,
                end_date__gte=start_date
            ).exists()

            if overlapping:
                return ServiceResult(
                    success=False,
                    message=_('You already have a time off request for this period.'),
                    errors={'dates': _('Overlapping request exists.')}
                )

            # Create the request
            request = TimeOffRequest.objects.create(
                employee=employee,
                time_off_type=time_off_type,
                start_date=start_date,
                end_date=end_date,
                is_half_day=is_half_day,
                half_day_period=half_day_period,
                total_days=total_days,
                reason=notes,
                status=TimeOffRequest.RequestStatus.PENDING if time_off_type.requires_approval
                else TimeOffRequest.RequestStatus.APPROVED
            )

            # Auto-approve if no approval required
            if not time_off_type.requires_approval:
                if time_off_type.is_accrued:
                    employee.pto_balance -= total_days
                    employee.save(update_fields=['pto_balance'])

            logger.info(f"Time off request created for employee {employee.employee_id}")

            return ServiceResult(
                success=True,
                message=_('Time off request submitted successfully.'),
                data=request
            )

        except Exception as e:
            logger.exception(f"Error creating time off request: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to create time off request.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def approve(
        request_id: int,
        approver,
        notes: str = ''
    ) -> ServiceResult:
        """
        Approve a time off request.

        Args:
            request_id: ID of the request to approve
            approver: User approving the request
            notes: Approval notes

        Returns:
            ServiceResult indicating success
        """
        try:
            request = TimeOffRequest.objects.select_related(
                'employee', 'time_off_type'
            ).get(id=request_id)

            if request.status != TimeOffRequest.RequestStatus.PENDING:
                return ServiceResult(
                    success=False,
                    message=_('Only pending requests can be approved.'),
                    errors={'status': _('Request is not pending.')}
                )

            # Approve the request
            request.approve(approver)

            if notes:
                request.notes = notes
                request.save(update_fields=['notes'])

            logger.info(f"Time off request {request_id} approved by {approver}")

            return ServiceResult(
                success=True,
                message=_('Time off request approved.'),
                data=request
            )

        except TimeOffRequest.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Time off request not found.'),
                errors={'request_id': _('Request does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error approving time off request: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to approve request.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def reject(
        request_id: int,
        approver,
        reason: str
    ) -> ServiceResult:
        """
        Reject a time off request.

        Args:
            request_id: ID of the request to reject
            approver: User rejecting the request
            reason: Rejection reason

        Returns:
            ServiceResult indicating success
        """
        try:
            request = TimeOffRequest.objects.get(id=request_id)

            if request.status != TimeOffRequest.RequestStatus.PENDING:
                return ServiceResult(
                    success=False,
                    message=_('Only pending requests can be rejected.'),
                    errors={'status': _('Request is not pending.')}
                )

            request.reject(approver, reason)

            logger.info(f"Time off request {request_id} rejected by {approver}")

            return ServiceResult(
                success=True,
                message=_('Time off request rejected.'),
                data=request
            )

        except TimeOffRequest.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Time off request not found.'),
                errors={'request_id': _('Request does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error rejecting time off request: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to reject request.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def cancel(
        request_id: int,
        user
    ) -> ServiceResult:
        """
        Cancel a time off request.

        Args:
            request_id: ID of the request to cancel
            user: User cancelling the request

        Returns:
            ServiceResult indicating success
        """
        try:
            request = TimeOffRequest.objects.select_related(
                'employee', 'time_off_type'
            ).get(id=request_id)

            if request.status not in [
                TimeOffRequest.RequestStatus.PENDING,
                TimeOffRequest.RequestStatus.APPROVED
            ]:
                return ServiceResult(
                    success=False,
                    message=_('This request cannot be cancelled.'),
                    errors={'status': _('Request cannot be cancelled.')}
                )

            # If approved, restore PTO balance
            if request.status == TimeOffRequest.RequestStatus.APPROVED:
                if request.time_off_type.is_accrued:
                    request.employee.pto_balance += request.total_days
                    request.employee.save(update_fields=['pto_balance'])

            request.status = TimeOffRequest.RequestStatus.CANCELLED
            request.save(update_fields=['status'])

            logger.info(f"Time off request {request_id} cancelled")

            return ServiceResult(
                success=True,
                message=_('Time off request cancelled.'),
                data=request
            )

        except TimeOffRequest.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Time off request not found.'),
                errors={'request_id': _('Request does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error cancelling time off request: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to cancel request.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    def get_balance(employee: Employee, time_off_type: TimeOffType = None) -> Union[TimeOffBalance, List[TimeOffBalance]]:
        """
        Get time off balance for an employee.

        Args:
            employee: The employee
            time_off_type: Specific type (optional)

        Returns:
            TimeOffBalance or list of TimeOffBalance objects
        """
        today = timezone.now().date()
        year_start = date(today.year, 1, 1)

        def calculate_balance(tot: TimeOffType) -> TimeOffBalance:
            # Used this year (approved requests)
            used = TimeOffRequest.objects.filter(
                employee=employee,
                time_off_type=tot,
                status=TimeOffRequest.RequestStatus.APPROVED,
                start_date__gte=year_start
            ).aggregate(total=Sum('total_days'))['total'] or Decimal('0')

            # Pending requests
            pending = TimeOffRequest.objects.filter(
                employee=employee,
                time_off_type=tot,
                status=TimeOffRequest.RequestStatus.PENDING
            ).aggregate(total=Sum('total_days'))['total'] or Decimal('0')

            # Available balance (simplified - using employee's pto_balance)
            if tot.code == 'PTO':
                available = employee.pto_balance
            elif tot.code == 'SICK':
                available = employee.sick_leave_balance
            else:
                available = Decimal('0')

            return TimeOffBalance(
                employee_id=employee.id,
                time_off_type=tot.name,
                available_balance=available,
                used_this_year=used,
                pending_requests=pending,
                accrued_this_year=Decimal('0'),  # Would calculate from accrual history
                carried_over=Decimal('0')  # Would calculate from previous year
            )

        if time_off_type:
            return calculate_balance(time_off_type)

        return [
            calculate_balance(tot)
            for tot in TimeOffType.objects.filter(is_active=True)
        ]

    @staticmethod
    def calculate_accrual(employee: Employee, period: str = 'monthly') -> Decimal:
        """
        Calculate time off accrual for an employee.

        Args:
            employee: The employee
            period: Accrual period ('monthly', 'bi_weekly', 'annual')

        Returns:
            Accrual amount in days
        """
        # Base accrual rates (days per month)
        base_rate = Decimal('1.25')  # 15 days per year

        # Adjust for years of service
        years = employee.years_of_service
        if years >= 10:
            multiplier = Decimal('1.50')  # 22.5 days
        elif years >= 5:
            multiplier = Decimal('1.25')  # 18.75 days
        elif years >= 2:
            multiplier = Decimal('1.10')  # 16.5 days
        else:
            multiplier = Decimal('1.00')

        # Adjust for employment type
        if employee.employment_type == 'part_time':
            multiplier *= Decimal('0.50')
        elif employee.employment_type in ['contract', 'temporary']:
            return Decimal('0')

        monthly_accrual = base_rate * multiplier

        if period == 'bi_weekly':
            return monthly_accrual / 2
        elif period == 'annual':
            return monthly_accrual * 12
        return monthly_accrual

    @staticmethod
    def get_team_calendar(
        manager: Employee,
        month: date
    ) -> List[Dict[str, Any]]:
        """
        Get team calendar showing time off for a manager's team.

        Args:
            manager: The manager
            month: Month to display

        Returns:
            List of calendar events
        """
        # Get date range
        month_start = month.replace(day=1)
        if month.month == 12:
            month_end = month.replace(year=month.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = month.replace(month=month.month + 1, day=1) - timedelta(days=1)

        # Get team members
        team = Employee.objects.filter(
            Q(id=manager.id) | Q(manager=manager),
            status__in=['active', 'probation', 'on_leave']
        )

        # Get approved time off
        events = []
        time_offs = TimeOffRequest.objects.filter(
            employee__in=team,
            status=TimeOffRequest.RequestStatus.APPROVED,
            start_date__lte=month_end,
            end_date__gte=month_start
        ).select_related('employee', 'employee__user', 'time_off_type')

        for to in time_offs:
            events.append({
                'id': to.id,
                'title': f"{to.employee.full_name} - {to.time_off_type.name}",
                'start': max(to.start_date, month_start).isoformat(),
                'end': min(to.end_date, month_end).isoformat(),
                'type': 'time_off',
                'employee_id': to.employee.id,
                'employee_name': to.employee.full_name,
                'color': to.time_off_type.color,
            })

        return events


# =============================================================================
# ONBOARDING SERVICE
# =============================================================================

class OnboardingService:
    """
    Service for onboarding workflow management.

    Handles:
    - Onboarding initiation
    - Task completion tracking
    - Progress reporting
    - Welcome packet generation
    """

    @staticmethod
    @transaction.atomic
    def start_onboarding(
        employee: Employee,
        checklist: OnboardingChecklist
    ) -> ServiceResult:
        """
        Start onboarding for an employee.

        Args:
            employee: The employee
            checklist: Onboarding checklist to use

        Returns:
            ServiceResult with onboarding record
        """
        return EmployeeService.onboard(employee, checklist=checklist)

    @staticmethod
    @transaction.atomic
    def complete_task(
        task_progress_id: int,
        completed_by
    ) -> ServiceResult:
        """
        Complete an onboarding task.

        Args:
            task_progress_id: ID of task progress record
            completed_by: User completing the task

        Returns:
            ServiceResult indicating success
        """
        try:
            task_progress = OnboardingTaskProgress.objects.select_related(
                'onboarding', 'task'
            ).get(id=task_progress_id)

            if task_progress.is_completed:
                return ServiceResult(
                    success=False,
                    message=_('Task is already completed.'),
                    errors={'task': _('Already completed.')}
                )

            task_progress.complete(completed_by)

            # Check if all tasks are complete
            onboarding = task_progress.onboarding
            if onboarding.completion_percentage == 100:
                onboarding.completed_at = timezone.now()
                onboarding.save(update_fields=['completed_at'])

                # Update employee status if pending
                employee = onboarding.employee
                if employee.status == Employee.EmploymentStatus.PENDING:
                    employee.status = Employee.EmploymentStatus.ACTIVE
                    employee.save(update_fields=['status'])

            logger.info(f"Onboarding task {task_progress_id} completed")

            return ServiceResult(
                success=True,
                message=_('Task completed successfully.'),
                data=task_progress
            )

        except OnboardingTaskProgress.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Task not found.'),
                errors={'task_progress_id': _('Task does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error completing task: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to complete task.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def skip_task(
        task_progress_id: int,
        skipped_by,
        reason: str
    ) -> ServiceResult:
        """
        Skip an onboarding task.

        Args:
            task_progress_id: ID of task progress record
            skipped_by: User skipping the task
            reason: Reason for skipping

        Returns:
            ServiceResult indicating success
        """
        try:
            task_progress = OnboardingTaskProgress.objects.select_related(
                'task'
            ).get(id=task_progress_id)

            if task_progress.task.is_required:
                return ServiceResult(
                    success=False,
                    message=_('Required tasks cannot be skipped.'),
                    errors={'task': _('Task is required.')}
                )

            task_progress.is_completed = True
            task_progress.completed_at = timezone.now()
            task_progress.completed_by = skipped_by
            task_progress.notes = f"Skipped: {reason}"
            task_progress.save()

            logger.info(f"Onboarding task {task_progress_id} skipped")

            return ServiceResult(
                success=True,
                message=_('Task skipped successfully.'),
                data=task_progress
            )

        except OnboardingTaskProgress.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Task not found.'),
                errors={'task_progress_id': _('Task does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error skipping task: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to skip task.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def reassign_task(
        task_progress_id: int,
        new_assignee
    ) -> ServiceResult:
        """
        Reassign an onboarding task.

        Args:
            task_progress_id: ID of task progress record
            new_assignee: User to assign the task to

        Returns:
            ServiceResult indicating success
        """
        try:
            task_progress = OnboardingTaskProgress.objects.get(id=task_progress_id)

            if task_progress.is_completed:
                return ServiceResult(
                    success=False,
                    message=_('Completed tasks cannot be reassigned.'),
                    errors={'task': _('Already completed.')}
                )

            # Note: Would need to add an 'assigned_to' field to OnboardingTaskProgress
            # For now, just update notes
            task_progress.notes = f"Reassigned to: {new_assignee}"
            task_progress.save(update_fields=['notes'])

            logger.info(f"Onboarding task {task_progress_id} reassigned")

            return ServiceResult(
                success=True,
                message=_('Task reassigned successfully.'),
                data=task_progress
            )

        except OnboardingTaskProgress.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Task not found.'),
                errors={'task_progress_id': _('Task does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error reassigning task: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to reassign task.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    def get_progress(employee: Employee) -> Optional[OnboardingProgress]:
        """
        Get onboarding progress for an employee.

        Args:
            employee: The employee

        Returns:
            OnboardingProgress object or None
        """
        try:
            onboarding = employee.onboarding
        except EmployeeOnboarding.DoesNotExist:
            return None

        task_progress = onboarding.task_progress.select_related('task').all()
        today = timezone.now().date()

        # Count tasks by category
        tasks_by_category = {}
        for tp in task_progress:
            category = tp.task.get_category_display()
            if category not in tasks_by_category:
                tasks_by_category[category] = {'total': 0, 'completed': 0}
            tasks_by_category[category]['total'] += 1
            if tp.is_completed:
                tasks_by_category[category]['completed'] += 1

        # Count overdue tasks
        overdue = sum(
            1 for tp in task_progress
            if not tp.is_completed and tp.due_date and tp.due_date < today
        )

        # Estimate completion date
        incomplete_tasks = [tp for tp in task_progress if not tp.is_completed]
        if incomplete_tasks:
            max_due = max(
                (tp.due_date for tp in incomplete_tasks if tp.due_date),
                default=None
            )
            estimated_completion = max_due
        else:
            estimated_completion = today

        return OnboardingProgress(
            employee_id=employee.id,
            checklist_name=onboarding.checklist.name if onboarding.checklist else '',
            total_tasks=task_progress.count(),
            completed_tasks=task_progress.filter(is_completed=True).count(),
            completion_percentage=onboarding.completion_percentage,
            overdue_tasks=overdue,
            tasks_by_category=tasks_by_category,
            estimated_completion_date=estimated_completion
        )

    @staticmethod
    def generate_welcome_packet(employee: Employee) -> WelcomePacket:
        """
        Generate a welcome packet for a new employee.

        Args:
            employee: The employee

        Returns:
            WelcomePacket object
        """
        # Get onboarding tasks
        onboarding_tasks = []
        try:
            onboarding = employee.onboarding
            for tp in onboarding.task_progress.select_related('task').all():
                onboarding_tasks.append({
                    'title': tp.task.title,
                    'description': tp.task.description,
                    'category': tp.task.get_category_display(),
                    'due_date': tp.due_date.isoformat() if tp.due_date else None,
                    'is_required': tp.task.is_required,
                })
        except EmployeeOnboarding.DoesNotExist:
            pass

        # Get required documents
        required_documents = []
        document_templates = DocumentTemplate.objects.filter(
            is_active=True,
            category__in=['contract', 'form', 'policy']
        )
        for template in document_templates:
            required_documents.append({
                'name': template.name,
                'category': template.get_category_display(),
                'requires_signature': template.requires_signature,
            })

        # Get company policies (would typically come from a policies app)
        company_policies = [
            {'name': 'Employee Handbook', 'category': 'General'},
            {'name': 'Code of Conduct', 'category': 'Compliance'},
            {'name': 'IT Security Policy', 'category': 'IT'},
            {'name': 'Time Off Policy', 'category': 'HR'},
        ]

        return WelcomePacket(
            employee_name=employee.full_name,
            job_title=employee.job_title,
            start_date=employee.start_date or timezone.now().date(),
            manager_name=employee.manager.full_name if employee.manager else None,
            department_name=employee.department.name if employee.department else None,
            onboarding_tasks=onboarding_tasks,
            required_documents=required_documents,
            company_policies=company_policies
        )


# =============================================================================
# PERFORMANCE SERVICE
# =============================================================================

class PerformanceService:
    """
    Service for performance review management.

    Handles:
    - Review creation and scheduling
    - Self-assessment submission
    - Manager review completion
    - HR approval workflow
    """

    @staticmethod
    @transaction.atomic
    def create_review(
        employee: Employee,
        review_type: str,
        period_start: date,
        period_end: date,
        reviewer=None
    ) -> ServiceResult:
        """
        Create a performance review.

        Args:
            employee: The employee being reviewed
            review_type: Type of review
            period_start: Review period start
            period_end: Review period end
            reviewer: Reviewer user (optional)

        Returns:
            ServiceResult with the created review
        """
        try:
            # Check for existing review in the same period
            existing = PerformanceReview.objects.filter(
                employee=employee,
                review_period_start=period_start,
                review_period_end=period_end,
                status__in=['draft', 'pending_self', 'pending_manager', 'pending_approval']
            ).exists()

            if existing:
                return ServiceResult(
                    success=False,
                    message=_('A review already exists for this period.'),
                    errors={'period': _('Duplicate review.')}
                )

            review = PerformanceReview.objects.create(
                employee=employee,
                reviewer=reviewer or (employee.manager.user if employee.manager else None),
                review_type=review_type,
                review_period_start=period_start,
                review_period_end=period_end,
                status=PerformanceReview.ReviewStatus.PENDING_SELF
            )

            logger.info(f"Performance review created for employee {employee.employee_id}")

            return ServiceResult(
                success=True,
                message=_('Performance review created.'),
                data=review
            )

        except Exception as e:
            logger.exception(f"Error creating performance review: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to create review.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def submit_self_assessment(
        review_id: int,
        self_assessment: str,
        accomplishments: str = ''
    ) -> ServiceResult:
        """
        Submit employee self-assessment.

        Args:
            review_id: ID of the review
            self_assessment: Self-assessment text
            accomplishments: Key accomplishments

        Returns:
            ServiceResult indicating success
        """
        try:
            review = PerformanceReview.objects.get(id=review_id)

            if review.status != PerformanceReview.ReviewStatus.PENDING_SELF:
                return ServiceResult(
                    success=False,
                    message=_('Review is not pending self-assessment.'),
                    errors={'status': _('Invalid review status.')}
                )

            review.self_assessment = self_assessment
            review.accomplishments = accomplishments
            review.status = PerformanceReview.ReviewStatus.PENDING_MANAGER
            review.employee_signed_at = timezone.now()
            review.save()

            logger.info(f"Self-assessment submitted for review {review_id}")

            return ServiceResult(
                success=True,
                message=_('Self-assessment submitted.'),
                data=review
            )

        except PerformanceReview.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Review not found.'),
                errors={'review_id': _('Review does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error submitting self-assessment: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to submit self-assessment.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def complete_manager_review(
        review_id: int,
        reviewer,
        overall_rating: int,
        goals_met_percentage: int,
        manager_feedback: str,
        areas_for_improvement: str = '',
        goals_for_next_period: str = '',
        promotion_recommended: bool = False,
        salary_increase_recommended: bool = False,
        salary_increase_percentage: Decimal = None,
        pip_recommended: bool = False
    ) -> ServiceResult:
        """
        Complete manager review.

        Args:
            review_id: ID of the review
            reviewer: Reviewing user
            overall_rating: Rating 1-5
            goals_met_percentage: 0-100
            manager_feedback: Feedback text
            areas_for_improvement: Improvement areas
            goals_for_next_period: Goals for next period
            promotion_recommended: Recommend promotion
            salary_increase_recommended: Recommend salary increase
            salary_increase_percentage: Recommended percentage
            pip_recommended: Recommend performance improvement plan

        Returns:
            ServiceResult indicating success
        """
        try:
            review = PerformanceReview.objects.get(id=review_id)

            if review.status != PerformanceReview.ReviewStatus.PENDING_MANAGER:
                return ServiceResult(
                    success=False,
                    message=_('Review is not pending manager review.'),
                    errors={'status': _('Invalid review status.')}
                )

            review.overall_rating = overall_rating
            review.goals_met_percentage = goals_met_percentage
            review.manager_feedback = manager_feedback
            review.areas_for_improvement = areas_for_improvement
            review.goals_for_next_period = goals_for_next_period
            review.promotion_recommended = promotion_recommended
            review.salary_increase_recommended = salary_increase_recommended
            review.salary_increase_percentage = salary_increase_percentage
            review.pip_recommended = pip_recommended
            review.reviewer = reviewer
            review.manager_signed_at = timezone.now()
            review.status = PerformanceReview.ReviewStatus.PENDING_APPROVAL
            review.save()

            logger.info(f"Manager review completed for review {review_id}")

            return ServiceResult(
                success=True,
                message=_('Manager review completed.'),
                data=review
            )

        except PerformanceReview.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Review not found.'),
                errors={'review_id': _('Review does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error completing manager review: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to complete review.'),
                errors={'__all__': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def approve_review(review_id: int, approver) -> ServiceResult:
        """
        HR approval of a performance review.

        Args:
            review_id: ID of the review
            approver: HR user approving

        Returns:
            ServiceResult indicating success
        """
        try:
            review = PerformanceReview.objects.get(id=review_id)

            if review.status != PerformanceReview.ReviewStatus.PENDING_APPROVAL:
                return ServiceResult(
                    success=False,
                    message=_('Review is not pending approval.'),
                    errors={'status': _('Invalid review status.')}
                )

            review.status = PerformanceReview.ReviewStatus.COMPLETED
            review.completed_at = timezone.now()
            review.save()

            logger.info(f"Performance review {review_id} approved")

            return ServiceResult(
                success=True,
                message=_('Review approved and completed.'),
                data=review
            )

        except PerformanceReview.DoesNotExist:
            return ServiceResult(
                success=False,
                message=_('Review not found.'),
                errors={'review_id': _('Review does not exist.')}
            )
        except Exception as e:
            logger.exception(f"Error approving review: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to approve review.'),
                errors={'__all__': str(e)}
            )
