"""
HR Core Template Views - Frontend views for Human Resources.

This module implements template-based views for:
- Employee directory and profiles
- Time-off calendar and requests
- Organization chart
- Onboarding tracking
- Performance reviews

All views are HTMX-aware and return partials when appropriate.
"""

import json
import logging
from datetime import date, timedelta
from decimal import Decimal

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.db.models import Count, Q, Sum, Prefetch
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView, ListView, DetailView, FormView, UpdateView

from tenants.mixins import TenantViewMixin
from tenants.decorators import require_tenant_type

from .models import (
    Employee, TimeOffType, TimeOffRequest, TimeOffBalance,
    OnboardingChecklist, OnboardingTask, EmployeeOnboarding, OnboardingTaskProgress,
    DocumentTemplate, EmployeeDocument, Offboarding,
    PerformanceReview, EmployeeGoal, EmployeeSkill, Certification, EmployeeActivityLog
)

logger = logging.getLogger(__name__)


# =============================================================================
# MIXINS
# =============================================================================

class HTMXMixin:
    """
    Mixin to handle HTMX requests gracefully.
    """
    partial_template_name = None

    def get_template_names(self):
        if self.request.headers.get('HX-Request') and self.partial_template_name:
            return [self.partial_template_name]
        return super().get_template_names()

    def render_htmx_response(self, template, context, **response_kwargs):
        response = render(self.request, template, context)
        if trigger := response_kwargs.get('hx_trigger'):
            response['HX-Trigger'] = trigger
        if push_url := response_kwargs.get('hx_push_url'):
            response['HX-Push-Url'] = push_url
        return response


class HRPermissionMixin:
    """
    Mixin for HR-specific permission checks.
    """

    def has_hr_permission(self, permission_type='view'):
        user = self.request.user

        if user.is_superuser or user.is_staff:
            return True

        if hasattr(user, 'tenantuser'):
            role = user.tenantuser.role.lower() if user.tenantuser.role else ''
            allowed_roles = {
                'view': ['hr', 'admin', 'pdg', 'supervisor', 'manager'],
                'edit': ['hr', 'admin', 'pdg'],
                'delete': ['hr', 'admin', 'pdg'],
                'admin': ['admin', 'pdg'],
            }
            return role in allowed_roles.get(permission_type, [])

        user_groups = [g.name.lower() for g in user.groups.all()]
        return any('hr' in g or 'admin' in g for g in user_groups)

    def is_employee_self(self, employee):
        """Check if the current user is viewing their own record."""
        return hasattr(employee, 'user') and employee.user == self.request.user

    def is_manager_of(self, employee):
        """Check if current user is manager of the employee."""
        try:
            user_employee = Employee.objects.get(user=self.request.user)
            return employee.manager == user_employee
        except Employee.DoesNotExist:
            return False


# =============================================================================
# EMPLOYEE VIEWS
# =============================================================================

@require_tenant_type('company')
class EmployeeDirectoryView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """
    Employee directory with search and filters - COMPANY ONLY.

    Displays all active employees with department/team filtering.
    """
    model = Employee
    template_name = 'hr/employee_list.html'
    partial_template_name = 'hr/partials/_employee_list.html'
    context_object_name = 'employees'
    paginate_by = 25

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return Employee.objects.none()

        queryset = Employee.objects.filter(
            user__tenantuser__tenant=tenant,
            status__in=['active', 'probation', 'on_leave']
        ).select_related(
            'user', 'department', 'manager__user'
        ).order_by('user__last_name', 'user__first_name')

        # Search
        search = self.request.GET.get('q')
        if search:
            queryset = queryset.filter(
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(user__email__icontains=search) |
                Q(job_title__icontains=search) |
                Q(employee_id__icontains=search)
            )

        # Department filter
        department = self.request.GET.get('department')
        if department:
            queryset = queryset.filter(department_id=department)

        # Status filter
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Team filter
        team = self.request.GET.get('team')
        if team:
            queryset = queryset.filter(team__icontains=team)

        # Employment type filter
        employment_type = self.request.GET.get('employment_type')
        if employment_type:
            queryset = queryset.filter(employment_type=employment_type)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if tenant:
            # Get departments for filter
            from configurations.models import Department
            context['departments'] = Department.objects.filter(
                tenant=tenant, is_active=True
            ).order_by('name')

            context['status_choices'] = Employee.EmploymentStatus.choices
            context['employment_type_choices'] = Employee.EmploymentType.choices

            context['current_filters'] = {
                'q': self.request.GET.get('q', ''),
                'department': self.request.GET.get('department', ''),
                'status': self.request.GET.get('status', ''),
                'team': self.request.GET.get('team', ''),
                'employment_type': self.request.GET.get('employment_type', ''),
            }

            # Stats
            base_qs = Employee.objects.filter(user__tenantuser__tenant=tenant)
            context['stats'] = {
                'total': base_qs.filter(status='active').count(),
                'on_leave': base_qs.filter(status='on_leave').count(),
                'probation': base_qs.filter(status='probation').count(),
                'new_hires_month': base_qs.filter(
                    hire_date__gte=timezone.now().date() - timedelta(days=30)
                ).count(),
            }

        return context


@require_tenant_type('company')
class EmployeeDetailView(LoginRequiredMixin, TenantViewMixin, HRPermissionMixin, HTMXMixin, DetailView):
    """
    Employee profile page with all details - COMPANY ONLY.

    Shows:
    - Personal information
    - Employment details
    - Time-off balances
    - Documents
    - Skills and certifications
    - Performance history
    - Activity timeline
    """
    model = Employee
    template_name = 'hr/employee_detail.html'
    context_object_name = 'employee'

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return Employee.objects.none()

        return Employee.objects.filter(
            user__tenantuser__tenant=tenant
        ).select_related(
            'user', 'department', 'manager__user',
            'from_application__job'
        ).prefetch_related(
            'employee_skills__skill',
            'certification_records',
            'documents',
            'time_off_requests',
            'time_off_balances__time_off_type',
            'performance_reviews',
            'goals',
            'activity_logs'
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        employee = self.object

        # Permission check - can view full details?
        can_view_sensitive = (
            self.has_hr_permission('view') or
            self.is_employee_self(employee) or
            self.is_manager_of(employee)
        )
        context['can_view_sensitive'] = can_view_sensitive
        context['can_edit'] = (
            self.has_hr_permission('edit') or
            self.is_employee_self(employee)
        )

        # Time-off balances
        context['time_off_balances'] = employee.time_off_balances.select_related(
            'time_off_type'
        ).filter(year=timezone.now().year)

        # Pending time-off requests
        context['pending_time_off'] = employee.time_off_requests.filter(
            status='pending'
        ).order_by('start_date')

        # Skills
        context['skills'] = employee.employee_skills.select_related('skill').all()

        # Certifications
        context['certifications'] = employee.certification_records.filter(
            is_active=True
        ).order_by('-issue_date')

        # Expiring certifications (next 90 days)
        context['expiring_certifications'] = employee.certification_records.filter(
            is_active=True,
            expiry_date__isnull=False,
            expiry_date__lte=timezone.now().date() + timedelta(days=90)
        ).order_by('expiry_date')

        # Documents
        context['documents'] = employee.documents.filter(
            status__in=['signed', 'draft', 'pending_signature']
        ).order_by('-created_at')[:10]

        # Performance reviews
        context['performance_reviews'] = employee.performance_reviews.order_by(
            '-review_period_end'
        )[:5]

        # Active goals
        context['active_goals'] = employee.goals.filter(
            status='active'
        ).order_by('target_date')

        # Direct reports
        context['direct_reports'] = Employee.objects.filter(
            manager=employee,
            status='active'
        ).select_related('user')[:10]

        # Activity log
        context['activity_log'] = employee.activity_logs.order_by('-created_at')[:20]

        # Onboarding status (if applicable)
        if hasattr(employee, 'onboarding'):
            context['onboarding'] = employee.onboarding
            context['onboarding_progress'] = employee.onboarding.completion_percentage

        return context


@require_tenant_type('company')
class EmployeeEditView(LoginRequiredMixin, TenantViewMixin, HRPermissionMixin, UpdateView):
    """
    Edit employee profile - COMPANY ONLY.
    """
    model = Employee
    template_name = 'hr/employee_form.html'
    fields = [
        'job_title', 'team', 'work_location', 'employment_type',
        'emergency_contact_name', 'emergency_contact_phone', 'emergency_contact_relationship'
    ]

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return Employee.objects.none()

        return Employee.objects.filter(user__tenantuser__tenant=tenant)

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        # Permission check
        if not (self.has_hr_permission('edit') or self.is_employee_self(obj)):
            from django.core.exceptions import PermissionDenied
            raise PermissionDenied
        return obj

    def form_valid(self, form):
        # Log the change
        EmployeeActivityLog.objects.create(
            employee=self.object,
            activity_type='updated',
            description='Employee information updated',
            performed_by=self.request.user,
        )
        messages.success(self.request, 'Employee information updated successfully.')
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('hr:employee-detail', kwargs={'pk': self.object.pk})


# =============================================================================
# TIME-OFF VIEWS
# =============================================================================

@require_tenant_type('company')
class TimeOffCalendarView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, TemplateView):
    """
    Team calendar view showing all time-off - COMPANY ONLY.

    Displays a calendar with scheduled time-off for the team.
    """
    template_name = 'hr/time_off_calendar.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if not tenant:
            return context

        # Get date range from params or default to current month
        year = int(self.request.GET.get('year', timezone.now().year))
        month = int(self.request.GET.get('month', timezone.now().month))

        from calendar import monthrange
        first_day = date(year, month, 1)
        last_day = date(year, month, monthrange(year, month)[1])

        # Get approved time-off for the month
        time_off_requests = TimeOffRequest.objects.filter(
            employee__user__tenantuser__tenant=tenant,
            status='approved',
            start_date__lte=last_day,
            end_date__gte=first_day
        ).select_related(
            'employee__user', 'time_off_type'
        ).order_by('start_date')

        # Department filter
        department = self.request.GET.get('department')
        if department:
            time_off_requests = time_off_requests.filter(
                employee__department_id=department
            )

        # Build calendar events
        events = []
        for req in time_off_requests:
            events.append({
                'id': str(req.pk),
                'title': f'{req.employee.full_name} - {req.time_off_type.name}',
                'start': req.start_date.isoformat(),
                'end': (req.end_date + timedelta(days=1)).isoformat(),  # Calendar end is exclusive
                'color': req.time_off_type.color,
                'employee_id': str(req.employee.pk),
                'type': req.time_off_type.name,
            })

        context['events'] = json.dumps(events)
        context['year'] = year
        context['month'] = month
        context['time_off_requests'] = time_off_requests

        # Get departments for filter
        from configurations.models import Department
        context['departments'] = Department.objects.filter(
            tenant=tenant, is_active=True
        )

        # Navigation
        import calendar
        context['month_name'] = calendar.month_name[month]
        context['prev_month'] = month - 1 if month > 1 else 12
        context['prev_year'] = year if month > 1 else year - 1
        context['next_month'] = month + 1 if month < 12 else 1
        context['next_year'] = year if month < 12 else year + 1

        return context


@require_tenant_type('company')
class TimeOffRequestView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Submit time-off request - COMPANY ONLY.
    """
    template_name = 'hr/time_off_request.html'

    def get(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        # Get employee record
        try:
            employee = Employee.objects.get(user=request.user)
        except Employee.DoesNotExist:
            messages.error(request, 'No employee record found.')
            return redirect('hr:employee-directory')

        # Get time-off types
        time_off_types = TimeOffType.objects.filter(is_active=True)

        # Get balances
        balances = TimeOffBalance.objects.filter(
            employee=employee,
            year=timezone.now().year
        ).select_related('time_off_type')

        context = {
            'employee': employee,
            'time_off_types': time_off_types,
            'balances': balances,
        }

        if request.headers.get('HX-Request'):
            return render(request, 'hr/partials/_time_off_request_form.html', context)

        return render(request, self.template_name, context)

    def post(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        try:
            employee = Employee.objects.get(user=request.user)
        except Employee.DoesNotExist:
            return HttpResponse('No employee record', status=400)

        time_off_type_id = request.POST.get('time_off_type')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')
        reason = request.POST.get('reason', '')
        is_half_day = request.POST.get('is_half_day') == 'true'
        half_day_period = request.POST.get('half_day_period', '')

        if not all([time_off_type_id, start_date, end_date]):
            return HttpResponse('Missing required fields', status=400)

        time_off_type = get_object_or_404(TimeOffType, pk=time_off_type_id)

        from django.utils.dateparse import parse_date
        start = parse_date(start_date)
        end = parse_date(end_date)

        if start > end:
            return HttpResponse('End date must be after start date', status=400)

        # Calculate total days
        if is_half_day:
            total_days = Decimal('0.5')
        else:
            # Simple calculation - weekdays only
            total_days = Decimal('0')
            current = start
            while current <= end:
                if current.weekday() < 5:  # Monday to Friday
                    total_days += 1
                current += timedelta(days=1)

        # Check balance if accrued
        if time_off_type.is_accrued:
            try:
                balance = TimeOffBalance.objects.get(
                    employee=employee,
                    time_off_type=time_off_type,
                    year=timezone.now().year
                )
                if balance.balance < total_days:
                    return HttpResponse('Insufficient balance', status=400)
            except TimeOffBalance.DoesNotExist:
                pass

        # Create request
        time_off_request = TimeOffRequest.objects.create(
            employee=employee,
            time_off_type=time_off_type,
            start_date=start,
            end_date=end,
            is_half_day=is_half_day,
            half_day_period=half_day_period,
            total_days=total_days,
            reason=reason,
            status='pending',
        )

        if request.headers.get('HX-Request'):
            response = render(request, 'hr/partials/_time_off_request_success.html', {
                'request': time_off_request
            })
            response['HX-Trigger'] = 'timeOffRequestCreated'
            return response

        messages.success(request, 'Time-off request submitted successfully!')
        return redirect('hr:my-time-off')


@require_tenant_type('company')
class TimeOffApprovalView(LoginRequiredMixin, TenantViewMixin, HRPermissionMixin, View):
    """
    Approve or reject time-off requests - COMPANY ONLY.
    """

    def post(self, request, pk):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        time_off_request = get_object_or_404(
            TimeOffRequest,
            pk=pk,
            employee__user__tenantuser__tenant=tenant
        )

        action = request.POST.get('action')

        if action == 'approve':
            if not self.has_hr_permission('edit'):
                # Check if user is manager
                try:
                    user_employee = Employee.objects.get(user=request.user)
                    if time_off_request.employee.manager != user_employee:
                        return HttpResponse('Not authorized', status=403)
                except Employee.DoesNotExist:
                    return HttpResponse('Not authorized', status=403)

            try:
                time_off_request.approve(request.user)
                message = 'Time-off request approved.'
            except Exception as e:
                return HttpResponse(str(e), status=400)

        elif action == 'reject':
            rejection_reason = request.POST.get('rejection_reason', '')
            time_off_request.reject(request.user, rejection_reason)
            message = 'Time-off request rejected.'

        else:
            return HttpResponse('Invalid action', status=400)

        if request.headers.get('HX-Request'):
            response = HttpResponse(status=204)
            response['HX-Trigger'] = json.dumps({
                'timeOffUpdated': {
                    'id': str(pk),
                    'status': time_off_request.status,
                }
            })
            return response

        messages.success(request, message)
        return redirect(request.META.get('HTTP_REFERER', '/'))


@require_tenant_type('company')
class MyTimeOffView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, TemplateView):
    """
    View for employees to see their time-off history and balances - COMPANY ONLY.
    """
    template_name = 'hr/my_time_off.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if not tenant:
            return context

        try:
            employee = Employee.objects.get(user=self.request.user)
        except Employee.DoesNotExist:
            context['no_employee'] = True
            return context

        context['employee'] = employee

        # Balances
        context['balances'] = TimeOffBalance.objects.filter(
            employee=employee,
            year=timezone.now().year
        ).select_related('time_off_type')

        # Requests
        context['pending_requests'] = employee.time_off_requests.filter(
            status='pending'
        ).order_by('start_date')

        context['approved_requests'] = employee.time_off_requests.filter(
            status='approved',
            end_date__gte=timezone.now().date()
        ).order_by('start_date')

        context['past_requests'] = employee.time_off_requests.filter(
            Q(status='approved', end_date__lt=timezone.now().date()) |
            Q(status__in=['rejected', 'cancelled'])
        ).order_by('-start_date')[:20]

        return context


# =============================================================================
# ORG CHART VIEW
# =============================================================================

@require_tenant_type('company')
class OrgChartView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, TemplateView):
    """
    Organization chart visualization - COMPANY ONLY.

    Displays hierarchical view of the organization.
    """
    template_name = 'hr/org_chart.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if not tenant:
            return context

        # Get all active employees with manager relationships
        employees = Employee.objects.filter(
            user__tenantuser__tenant=tenant,
            status='active'
        ).select_related(
            'user', 'department', 'manager__user'
        ).order_by('user__last_name')

        # Build org tree data for frontend
        org_data = []
        for emp in employees:
            org_data.append({
                'id': str(emp.pk),
                'name': emp.full_name,
                'title': emp.job_title,
                'department': emp.department.name if emp.department else '',
                'image': emp.user.profile_image.url if hasattr(emp.user, 'profile_image') and emp.user.profile_image else None,
                'parent': str(emp.manager.pk) if emp.manager else None,
            })

        context['org_data'] = json.dumps(org_data)
        context['employees'] = employees

        # Get top-level employees (no manager)
        context['top_level'] = employees.filter(manager__isnull=True)

        # Department filter
        from configurations.models import Department
        context['departments'] = Department.objects.filter(
            tenant=tenant, is_active=True
        )

        return context


@require_tenant_type('company')
class OrgChartDataView(LoginRequiredMixin, TenantViewMixin, View):
    """
    JSON endpoint for org chart data (for dynamic loading) - COMPANY ONLY.
    """

    def get(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return JsonResponse({'error': 'No tenant'}, status=403)

        employees = Employee.objects.filter(
            user__tenantuser__tenant=tenant,
            status='active'
        ).select_related('user', 'department', 'manager')

        # Filter by department if specified
        department = request.GET.get('department')
        if department:
            employees = employees.filter(department_id=department)

        data = []
        for emp in employees:
            data.append({
                'id': str(emp.pk),
                'name': emp.full_name,
                'title': emp.job_title,
                'department': emp.department.name if emp.department else '',
                'email': emp.user.email,
                'parent': str(emp.manager.pk) if emp.manager else None,
                'direct_reports_count': emp.direct_reports.filter(status='active').count(),
            })

        return JsonResponse({'employees': data})


# =============================================================================
# ONBOARDING VIEWS
# =============================================================================

@require_tenant_type('company')
class OnboardingDashboardView(LoginRequiredMixin, TenantViewMixin, HRPermissionMixin, HTMXMixin, TemplateView):
    """
    Onboarding dashboard for HR to track all onboardings - COMPANY ONLY.
    """
    template_name = 'hr/onboarding_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()

        if not tenant:
            return context

        # Active onboardings
        context['active_onboardings'] = EmployeeOnboarding.objects.filter(
            employee__user__tenantuser__tenant=tenant,
            completed_at__isnull=True
        ).select_related(
            'employee__user', 'checklist'
        ).prefetch_related('task_progress').order_by('start_date')

        # Recently completed
        context['completed_onboardings'] = EmployeeOnboarding.objects.filter(
            employee__user__tenantuser__tenant=tenant,
            completed_at__isnull=False
        ).select_related('employee__user').order_by('-completed_at')[:10]

        # Checklists for creating new onboarding
        context['checklists'] = OnboardingChecklist.objects.filter(is_active=True)

        return context


@require_tenant_type('company')
class OnboardingDetailView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, DetailView):
    """
    Individual onboarding progress view - COMPANY ONLY.
    """
    model = EmployeeOnboarding
    template_name = 'hr/onboarding_detail.html'
    context_object_name = 'onboarding'

    def get_queryset(self):
        tenant = self.get_tenant()
        if not tenant:
            return EmployeeOnboarding.objects.none()

        return EmployeeOnboarding.objects.filter(
            employee__user__tenantuser__tenant=tenant
        ).select_related(
            'employee__user', 'checklist'
        ).prefetch_related(
            'task_progress__task',
            'task_progress__completed_by'
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        onboarding = self.object

        # Group tasks by category
        tasks_by_category = {}
        for progress in onboarding.task_progress.select_related('task').all():
            category = progress.task.get_category_display()
            if category not in tasks_by_category:
                tasks_by_category[category] = []
            tasks_by_category[category].append(progress)

        context['tasks_by_category'] = tasks_by_category

        return context


@require_tenant_type('company')
class OnboardingTaskCompleteView(LoginRequiredMixin, TenantViewMixin, View):
    """
    Mark an onboarding task as complete - COMPANY ONLY.
    """

    def post(self, request, pk):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        task_progress = get_object_or_404(
            OnboardingTaskProgress,
            pk=pk,
            onboarding__employee__user__tenantuser__tenant=tenant
        )

        task_progress.complete(user=request.user)

        # Check if all required tasks are complete
        onboarding = task_progress.onboarding
        all_complete = not onboarding.task_progress.filter(
            task__is_required=True,
            is_completed=False
        ).exists()

        if all_complete and not onboarding.completed_at:
            onboarding.completed_at = timezone.now()
            onboarding.save(update_fields=['completed_at'])

        if request.headers.get('HX-Request'):
            response = render(request, 'hr/partials/_onboarding_task_item.html', {
                'progress': task_progress
            })
            response['HX-Trigger'] = 'taskCompleted'
            return response

        return redirect('hr:onboarding-detail', pk=onboarding.pk)
