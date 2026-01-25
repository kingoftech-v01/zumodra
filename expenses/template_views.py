"""
Expenses Template Views - Frontend HTML Views
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.db.models import Sum, Count, Q
from django.utils import timezone

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    ExpenseCategory,
    ExpenseReport,
    ExpenseLineItem,
    ExpenseApproval,
    Reimbursement,
    MileageRate,
)


class ExpenseDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main expense dashboard with overview stats"""
    template_name = 'expenses/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get current user's employee record
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
            is_employee = True
        except:
            employee = None
            is_employee = False

        # Filter based on user role
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']:
            # Admins see all expense reports
            reports_queryset = ExpenseReport.objects.filter(tenant=self.request.tenant)
        elif is_employee:
            # Regular employees see only their own
            reports_queryset = ExpenseReport.objects.filter(
                tenant=self.request.tenant,
                employee=employee
            )
        else:
            reports_queryset = ExpenseReport.objects.none()

        # Stats
        context['pending_approval'] = reports_queryset.filter(
            status='pending_approval'
        ).count()

        context['approved_not_paid'] = reports_queryset.filter(
            status='approved'
        ).count()

        context['total_pending_amount'] = reports_queryset.filter(
            status__in=['submitted', 'pending_approval', 'approved']
        ).aggregate(total=Sum('reimbursable_amount'))['total'] or 0

        # Recent expense reports
        context['recent_reports'] = reports_queryset.select_related(
            'employee__user'
        ).order_by('-created_at')[:10]

        # Pending approvals for current user
        if hasattr(self.request.user, 'expense_approvals_given'):
            context['my_pending_approvals'] = ExpenseApproval.objects.filter(
                tenant=self.request.tenant,
                approver=self.request.user,
                action='pending'
            ).count()

        return context


class ExpenseReportListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List expense reports"""
    model = ExpenseReport
    template_name = 'expenses/expense_report_list.html'
    partial_template_name = 'expenses/partials/_expense_report_list.html'
    context_object_name = 'expense_reports'
    paginate_by = 20

    def get_queryset(self):
        queryset = ExpenseReport.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'employee__user'
        ).prefetch_related(
            'line_items',
            'approvals'
        ).order_by('-created_at')

        # Filter based on user role
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee=employee)
            except:
                queryset = ExpenseReport.objects.none()

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Search
        search = self.request.GET.get('q')
        if search:
            queryset = queryset.filter(
                Q(report_number__icontains=search) |
                Q(title__icontains=search) |
                Q(description__icontains=search)
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = ExpenseReport.ReportStatus.choices
        return context


class ExpenseReportDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Expense report detail view"""
    model = ExpenseReport
    template_name = 'expenses/expense_report_detail.html'
    context_object_name = 'expense_report'

    def get_queryset(self):
        queryset = ExpenseReport.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'employee__user',
            'reimbursement'
        ).prefetch_related(
            'line_items__category',
            'approvals__approver'
        )

        # Filter based on user role
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee=employee)
            except:
                queryset = ExpenseReport.objects.none()

        return queryset


class ExpenseCategoryListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List expense categories (read-only)"""
    model = ExpenseCategory
    template_name = 'expenses/expense_category_list.html'
    context_object_name = 'categories'
    paginate_by = 50

    def get_queryset(self):
        return ExpenseCategory.objects.filter(
            tenant=self.request.tenant,
            is_active=True
        ).select_related('parent').order_by('name')


class ExpenseApprovalListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List expense approvals (pending approvals for current user)"""
    model = ExpenseApproval
    template_name = 'expenses/expense_approval_list.html'
    partial_template_name = 'expenses/partials/_expense_approval_list.html'
    context_object_name = 'expense_approvals'
    paginate_by = 20

    def get_queryset(self):
        queryset = ExpenseApproval.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'expense_report__employee__user',
            'approver'
        ).order_by('requested_at')

        # Filter to pending approvals for current user
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor']):
            queryset = queryset.filter(approver=self.request.user)

        # Filter by action
        action = self.request.GET.get('action')
        if action:
            queryset = queryset.filter(action=action)
        else:
            # Default to pending
            queryset = queryset.filter(action='pending')

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['action_choices'] = ExpenseApproval.ApprovalAction.choices
        return context


class ReimbursementListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List reimbursements"""
    model = Reimbursement
    template_name = 'expenses/reimbursement_list.html'
    context_object_name = 'reimbursements'
    paginate_by = 20

    def get_queryset(self):
        queryset = Reimbursement.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'expense_report',
            'employee__user',
            'payment_transaction',
            'payroll_run'
        ).order_by('-created_at')

        # Filter based on user role
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee=employee)
            except:
                queryset = Reimbursement.objects.none()

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = Reimbursement.ReimbursementStatus.choices
        return context


class MileageRateListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List mileage rates (read-only)"""
    model = MileageRate
    template_name = 'expenses/mileage_rate_list.html'
    context_object_name = 'mileage_rates'
    paginate_by = 50

    def get_queryset(self):
        return MileageRate.objects.filter(
            tenant=self.request.tenant,
            is_active=True
        ).order_by('-effective_start')


class HTMXExpenseStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for expense stats"""
    template_name = 'expenses/partials/_quick_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Filter based on user role
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']:
            reports_queryset = ExpenseReport.objects.filter(tenant=self.request.tenant)
        else:
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                reports_queryset = ExpenseReport.objects.filter(
                    tenant=self.request.tenant,
                    employee=employee
                )
            except:
                reports_queryset = ExpenseReport.objects.none()

        context['pending_approval'] = reports_queryset.filter(
            status='pending_approval'
        ).count()

        context['total_pending_amount'] = reports_queryset.filter(
            status__in=['submitted', 'pending_approval', 'approved']
        ).aggregate(total=Sum('reimbursable_amount'))['total'] or 0

        return context
