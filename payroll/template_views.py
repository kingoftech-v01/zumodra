"""
Payroll Template Views - Frontend HTML Views
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView, ListView, DetailView
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import timedelta

from tenants.mixins import TenantViewMixin
from core.mixins import HTMXMixin
from .models import (
    PayrollRun,
    EmployeePayment,
    DirectDeposit,
    PayStub,
    PayrollDeduction,
    PayrollTax,
)


class PayrollDashboardView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """Main payroll dashboard with overview stats"""
    template_name = 'payroll/dashboard.html'

    def dispatch(self, request, *args, **kwargs):
        """Only admins can access payroll"""
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            messages.error(request, 'You do not have permission to access payroll.')
            return redirect('frontend:dashboard:index')
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Recent payroll run
        latest_run = PayrollRun.objects.filter(
            tenant=self.request.tenant
        ).first()

        if latest_run:
            context['latest_run'] = latest_run

        # Current year stats
        current_year = timezone.now().year
        year_start = timezone.datetime(current_year, 1, 1).date()

        year_runs = PayrollRun.objects.filter(
            tenant=self.request.tenant,
            pay_date__gte=year_start
        )

        context['ytd_payroll_count'] = year_runs.count()
        context['ytd_total_paid'] = year_runs.filter(
            status='paid'
        ).aggregate(total=Sum('total_net'))['total'] or 0
        context['ytd_total_taxes'] = year_runs.filter(
            status='paid'
        ).aggregate(total=Sum('total_taxes'))['total'] or 0

        # Pending approvals
        context['pending_approvals'] = PayrollRun.objects.filter(
            tenant=self.request.tenant,
            status='processing'
        ).count()

        # Recent payroll runs
        context['recent_runs'] = PayrollRun.objects.filter(
            tenant=self.request.tenant
        ).select_related('created_by', 'approved_by')[:10]

        return context


class PayrollRunListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List all payroll runs"""
    model = PayrollRun
    template_name = 'payroll/payroll_run_list.html'
    partial_template_name = 'payroll/partials/_payroll_run_list.html'
    context_object_name = 'payroll_runs'
    paginate_by = 20

    def dispatch(self, request, *args, **kwargs):
        """Only admins can access"""
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            messages.error(request, 'You do not have permission to access payroll.')
            return redirect('frontend:dashboard:index')
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        queryset = PayrollRun.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'created_by',
            'approved_by'
        ).order_by('-pay_date')

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Filter by frequency
        frequency = self.request.GET.get('frequency')
        if frequency:
            queryset = queryset.filter(frequency=frequency)

        # Search
        search = self.request.GET.get('q')
        if search:
            queryset = queryset.filter(
                Q(run_number__icontains=search) |
                Q(notes__icontains=search)
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = PayrollRun.PayrollStatus.choices
        context['frequency_choices'] = PayrollRun.PayrollFrequency.choices
        return context


class PayrollRunDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Payroll run detail view"""
    model = PayrollRun
    template_name = 'payroll/payroll_run_detail.html'
    context_object_name = 'payroll_run'

    def dispatch(self, request, *args, **kwargs):
        """Only admins can access"""
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            messages.error(request, 'You do not have permission to access payroll.')
            return redirect('frontend:dashboard:index')
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return PayrollRun.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'created_by',
            'approved_by'
        ).prefetch_related(
            'employee_payments__employee__user',
            'employee_payments__direct_deposit',
            'employee_payments__deductions',
            'employee_payments__tax_records'
        )


class EmployeePaymentListView(LoginRequiredMixin, TenantViewMixin, HTMXMixin, ListView):
    """List employee payments"""
    model = EmployeePayment
    template_name = 'payroll/employee_payment_list.html'
    partial_template_name = 'payroll/partials/_employee_payment_list.html'
    context_object_name = 'employee_payments'
    paginate_by = 20

    def get_queryset(self):
        queryset = EmployeePayment.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'payroll_run',
            'employee__user',
            'direct_deposit',
            'payment_transaction'
        ).order_by('-created_at')

        # Filter by employee (if user is employee, show only their payments)
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            # Regular employees see only their own payments
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee=employee)
            except:
                queryset = EmployeePayment.objects.none()

        # Filter by payroll run
        payroll_run_id = self.request.GET.get('payroll_run')
        if payroll_run_id:
            queryset = queryset.filter(payroll_run_id=payroll_run_id)

        # Filter by paid status
        paid = self.request.GET.get('paid')
        if paid is not None:
            queryset = queryset.filter(paid=paid == 'true')

        return queryset


class EmployeePaymentDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Employee payment detail view"""
    model = EmployeePayment
    template_name = 'payroll/employee_payment_detail.html'
    context_object_name = 'employee_payment'

    def get_queryset(self):
        queryset = EmployeePayment.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'payroll_run',
            'employee__user',
            'direct_deposit',
            'payment_transaction'
        ).prefetch_related(
            'deductions',
            'tax_records'
        )

        # Filter by employee if not admin
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee=employee)
            except:
                queryset = EmployeePayment.objects.none()

        return queryset


class DirectDepositListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List direct deposit accounts"""
    model = DirectDeposit
    template_name = 'payroll/direct_deposit_list.html'
    context_object_name = 'direct_deposits'
    paginate_by = 20

    def get_queryset(self):
        queryset = DirectDeposit.objects.filter(
            tenant=self.request.tenant
        ).select_related('employee__user').order_by('-is_primary', '-created_at')

        # Filter by employee if not admin
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee=employee)
            except:
                queryset = DirectDeposit.objects.none()

        # Filter by verification status
        verified = self.request.GET.get('verified')
        if verified is not None:
            queryset = queryset.filter(verified=verified == 'true')

        return queryset


class DirectDepositDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Direct deposit detail view"""
    model = DirectDeposit
    template_name = 'payroll/direct_deposit_detail.html'
    context_object_name = 'direct_deposit'

    def get_queryset(self):
        queryset = DirectDeposit.objects.filter(
            tenant=self.request.tenant
        ).select_related('employee__user')

        # Filter by employee if not admin
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee=employee)
            except:
                queryset = DirectDeposit.objects.none()

        return queryset


class PayStubListView(LoginRequiredMixin, TenantViewMixin, ListView):
    """List pay stubs"""
    model = PayStub
    template_name = 'payroll/paystub_list.html'
    context_object_name = 'paystubs'
    paginate_by = 20

    def get_queryset(self):
        queryset = PayStub.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'employee_payment__employee__user',
            'employee_payment__payroll_run'
        ).order_by('-generated_at')

        # Filter by employee if not admin
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee_payment__employee=employee)
            except:
                queryset = PayStub.objects.none()

        return queryset


class PayStubDetailView(LoginRequiredMixin, TenantViewMixin, DetailView):
    """Pay stub detail view"""
    model = PayStub
    template_name = 'payroll/paystub_detail.html'
    context_object_name = 'paystub'

    def get_queryset(self):
        queryset = PayStub.objects.filter(
            tenant=self.request.tenant
        ).select_related(
            'employee_payment__employee__user',
            'employee_payment__payroll_run',
            'employee_payment__direct_deposit'
        )

        # Filter by employee if not admin
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            try:
                from hr_core.models import Employee
                employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
                queryset = queryset.filter(employee_payment__employee=employee)
            except:
                queryset = PayStub.objects.none()

        return queryset

    def get_object(self, queryset=None):
        """Mark pay stub as viewed by employee"""
        obj = super().get_object(queryset)

        # If employee is viewing their own pay stub, mark as viewed
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
            if obj.employee_payment.employee == employee and not obj.employee_viewed:
                obj.employee_viewed = True
                obj.employee_viewed_at = timezone.now()
                obj.save(update_fields=['employee_viewed', 'employee_viewed_at'])
        except:
            pass

        return obj


class HTMXPayrollStatsView(LoginRequiredMixin, TenantViewMixin, TemplateView):
    """HTMX partial for payroll stats"""
    template_name = 'payroll/partials/_quick_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Current year stats
        current_year = timezone.now().year
        year_start = timezone.datetime(current_year, 1, 1).date()

        year_runs = PayrollRun.objects.filter(
            tenant=self.request.tenant,
            pay_date__gte=year_start
        )

        context['ytd_total_paid'] = year_runs.filter(
            status='paid'
        ).aggregate(total=Sum('total_net'))['total'] or 0

        context['pending_approvals'] = PayrollRun.objects.filter(
            tenant=self.request.tenant,
            status='processing'
        ).count()

        context['active_employees'] = EmployeePayment.objects.filter(
            tenant=self.request.tenant,
            payroll_run__status='paid'
        ).values('employee').distinct().count()

        return context
