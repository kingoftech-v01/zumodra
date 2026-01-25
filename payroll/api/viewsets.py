"""
Payroll API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from django.utils import timezone

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    PayrollRun,
    EmployeePayment,
    DirectDeposit,
    PayStub,
    PayrollDeduction,
    PayrollTax,
)
from .serializers import (
    PayrollRunListSerializer,
    PayrollRunDetailSerializer,
    PayrollRunCreateSerializer,
    EmployeePaymentListSerializer,
    EmployeePaymentDetailSerializer,
    DirectDepositListSerializer,
    DirectDepositDetailSerializer,
    DirectDepositCreateSerializer,
    PayStubSerializer,
    PayrollDeductionSerializer,
    PayrollTaxSerializer,
)


class PayrollRunViewSet(SecureTenantViewSet):
    """
    Viewset for payroll runs (admin only).
    Only HR managers and admins can manage payroll.
    """
    queryset = PayrollRun.objects.select_related(
        'created_by',
        'approved_by'
    ).prefetch_related(
        'employee_payments__employee__user'
    ).order_by('-pay_date')
    filterset_fields = ['status', 'frequency']
    search_fields = ['run_number', 'notes']
    ordering = ['-pay_date']

    def get_serializer_class(self):
        if self.action == 'list':
            return PayrollRunListSerializer
        if self.action == 'create':
            return PayrollRunCreateSerializer
        return PayrollRunDetailSerializer

    def get_queryset(self):
        """Only admins can view payroll runs"""
        if not (self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
                self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            # Return empty queryset for non-admins
            return PayrollRun.objects.none()

        return super().get_queryset()

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve payroll run (supervisor/PDG only)"""
        payroll_run = self.get_object()

        # Check permissions
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor']):
            return Response(
                {'detail': 'Only supervisors can approve payroll runs'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if payroll_run.status != 'processing':
            return Response(
                {'detail': 'Can only approve payroll runs in processing status'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update status
        payroll_run.status = 'approved'
        payroll_run.approved_by = request.user
        payroll_run.approved_at = timezone.now()
        payroll_run.save(update_fields=['status', 'approved_by', 'approved_at', 'updated_at'])

        serializer = self.get_serializer(payroll_run)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def process(self, request, pk=None):
        """Process payroll run (initiate payment)"""
        payroll_run = self.get_object()

        # Check permissions
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            return Response(
                {'detail': 'Only HR managers can process payroll'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if payroll_run.status != 'approved':
            return Response(
                {'detail': 'Payroll run must be approved before processing'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # TODO: Process actual payments via Stripe/ACH
        # This would typically involve:
        # 1. Creating PaymentTransactions for each employee
        # 2. Initiating ACH transfers to bank accounts
        # 3. Generating pay stubs

        # Update status
        payroll_run.status = 'paid'
        payroll_run.paid_at = timezone.now()
        payroll_run.save(update_fields=['status', 'paid_at', 'updated_at'])

        # Mark all employee payments as paid
        payroll_run.employee_payments.update(paid=True, paid_at=timezone.now())

        serializer = self.get_serializer(payroll_run)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def preview(self, request, pk=None):
        """Preview payroll run totals before approval"""
        payroll_run = self.get_object()

        # Calculate totals from employee payments
        from django.db.models import Sum

        employee_payments = payroll_run.employee_payments.all()

        totals = employee_payments.aggregate(
            total_gross=Sum('gross_amount'),
            total_net=Sum('net_amount'),
            total_taxes=Sum('total_taxes'),
            total_deductions=Sum('total_deductions'),
        )

        # Update payroll run totals
        payroll_run.employee_count = employee_payments.count()
        payroll_run.total_gross = totals['total_gross'] or 0
        payroll_run.total_net = totals['total_net'] or 0
        payroll_run.total_taxes = totals['total_taxes'] or 0
        payroll_run.total_deductions = totals['total_deductions'] or 0
        payroll_run.save()

        serializer = self.get_serializer(payroll_run)
        return Response(serializer.data)


class EmployeePaymentViewSet(SecureTenantViewSet):
    """
    Viewset for employee payments.
    Employees can view their own payments; admins can view all.
    """
    queryset = EmployeePayment.objects.select_related(
        'payroll_run',
        'employee__user',
        'direct_deposit',
        'payment_transaction'
    ).prefetch_related(
        'deductions',
        'tax_records'
    ).order_by('-created_at')
    filterset_fields = ['paid']
    search_fields = ['employee__user__email', 'employee__user__first_name', 'employee__user__last_name']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return EmployeePaymentListSerializer
        return EmployeePaymentDetailSerializer

    def get_queryset(self):
        """Filter based on user permissions"""
        queryset = super().get_queryset()

        # Admins see all payments
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']:
            return queryset

        # Regular employees see only their own payments
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
            return queryset.filter(employee=employee)
        except:
            return EmployeePayment.objects.none()

    @action(detail=False, methods=['get'])
    def my_payments(self, request):
        """Get current user's payments"""
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=request.user, tenant=request.tenant)
            queryset = self.filter_queryset(self.get_queryset()).filter(employee=employee)
            page = self.paginate_queryset(queryset)

            if page is not None:
                serializer = EmployeePaymentListSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = EmployeePaymentListSerializer(queryset, many=True)
            return Response(serializer.data)
        except:
            return Response({'detail': 'Employee record not found'}, status=status.HTTP_404_NOT_FOUND)


class DirectDepositViewSet(SecureTenantViewSet):
    """
    Viewset for direct deposit accounts.
    Employees can manage their own accounts; admins can view all.
    """
    queryset = DirectDeposit.objects.select_related(
        'employee__user'
    ).order_by('-is_primary', '-created_at')
    filterset_fields = ['is_active', 'verified']
    search_fields = ['employee__user__email', 'bank_name']
    ordering = ['-is_primary', '-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return DirectDepositListSerializer
        if self.action == 'create':
            return DirectDepositCreateSerializer
        return DirectDepositDetailSerializer

    def get_queryset(self):
        """Filter based on user permissions"""
        queryset = super().get_queryset()

        # Admins see all accounts
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']:
            return queryset

        # Regular employees see only their own accounts
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
            return queryset.filter(employee=employee)
        except:
            return DirectDeposit.objects.none()

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """Verify direct deposit account (admin only)"""
        direct_deposit = self.get_object()

        # Check permissions
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            return Response(
                {'detail': 'Only HR managers can verify direct deposit accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Update verification status
        direct_deposit.verified = True
        direct_deposit.verified_at = timezone.now()
        direct_deposit.save(update_fields=['verified', 'verified_at', 'updated_at'])

        serializer = self.get_serializer(direct_deposit)
        return Response(serializer.data)


class PayStubViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for pay stubs.
    Pay stubs are generated automatically.
    """
    queryset = PayStub.objects.select_related(
        'employee_payment__employee__user',
        'employee_payment__payroll_run',
        'employee_payment__direct_deposit'
    ).order_by('-generated_at')
    serializer_class = PayStubSerializer
    filterset_fields = ['employee_viewed']
    search_fields = ['stub_number', 'employee_payment__employee__user__email']
    ordering = ['-generated_at']

    def get_queryset(self):
        """Filter based on user permissions"""
        queryset = super().get_queryset()

        # Admins see all pay stubs
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']:
            return queryset

        # Regular employees see only their own pay stubs
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
            return queryset.filter(employee_payment__employee=employee)
        except:
            return PayStub.objects.none()

    @action(detail=True, methods=['get'])
    def download_pdf(self, request, pk=None):
        """Download pay stub PDF"""
        pay_stub = self.get_object()

        # Check if PDF exists
        if not pay_stub.pdf_file:
            return Response(
                {'detail': 'PDF file not generated yet'},
                status=status.HTTP_404_NOT_FOUND
            )

        # TODO: Return file download response
        # This would typically involve:
        # 1. Generating a signed URL for the PDF
        # 2. Returning redirect to the URL
        # 3. Or streaming the file directly

        return Response({
            'pdf_url': pay_stub.pdf_url or pay_stub.pdf_file.url,
            'stub_number': pay_stub.stub_number
        })

    @action(detail=True, methods=['post'])
    def mark_viewed(self, request, pk=None):
        """Mark pay stub as viewed by employee"""
        pay_stub = self.get_object()

        # Validate user is the employee
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=request.user, tenant=request.tenant)
            if pay_stub.employee_payment.employee != employee:
                return Response(
                    {'detail': 'You can only mark your own pay stubs as viewed'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except:
            return Response(
                {'detail': 'Employee record not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Update viewed status
        if not pay_stub.employee_viewed:
            pay_stub.employee_viewed = True
            pay_stub.employee_viewed_at = timezone.now()
            pay_stub.save(update_fields=['employee_viewed', 'employee_viewed_at'])

        serializer = self.get_serializer(pay_stub)
        return Response(serializer.data)


class PayrollDeductionViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for payroll deductions.
    Deductions are created automatically from employee benefits.
    """
    queryset = PayrollDeduction.objects.select_related(
        'employee_payment__employee__user',
        'employee_payment__payroll_run'
    ).order_by('deduction_type')
    serializer_class = PayrollDeductionSerializer
    filterset_fields = ['deduction_type', 'pre_tax']
    search_fields = ['description']
    ordering = ['deduction_type']


class PayrollTaxViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for payroll taxes.
    Taxes are calculated automatically.
    """
    queryset = PayrollTax.objects.select_related(
        'employee_payment__employee__user',
        'employee_payment__payroll_run'
    ).order_by('tax_type')
    serializer_class = PayrollTaxSerializer
    filterset_fields = ['tax_type', 'jurisdiction']
    search_fields = ['jurisdiction']
    ordering = ['tax_type']
