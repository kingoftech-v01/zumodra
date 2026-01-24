"""
Expenses API ViewSets
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q
from django.utils import timezone

from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet
from ..models import (
    ExpenseCategory,
    ExpenseReport,
    ExpenseLineItem,
    ExpenseApproval,
    Reimbursement,
    MileageRate,
)
from .serializers import (
    ExpenseCategorySerializer,
    ExpenseReportListSerializer,
    ExpenseReportDetailSerializer,
    ExpenseReportCreateSerializer,
    ExpenseLineItemListSerializer,
    ExpenseLineItemDetailSerializer,
    ExpenseApprovalListSerializer,
    ExpenseApprovalDetailSerializer,
    ReimbursementSerializer,
    MileageRateSerializer,
)


class ExpenseCategoryViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for expense categories.
    Categories are managed by administrators.
    """
    queryset = ExpenseCategory.objects.filter(is_active=True).select_related('parent').order_by('name')
    serializer_class = ExpenseCategorySerializer
    filterset_fields = ['parent', 'requires_receipt']
    search_fields = ['name', 'description']
    ordering = ['name']


class ExpenseReportViewSet(SecureTenantViewSet):
    """
    Viewset for expense reports.
    Employees can manage their own reports; admins can view all.
    """
    queryset = ExpenseReport.objects.select_related(
        'employee__user',
        'reimbursement'
    ).prefetch_related(
        'line_items__category',
        'approvals__approver'
    ).order_by('-created_at')
    filterset_fields = ['status']
    search_fields = ['report_number', 'title', 'description']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ExpenseReportListSerializer
        if self.action == 'create':
            return ExpenseReportCreateSerializer
        return ExpenseReportDetailSerializer

    def get_queryset(self):
        """Filter based on user permissions"""
        queryset = super().get_queryset()

        # Admins see all reports
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']:
            return queryset

        # Regular employees see only their own reports
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
            return queryset.filter(employee=employee)
        except:
            return ExpenseReport.objects.none()

    @action(detail=False, methods=['get'])
    def my_reports(self, request):
        """Get current user's expense reports"""
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=request.user, tenant=request.tenant)
            queryset = self.filter_queryset(self.get_queryset()).filter(employee=employee)
            page = self.paginate_queryset(queryset)

            if page is not None:
                serializer = ExpenseReportListSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = ExpenseReportListSerializer(queryset, many=True)
            return Response(serializer.data)
        except:
            return Response({'detail': 'Employee record not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['post'])
    def submit(self, request, pk=None):
        """Submit expense report for approval"""
        expense_report = self.get_object()

        # Validate user is employee
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=request.user, tenant=request.tenant)
            if expense_report.employee != employee:
                return Response(
                    {'detail': 'You can only submit your own expense reports'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except:
            return Response({'detail': 'Employee record not found'}, status=status.HTTP_404_NOT_FOUND)

        # Validate status
        if expense_report.status != 'draft':
            return Response(
                {'detail': 'Can only submit expense reports in draft status'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate has line items
        if not expense_report.line_items.exists():
            return Response(
                {'detail': 'Cannot submit expense report without line items'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Recalculate totals
        expense_report.calculate_totals()

        # Update status
        expense_report.status = 'pending_approval'
        expense_report.submitted_at = timezone.now()
        expense_report.save(update_fields=['status', 'submitted_at', 'updated_at'])

        # TODO: Create ExpenseApproval records based on approval workflow

        serializer = self.get_serializer(expense_report)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def recall(self, request, pk=None):
        """Recall submitted expense report"""
        expense_report = self.get_object()

        # Validate user is employee
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=request.user, tenant=request.tenant)
            if expense_report.employee != employee:
                return Response(
                    {'detail': 'You can only recall your own expense reports'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except:
            return Response({'detail': 'Employee record not found'}, status=status.HTTP_404_NOT_FOUND)

        # Validate status
        if expense_report.status not in ['submitted', 'pending_approval']:
            return Response(
                {'detail': 'Can only recall submitted or pending expense reports'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update status
        expense_report.status = 'draft'
        expense_report.save(update_fields=['status', 'updated_at'])

        serializer = self.get_serializer(expense_report)
        return Response(serializer.data)


class ExpenseLineItemViewSet(SecureTenantViewSet):
    """
    Viewset for expense line items.
    """
    queryset = ExpenseLineItem.objects.select_related(
        'expense_report__employee__user',
        'category'
    ).order_by('expense_date')
    filterset_fields = ['expense_type', 'category', 'is_reimbursable']
    search_fields = ['description', 'merchant']
    ordering = ['expense_date']

    def get_serializer_class(self):
        if self.action == 'list':
            return ExpenseLineItemListSerializer
        return ExpenseLineItemDetailSerializer

    @action(detail=True, methods=['post'])
    def upload_receipt(self, request, pk=None):
        """Upload receipt for expense line item"""
        line_item = self.get_object()

        # TODO: Handle file upload
        # This would typically involve:
        # 1. Validating file type and size
        # 2. Uploading to storage (S3, etc.)
        # 3. Updating receipt_file or receipt_url

        serializer = self.get_serializer(line_item)
        return Response(serializer.data)


class ExpenseApprovalViewSet(SecureTenantViewSet):
    """
    Viewset for expense approvals.
    Approvers can view and action their pending approvals.
    """
    queryset = ExpenseApproval.objects.select_related(
        'expense_report__employee__user',
        'approver'
    ).order_by('requested_at')
    filterset_fields = ['action', 'approval_level']
    search_fields = ['expense_report__report_number', 'comments']
    ordering = ['requested_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ExpenseApprovalListSerializer
        return ExpenseApprovalDetailSerializer

    def get_queryset(self):
        """Filter to approvals for current user"""
        queryset = super().get_queryset()

        # Admins see all approvals
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor']:
            return queryset

        # Regular users see only their approvals
        return queryset.filter(approver=self.request.user)

    @action(detail=False, methods=['get'])
    def pending_approvals(self, request):
        """Get pending approvals for current user"""
        queryset = self.filter_queryset(self.get_queryset()).filter(
            approver=request.user,
            action='pending'
        )
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = ExpenseApprovalListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = ExpenseApprovalListSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve expense"""
        approval = self.get_object()

        # Validate user is approver
        if approval.approver != request.user:
            return Response(
                {'detail': 'Only the assigned approver can approve'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if approval.action != 'pending':
            return Response(
                {'detail': 'Approval already actioned'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update approval
        approval.action = 'approved'
        approval.comments = request.data.get('comments', '')
        approval.responded_at = timezone.now()
        approval.save()

        # Check if all approvals are complete
        expense_report = approval.expense_report
        all_approved = not expense_report.approvals.filter(action='pending').exists()

        if all_approved:
            expense_report.status = 'approved'
            expense_report.approved_at = timezone.now()
            expense_report.save(update_fields=['status', 'approved_at', 'updated_at'])

        serializer = self.get_serializer(approval)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject expense"""
        approval = self.get_object()

        # Validate user is approver
        if approval.approver != request.user:
            return Response(
                {'detail': 'Only the assigned approver can reject'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if approval.action != 'pending':
            return Response(
                {'detail': 'Approval already actioned'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update approval
        approval.action = 'rejected'
        approval.comments = request.data.get('comments', '')
        approval.responded_at = timezone.now()
        approval.save()

        # Update expense report
        expense_report = approval.expense_report
        expense_report.status = 'rejected'
        expense_report.rejected_at = timezone.now()
        expense_report.approver_notes = approval.comments
        expense_report.save(update_fields=['status', 'rejected_at', 'approver_notes', 'updated_at'])

        serializer = self.get_serializer(approval)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def return_for_revision(self, request, pk=None):
        """Return expense for revision"""
        approval = self.get_object()

        # Validate user is approver
        if approval.approver != request.user:
            return Response(
                {'detail': 'Only the assigned approver can return for revision'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if approval.action != 'pending':
            return Response(
                {'detail': 'Approval already actioned'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update approval
        approval.action = 'returned'
        approval.comments = request.data.get('comments', '')
        approval.responded_at = timezone.now()
        approval.save()

        # Update expense report
        expense_report = approval.expense_report
        expense_report.status = 'draft'
        expense_report.approver_notes = approval.comments
        expense_report.save(update_fields=['status', 'approver_notes', 'updated_at'])

        serializer = self.get_serializer(approval)
        return Response(serializer.data)


class ReimbursementViewSet(SecureTenantViewSet):
    """
    Viewset for reimbursements.
    """
    queryset = Reimbursement.objects.select_related(
        'expense_report',
        'employee__user',
        'payment_transaction',
        'payroll_run'
    ).order_by('-created_at')
    serializer_class = ReimbursementSerializer
    filterset_fields = ['status', 'payment_method']
    search_fields = ['reimbursement_id', 'expense_report__report_number']
    ordering = ['-created_at']

    def get_queryset(self):
        """Filter based on user permissions"""
        queryset = super().get_queryset()

        # Admins see all reimbursements
        if self.request.user.is_staff or hasattr(self.request.user, 'tenant_user') and \
           self.request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']:
            return queryset

        # Regular employees see only their own reimbursements
        try:
            from hr_core.models import Employee
            employee = Employee.objects.get(user=self.request.user, tenant=self.request.tenant)
            return queryset.filter(employee=employee)
        except:
            return Reimbursement.objects.none()

    @action(detail=True, methods=['post'])
    def process(self, request, pk=None):
        """Process reimbursement payment (admin only)"""
        reimbursement = self.get_object()

        # Check permissions
        if not (request.user.is_staff or hasattr(request.user, 'tenant_user') and \
                request.user.tenant_user.role in ['pdg', 'supervisor', 'hr_manager']):
            return Response(
                {'detail': 'Only administrators can process reimbursements'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate status
        if reimbursement.status != 'pending':
            return Response(
                {'detail': 'Can only process pending reimbursements'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # TODO: Process actual payment
        # This would typically involve:
        # 1. Creating PaymentTransaction
        # 2. Initiating transfer to employee bank account
        # 3. Or adding to next payroll run

        # Update status
        reimbursement.status = 'paid'
        reimbursement.paid_at = timezone.now()
        reimbursement.save(update_fields=['status', 'paid_at', 'updated_at'])

        # Update expense report
        reimbursement.expense_report.status = 'paid'
        reimbursement.expense_report.paid_at = timezone.now()
        reimbursement.expense_report.save(update_fields=['status', 'paid_at', 'updated_at'])

        serializer = self.get_serializer(reimbursement)
        return Response(serializer.data)


class MileageRateViewSet(SecureReadOnlyViewSet):
    """
    Read-only viewset for mileage rates.
    Rates are managed by administrators.
    """
    queryset = MileageRate.objects.filter(is_active=True).order_by('-effective_start')
    serializer_class = MileageRateSerializer
    filterset_fields = ['country', 'purpose']
    search_fields = ['country', 'region']
    ordering = ['-effective_start']

    @action(detail=False, methods=['get'])
    def current_rate(self, request):
        """Get current mileage rate"""
        country = request.query_params.get('country', 'US')
        purpose = request.query_params.get('purpose', 'business')

        rate = MileageRate.get_current_rate(country=country, purpose=purpose)

        if rate:
            return Response({'rate': float(rate), 'country': country, 'purpose': purpose})
        else:
            return Response(
                {'detail': 'No active mileage rate found for specified country and purpose'},
                status=status.HTTP_404_NOT_FOUND
            )
