"""
Expenses App Models - Business Expense Tracking (TENANT Schema)

This app handles employee expense tracking and reimbursement:
- Expense reports with line items
- Approval workflows
- Receipt management
- Reimbursement processing
- Mileage tracking
- Per diem allowances

Integrates with hr_core.Employee and payments.PaymentTransaction.
"""

from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator
from django.utils import timezone
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from core.models import TenantAwareModel  # Import from core.models instead of defining here


class ExpenseCategory(TenantAwareModel):
    """
    Expense category for classification and budgeting.

    Examples: Travel, Meals & Entertainment, Office Supplies, etc.
    """
    # Category Details
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True, db_index=True)
    description = models.TextField(blank=True)

    # Parent Category (for hierarchical categories)
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='subcategories'
    )

    # Settings
    requires_receipt = models.BooleanField(
        default=True,
        help_text="Whether receipts are required for this category"
    )
    requires_justification = models.BooleanField(
        default=False,
        help_text="Whether additional justification is required"
    )

    # Limits
    daily_limit = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Daily spending limit for this category (null = no limit)"
    )
    monthly_limit = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Monthly spending limit for this category (null = no limit)"
    )

    # Tax Treatment
    is_taxable = models.BooleanField(
        default=True,
        help_text="Whether expenses in this category are taxable to employee"
    )

    # GL Code (for accounting integration)
    gl_code = models.CharField(
        max_length=50,
        blank=True,
        help_text="General ledger code for accounting"
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Expense Category"
        verbose_name_plural = "Expense Categories"
        ordering = ['name']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        if self.parent:
            return f"{self.parent.name} > {self.name}"
        return self.name


class ExpenseReport(TenantAwareModel):
    """
    Expense report submitted by employee.

    Contains multiple expense line items and goes through approval workflow.
    """
    class ReportStatus(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        SUBMITTED = 'submitted', 'Submitted'
        PENDING_APPROVAL = 'pending_approval', 'Pending Approval'
        APPROVED = 'approved', 'Approved'
        REJECTED = 'rejected', 'Rejected'
        PAID = 'paid', 'Paid'
        PARTIALLY_PAID = 'partially_paid', 'Partially Paid'

    # Report Identifier
    report_number = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique expense report number (auto-generated)"
    )

    # Employee (from hr_core)
    employee = models.ForeignKey(
        'hr_core.Employee',
        on_delete=models.PROTECT,
        related_name='expense_reports'
    )

    # Report Details
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    purpose = models.TextField(
        blank=True,
        help_text="Business purpose of expenses"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=ReportStatus.choices,
        default=ReportStatus.DRAFT,
        db_index=True
    )

    # Period
    period_start = models.DateField()
    period_end = models.DateField()

    # Totals (calculated from line items)
    total_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total expense amount"
    )
    reimbursable_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Amount to be reimbursed to employee"
    )
    non_reimbursable_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Non-reimbursable amount (e.g., personal expenses)"
    )

    # Dates
    submitted_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    rejected_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Notes
    employee_notes = models.TextField(blank=True)
    approver_notes = models.TextField(blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Expense Report"
        verbose_name_plural = "Expense Reports"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['report_number']),
            models.Index(fields=['employee', 'status']),
            models.Index(fields=['status', '-created_at']),
        ]

    def __str__(self):
        return f"{self.report_number} - {self.employee.user.get_full_name()} - ${self.total_amount}"

    def save(self, *args, **kwargs):
        # Generate report number if not set
        if not self.report_number:
            import uuid
            from datetime import datetime
            date_str = datetime.now().strftime('%Y%m')
            unique_id = uuid.uuid4().hex[:6].upper()
            self.report_number = f"EXP-{date_str}-{unique_id}"

        super().save(*args, **kwargs)

    def calculate_totals(self):
        """Recalculate totals from line items"""
        line_items = self.line_items.all()
        self.total_amount = sum(item.amount for item in line_items)
        self.reimbursable_amount = sum(
            item.amount for item in line_items if item.is_reimbursable
        )
        self.non_reimbursable_amount = self.total_amount - self.reimbursable_amount
        self.save(update_fields=['total_amount', 'reimbursable_amount', 'non_reimbursable_amount'])


class ExpenseLineItem(TenantAwareModel):
    """
    Individual expense within an expense report.
    """
    class ExpenseType(models.TextChoices):
        GENERAL = 'general', 'General Expense'
        MILEAGE = 'mileage', 'Mileage'
        PER_DIEM = 'per_diem', 'Per Diem'

    # Expense Report
    expense_report = models.ForeignKey(
        ExpenseReport,
        on_delete=models.CASCADE,
        related_name='line_items'
    )

    # Expense Details
    expense_type = models.CharField(
        max_length=20,
        choices=ExpenseType.choices,
        default=ExpenseType.GENERAL
    )
    category = models.ForeignKey(
        ExpenseCategory,
        on_delete=models.PROTECT,
        related_name='expense_items'
    )
    description = models.CharField(max_length=500)

    # Date
    expense_date = models.DateField(db_index=True)

    # Amount
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))]
    )
    currency = models.CharField(max_length=3, default='USD')

    # Merchant/Vendor
    merchant = models.CharField(max_length=200, blank=True)
    location = models.CharField(
        max_length=200,
        blank=True,
        help_text="City, state, or country"
    )

    # Mileage (if expense_type = mileage)
    mileage_distance = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Distance in miles/km"
    )
    mileage_rate = models.DecimalField(
        max_digits=6,
        decimal_places=4,
        null=True,
        blank=True,
        help_text="Rate per mile/km"
    )
    mileage_start_location = models.CharField(max_length=200, blank=True)
    mileage_end_location = models.CharField(max_length=200, blank=True)

    # Receipt
    receipt_file = models.FileField(
        upload_to='expense_receipts/%Y/%m/',
        blank=True,
        null=True
    )
    receipt_url = models.URLField(blank=True)

    # Reimbursable
    is_reimbursable = models.BooleanField(
        default=True,
        help_text="Whether this expense should be reimbursed"
    )

    # Billable to Client
    is_billable = models.BooleanField(
        default=False,
        help_text="Whether this expense is billable to a client"
    )
    client_name = models.CharField(
        max_length=200,
        blank=True,
        help_text="Client to bill (if billable)"
    )

    # Notes
    notes = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Expense Line Item"
        verbose_name_plural = "Expense Line Items"
        ordering = ['expense_date']
        indexes = [
            models.Index(fields=['expense_report', 'expense_date']),
            models.Index(fields=['category', 'expense_date']),
        ]

    def __str__(self):
        return f"{self.expense_date} - {self.category.name} - ${self.amount}"

    def save(self, *args, **kwargs):
        # Calculate mileage amount if mileage expense
        if self.expense_type == self.ExpenseType.MILEAGE and self.mileage_distance and self.mileage_rate:
            self.amount = self.mileage_distance * self.mileage_rate

        super().save(*args, **kwargs)


class ExpenseApproval(TenantAwareModel):
    """
    Approval step in expense report workflow.

    Supports multi-level approval (e.g., manager → department head → finance).
    """
    class ApprovalAction(models.TextChoices):
        PENDING = 'pending', 'Pending'
        APPROVED = 'approved', 'Approved'
        REJECTED = 'rejected', 'Rejected'
        RETURNED = 'returned', 'Returned for Revision'

    # Expense Report
    expense_report = models.ForeignKey(
        ExpenseReport,
        on_delete=models.CASCADE,
        related_name='approvals'
    )

    # Approver
    approver = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='expense_approvals_given'
    )
    approver_role = models.CharField(
        max_length=50,
        help_text="Role of approver (Manager, Department Head, Finance, etc.)"
    )

    # Approval Level (for multi-level approval)
    approval_level = models.PositiveSmallIntegerField(
        default=1,
        help_text="Approval level (1 = first level, 2 = second level, etc.)"
    )

    # Action
    action = models.CharField(
        max_length=20,
        choices=ApprovalAction.choices,
        default=ApprovalAction.PENDING,
        db_index=True
    )

    # Comments
    comments = models.TextField(blank=True)

    # Dates
    requested_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Expense Approval"
        verbose_name_plural = "Expense Approvals"
        ordering = ['approval_level', 'requested_at']
        unique_together = [('expense_report', 'approval_level')]
        indexes = [
            models.Index(fields=['expense_report', 'approval_level']),
            models.Index(fields=['approver', 'action']),
        ]

    def __str__(self):
        return f"Level {self.approval_level} - {self.approver.get_full_name()} - {self.get_action_display()}"


class Reimbursement(TenantAwareModel):
    """
    Reimbursement payment to employee for approved expenses.

    Links expense report to payment transaction.
    """
    class ReimbursementStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        PAID = 'paid', 'Paid'
        FAILED = 'failed', 'Failed'
        CANCELED = 'canceled', 'Canceled'

    # Reimbursement Identifier
    reimbursement_id = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique reimbursement identifier (auto-generated)"
    )

    # Expense Report
    expense_report = models.OneToOneField(
        ExpenseReport,
        on_delete=models.PROTECT,
        related_name='reimbursement'
    )

    # Employee
    employee = models.ForeignKey(
        'hr_core.Employee',
        on_delete=models.PROTECT,
        related_name='reimbursements'
    )

    # Amount
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text="Reimbursement amount"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Status
    status = models.CharField(
        max_length=20,
        choices=ReimbursementStatus.choices,
        default=ReimbursementStatus.PENDING,
        db_index=True
    )

    # Payment Method
    payment_method = models.CharField(
        max_length=20,
        choices=[
            ('direct_deposit', 'Direct Deposit'),
            ('check', 'Check'),
            ('payroll', 'Include in Next Payroll'),
        ],
        default='direct_deposit'
    )

    # Payment Transaction
    payment_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='expense_reimbursements'
    )

    # Payroll Run (if payment_method = payroll)
    payroll_run = models.ForeignKey(
        'payroll.PayrollRun',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='expense_reimbursements'
    )

    # Dates
    approved_at = models.DateTimeField(auto_now_add=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Notes
    notes = models.TextField(blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Reimbursement"
        verbose_name_plural = "Reimbursements"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['reimbursement_id']),
            models.Index(fields=['employee', 'status']),
            models.Index(fields=['status', '-created_at']),
        ]

    def __str__(self):
        return f"{self.reimbursement_id} - {self.employee.user.get_full_name()} - ${self.amount}"

    def save(self, *args, **kwargs):
        # Generate reimbursement ID if not set
        if not self.reimbursement_id:
            import uuid
            from datetime import datetime
            date_str = datetime.now().strftime('%Y%m')
            unique_id = uuid.uuid4().hex[:6].upper()
            self.reimbursement_id = f"REIMB-{date_str}-{unique_id}"

        super().save(*args, **kwargs)


class MileageRate(TenantAwareModel):
    """
    Standard mileage reimbursement rates.

    Rates can change over time and vary by country/region.
    """
    # Region
    country = models.CharField(max_length=2, default='US')
    region = models.CharField(
        max_length=100,
        blank=True,
        help_text="State, province, or region"
    )

    # Rate
    rate = models.DecimalField(
        max_digits=6,
        decimal_places=4,
        validators=[MinValueValidator(Decimal('0.0001'))],
        help_text="Rate per mile/km"
    )
    unit = models.CharField(
        max_length=10,
        choices=[('mile', 'Mile'), ('km', 'Kilometer')],
        default='mile'
    )

    # Purpose
    purpose = models.CharField(
        max_length=50,
        choices=[
            ('business', 'Business'),
            ('medical', 'Medical/Moving'),
            ('charity', 'Charity'),
        ],
        default='business'
    )

    # Effective Dates
    effective_start = models.DateField()
    effective_end = models.DateField(null=True, blank=True)

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Mileage Rate"
        verbose_name_plural = "Mileage Rates"
        ordering = ['-effective_start']
        indexes = [
            models.Index(fields=['country', 'effective_start']),
            models.Index(fields=['is_active', 'effective_start']),
        ]

    def __str__(self):
        return f"{self.country} - ${self.rate}/{self.unit} ({self.get_purpose_display()}) - Effective {self.effective_start}"

    @classmethod
    def get_current_rate(cls, country='US', purpose='business'):
        """Get current mileage rate for country and purpose"""
        today = timezone.now().date()
        rate = cls.objects.filter(
            country=country,
            purpose=purpose,
            is_active=True,
            effective_start__lte=today
        ).filter(
            models.Q(effective_end__isnull=True) | models.Q(effective_end__gte=today)
        ).order_by('-effective_start').first()

        return rate.rate if rate else None
