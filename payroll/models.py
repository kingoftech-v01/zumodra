"""
Payroll App Models - Employee Payroll Processing (TENANT Schema)

This app handles employee payroll:
- Payroll runs (weekly, biweekly, monthly)
- Employee payments with tax calculations
- Direct deposit management
- Pay stubs and deductions

Integrates with hr_core.Employee and payments.PaymentTransaction.
"""

from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator
from django.utils import timezone
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from core.models import TenantAwareModel  # Import from core.models instead of defining here


class PayrollRun(TenantAwareModel):
    """
    Payroll cycle/run.

    Represents a single payroll period (weekly, biweekly, monthly).
    Contains multiple employee payments.
    """
    class PayrollStatus(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        PROCESSING = 'processing', 'Processing'
        APPROVED = 'approved', 'Approved'
        PAID = 'paid', 'Paid'
        FAILED = 'failed', 'Failed'

    class PayrollFrequency(models.TextChoices):
        WEEKLY = 'weekly', 'Weekly'
        BIWEEKLY = 'biweekly', 'Bi-weekly'
        SEMI_MONTHLY = 'semi_monthly', 'Semi-monthly'
        MONTHLY = 'monthly', 'Monthly'

    # Run Identifier
    run_number = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Payroll run number (e.g., 2026-01-001)"
    )

    # Payroll Period
    frequency = models.CharField(
        max_length=20,
        choices=PayrollFrequency.choices,
        default=PayrollFrequency.BIWEEKLY
    )
    pay_period_start = models.DateField(
        help_text="Start date of pay period"
    )
    pay_period_end = models.DateField(
        help_text="End date of pay period"
    )
    pay_date = models.DateField(
        help_text="Date employees will be paid"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=PayrollStatus.choices,
        default=PayrollStatus.DRAFT,
        db_index=True
    )

    # Totals
    employee_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of employees in this payroll run"
    )
    total_gross = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total gross wages"
    )
    total_net = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total net pay"
    )
    total_taxes = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total tax withholdings"
    )
    total_deductions = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total deductions (benefits, 401k, etc.)"
    )

    # Created By
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='payroll_runs_created'
    )
    approved_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='payroll_runs_approved'
    )

    # Dates
    approved_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Notes
    notes = models.TextField(blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Payroll Run"
        verbose_name_plural = "Payroll Runs"
        ordering = ['-pay_date']
        indexes = [
            models.Index(fields=['run_number']),
            models.Index(fields=['status', '-pay_date']),
            models.Index(fields=['-pay_date']),
        ]

    def __str__(self):
        return f"Payroll {self.run_number} - {self.pay_period_start} to {self.pay_period_end}"

    def save(self, *args, **kwargs):
        # Generate run number if not set
        if not self.run_number:
            from datetime import datetime
            year_month = self.pay_period_end.strftime('%Y-%m')
            # Find highest number for this month
            last_run = PayrollRun.objects.filter(
                run_number__startswith=year_month
            ).order_by('-run_number').first()

            if last_run:
                try:
                    last_number = int(last_run.run_number.split('-')[-1])
                    next_number = last_number + 1
                except (ValueError, IndexError):
                    next_number = 1
            else:
                next_number = 1

            self.run_number = f"{year_month}-{next_number:03d}"

        super().save(*args, **kwargs)


class DirectDeposit(TenantAwareModel):
    """
    Employee bank account for direct deposit.

    Stores bank account information securely for payroll deposits.
    """
    class AccountType(models.TextChoices):
        CHECKING = 'checking', 'Checking'
        SAVINGS = 'savings', 'Savings'

    # Employee (from hr_core)
    employee = models.ForeignKey(
        'hr_core.Employee',
        on_delete=models.CASCADE,
        related_name='direct_deposits'
    )

    # Bank Details
    account_type = models.CharField(
        max_length=20,
        choices=AccountType.choices,
        default=AccountType.CHECKING
    )
    routing_number = models.CharField(
        max_length=9,
        help_text="Bank routing number (encrypted in production)"
    )
    account_number_last4 = models.CharField(
        max_length=4,
        help_text="Last 4 digits of account number"
    )
    bank_name = models.CharField(max_length=200, blank=True)

    # Encrypted Full Account Number (in production, use django-encrypted-model-fields)
    account_number = models.CharField(
        max_length=255,
        help_text="Full account number (should be encrypted)"
    )

    # Allocation (percentage or fixed amount)
    allocation_type = models.CharField(
        max_length=20,
        choices=[
            ('percentage', 'Percentage'),
            ('fixed', 'Fixed Amount'),
            ('remainder', 'Remainder'),
        ],
        default='remainder'
    )
    allocation_value = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Percentage (0-100) or fixed amount"
    )

    # Status
    is_active = models.BooleanField(default=True)
    is_primary = models.BooleanField(
        default=True,
        help_text="Primary account for payroll"
    )

    # Verification
    verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Direct Deposit"
        verbose_name_plural = "Direct Deposits"
        ordering = ['-is_primary', '-created_at']

    def __str__(self):
        return f"{self.bank_name} ****{self.account_number_last4} ({self.get_account_type_display()})"


class EmployeePayment(TenantAwareModel):
    """
    Individual employee payment within a payroll run.

    Contains gross pay, taxes, deductions, and net pay for one employee.
    """
    # Payroll Run
    payroll_run = models.ForeignKey(
        PayrollRun,
        on_delete=models.CASCADE,
        related_name='employee_payments'
    )

    # Employee (from hr_core)
    employee = models.ForeignKey(
        'hr_core.Employee',
        on_delete=models.PROTECT,
        related_name='payroll_payments'
    )

    # Gross Amount (base salary for period)
    gross_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Gross wages before deductions"
    )

    # Hours (if hourly employee)
    regular_hours = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Regular hours worked"
    )
    overtime_hours = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Overtime hours worked"
    )
    hourly_rate = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Hourly rate (if applicable)"
    )

    # Bonuses and Adjustments
    bonus_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Bonus or commission"
    )
    adjustment_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Manual adjustment (can be negative)"
    )

    # Taxes (calculated by tax app)
    federal_tax = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Federal income tax withheld"
    )
    state_tax = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="State income tax withheld"
    )
    local_tax = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Local income tax withheld"
    )
    social_security = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Social Security (FICA) tax"
    )
    medicare = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Medicare tax"
    )

    # Total Taxes
    total_taxes = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Sum of all taxes"
    )

    # Deductions (benefits, 401k, etc.)
    total_deductions = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Sum of all deductions"
    )

    # Net Amount (gross - taxes - deductions)
    net_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Net pay (take-home)"
    )

    # Payment Details
    payment_method = models.CharField(
        max_length=20,
        choices=[
            ('direct_deposit', 'Direct Deposit'),
            ('check', 'Check'),
            ('cash', 'Cash'),
        ],
        default='direct_deposit'
    )
    direct_deposit = models.ForeignKey(
        DirectDeposit,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Direct deposit account used"
    )

    # Payment Transaction
    payment_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='payroll_payments',
        help_text="Payment transaction record"
    )

    # Status
    paid = models.BooleanField(default=False)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Year-to-Date Totals (for tax reporting)
    ytd_gross = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Year-to-date gross"
    )
    ytd_taxes = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Year-to-date taxes"
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Employee Payment"
        verbose_name_plural = "Employee Payments"
        ordering = ['employee__user__last_name', 'employee__user__first_name']
        unique_together = [('payroll_run', 'employee')]
        indexes = [
            models.Index(fields=['payroll_run', 'employee']),
            models.Index(fields=['employee', '-created_at']),
        ]

    def __str__(self):
        return f"{self.employee.user.get_full_name()} - {self.payroll_run.run_number} - ${self.net_amount}"

    def save(self, *args, **kwargs):
        # Calculate total taxes
        self.total_taxes = (
            self.federal_tax +
            self.state_tax +
            self.local_tax +
            self.social_security +
            self.medicare
        )

        # Calculate net amount
        self.net_amount = self.gross_amount + self.bonus_amount + self.adjustment_amount - self.total_taxes - self.total_deductions

        super().save(*args, **kwargs)


class PayrollDeduction(TenantAwareModel):
    """
    Deduction from employee payment.

    Examples: Health insurance, 401k, garnishments, union dues, etc.
    """
    class DeductionType(models.TextChoices):
        HEALTH_INSURANCE = 'health_insurance', 'Health Insurance'
        DENTAL_INSURANCE = 'dental_insurance', 'Dental Insurance'
        VISION_INSURANCE = 'vision_insurance', 'Vision Insurance'
        RETIREMENT_401K = 'retirement_401k', '401(k) Retirement'
        RETIREMENT_IRA = 'retirement_ira', 'IRA Retirement'
        HSA = 'hsa', 'Health Savings Account'
        FSA = 'fsa', 'Flexible Spending Account'
        UNION_DUES = 'union_dues', 'Union Dues'
        GARNISHMENT = 'garnishment', 'Wage Garnishment'
        CHILD_SUPPORT = 'child_support', 'Child Support'
        LOAN_REPAYMENT = 'loan_repayment', 'Loan Repayment'
        OTHER = 'other', 'Other'

    # Employee Payment
    employee_payment = models.ForeignKey(
        EmployeePayment,
        on_delete=models.CASCADE,
        related_name='deductions'
    )

    # Deduction Details
    deduction_type = models.CharField(
        max_length=30,
        choices=DeductionType.choices
    )
    description = models.CharField(max_length=255)

    # Amount
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))]
    )

    # Tax Treatment
    pre_tax = models.BooleanField(
        default=False,
        help_text="Whether deduction is pre-tax (reduces taxable income)"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Payroll Deduction"
        verbose_name_plural = "Payroll Deductions"
        ordering = ['deduction_type']

    def __str__(self):
        return f"{self.get_deduction_type_display()} - ${self.amount}"


class PayStub(TenantAwareModel):
    """
    Generated pay stub for employee payment.

    Electronic or printable record of payment details.
    """
    # Employee Payment
    employee_payment = models.OneToOneField(
        EmployeePayment,
        on_delete=models.CASCADE,
        related_name='pay_stub'
    )

    # Pay Stub Number
    stub_number = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique pay stub number"
    )

    # PDF Generation
    pdf_file = models.FileField(
        upload_to='paystubs/%Y/%m/',
        blank=True,
        null=True,
        help_text="Generated PDF pay stub"
    )
    pdf_url = models.URLField(blank=True)

    # Employee Access
    employee_viewed = models.BooleanField(default=False)
    employee_viewed_at = models.DateTimeField(null=True, blank=True)

    # Generated At
    generated_at = models.DateTimeField(auto_now_add=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Pay Stub"
        verbose_name_plural = "Pay Stubs"
        ordering = ['-generated_at']

    def __str__(self):
        return f"Pay Stub {self.stub_number} - {self.employee_payment.employee.user.get_full_name()}"

    def save(self, *args, **kwargs):
        # Generate stub number if not set
        if not self.stub_number:
            import uuid
            date_str = self.employee_payment.payroll_run.pay_date.strftime('%Y%m%d')
            unique_id = uuid.uuid4().hex[:6].upper()
            self.stub_number = f"PS-{date_str}-{unique_id}"

        super().save(*args, **kwargs)


class PayrollTax(TenantAwareModel):
    """
    Tax withholding record for compliance and reporting.

    Tracks tax calculations per employee per pay period.
    """
    class TaxType(models.TextChoices):
        FEDERAL_INCOME = 'federal_income', 'Federal Income Tax'
        STATE_INCOME = 'state_income', 'State Income Tax'
        LOCAL_INCOME = 'local_income', 'Local Income Tax'
        SOCIAL_SECURITY = 'social_security', 'Social Security (FICA)'
        MEDICARE = 'medicare', 'Medicare'
        UNEMPLOYMENT = 'unemployment', 'Unemployment Tax'

    # Employee Payment
    employee_payment = models.ForeignKey(
        EmployeePayment,
        on_delete=models.CASCADE,
        related_name='tax_records'
    )

    # Tax Details
    tax_type = models.CharField(
        max_length=30,
        choices=TaxType.choices
    )
    taxable_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Amount subject to this tax"
    )
    tax_rate = models.DecimalField(
        max_digits=6,
        decimal_places=4,
        help_text="Tax rate as decimal (e.g., 0.22 for 22%)"
    )
    tax_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Calculated tax amount"
    )

    # Jurisdiction
    jurisdiction = models.CharField(
        max_length=100,
        blank=True,
        help_text="State, city, or other jurisdiction"
    )

    # Calculation Metadata
    calculation_data = models.JSONField(
        default=dict,
        blank=True,
        help_text="Tax calculation details (brackets, deductions, etc.)"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Payroll Tax"
        verbose_name_plural = "Payroll Taxes"
        ordering = ['tax_type']

    def __str__(self):
        return f"{self.get_tax_type_display()} - ${self.tax_amount}"
