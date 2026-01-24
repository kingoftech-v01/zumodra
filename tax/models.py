"""
Tax App Models - Tax Calculation and Compliance (TENANT Schema)

This app handles tax calculation and compliance:
- Avalara AvaTax API integration for automatic tax calculation
- Tax rates by jurisdiction
- Tax exemptions
- Tax remittance tracking
- Tax reporting (quarterly, annual)

Integrates with payments.PaymentTransaction and subscriptions.SubscriptionInvoice.
"""

from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator
from django.utils import timezone
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from core.models import TenantAwareModel  # Import from core.models instead of defining here


class AvalaraConfig(TenantAwareModel):
    """
    Per-tenant Avalara configuration.

    Each tenant has their own Avalara account for tax calculation.
    """
    # Avalara Credentials (should be encrypted in production)
    account_id = models.CharField(
        max_length=255,
        help_text="Avalara account ID"
    )
    license_key = models.CharField(
        max_length=255,
        help_text="Avalara license key (should be encrypted)"
    )
    company_code = models.CharField(
        max_length=100,
        help_text="Avalara company code"
    )

    # Environment
    is_sandbox = models.BooleanField(
        default=True,
        help_text="Whether to use Avalara sandbox environment"
    )

    # Company Information
    company_name = models.CharField(max_length=255)
    tax_id = models.CharField(
        max_length=50,
        blank=True,
        help_text="Tax ID (EIN, VAT number, etc.)"
    )

    # Default Settings
    default_tax_code = models.CharField(
        max_length=50,
        default='P0000000',
        help_text="Default Avalara tax code for products"
    )
    commit_transactions = models.BooleanField(
        default=False,
        help_text="Whether to auto-commit transactions in Avalara"
    )

    # Status
    is_active = models.BooleanField(default=False)
    last_sync = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Avalara Configuration"
        verbose_name_plural = "Avalara Configurations"

    def __str__(self):
        env = "Sandbox" if self.is_sandbox else "Production"
        status = "Active" if self.is_active else "Inactive"
        return f"{self.company_name} - {env} ({status})"


class TaxRate(TenantAwareModel):
    """
    Tax rates by jurisdiction.

    Can be manually defined or auto-synced from Avalara.
    """
    class TaxType(models.TextChoices):
        SALES = 'sales', 'Sales Tax'
        VAT = 'vat', 'Value Added Tax (VAT)'
        GST = 'gst', 'Goods and Services Tax (GST)'
        PST = 'pst', 'Provincial Sales Tax (PST)'
        HST = 'hst', 'Harmonized Sales Tax (HST)'
        EXCISE = 'excise', 'Excise Tax'

    # Jurisdiction
    country = models.CharField(max_length=2, default='US')
    state_province = models.CharField(
        max_length=100,
        blank=True,
        help_text="State, province, or region"
    )
    county = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)

    # Tax Type
    tax_type = models.CharField(
        max_length=20,
        choices=TaxType.choices,
        default=TaxType.SALES
    )

    # Rate
    rate = models.DecimalField(
        max_digits=7,
        decimal_places=5,
        validators=[MinValueValidator(Decimal('0.00000'))],
        help_text="Tax rate as decimal (e.g., 0.08500 for 8.5%)"
    )

    # Effective Dates
    effective_start = models.DateField()
    effective_end = models.DateField(null=True, blank=True)

    # Avalara Integration
    avalara_jurisdiction_id = models.CharField(max_length=100, blank=True)

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Tax Rate"
        verbose_name_plural = "Tax Rates"
        ordering = ['country', 'state_province', 'city']
        indexes = [
            models.Index(fields=['country', 'state_province']),
            models.Index(fields=['postal_code']),
            models.Index(fields=['is_active', 'effective_start']),
        ]

    def __str__(self):
        location = f"{self.city}, {self.state_province}, {self.country}" if self.city else f"{self.state_province}, {self.country}"
        return f"{location} - {self.get_tax_type_display()}: {self.rate * 100:.2f}%"

    @property
    def rate_percentage(self):
        """Get rate as percentage"""
        return self.rate * 100


class TaxCalculation(TenantAwareModel):
    """
    Calculated tax for a transaction.

    Stores tax calculation results from Avalara or manual calculation.
    """
    class CalculationSource(models.TextChoices):
        AVALARA = 'avalara', 'Avalara AvaTax'
        MANUAL = 'manual', 'Manual Calculation'
        IMPORTED = 'imported', 'Imported'

    # Related Transaction
    payment_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='tax_calculations'
    )
    subscription_invoice = models.ForeignKey(
        'subscriptions.SubscriptionInvoice',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='tax_calculations'
    )

    # Calculation Source
    source = models.CharField(
        max_length=20,
        choices=CalculationSource.choices,
        default=CalculationSource.AVALARA
    )

    # Amounts
    subtotal = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Amount before tax"
    )
    tax_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Total tax amount"
    )
    total = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Subtotal + tax"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Tax Breakdown (by jurisdiction)
    tax_breakdown = models.JSONField(
        default=list,
        help_text="Detailed tax breakdown by jurisdiction"
    )

    # Address Used for Calculation
    tax_address = models.JSONField(
        default=dict,
        help_text="Address used for tax calculation"
    )

    # Avalara Response
    avalara_transaction_code = models.CharField(max_length=255, blank=True)
    avalara_response = models.JSONField(
        default=dict,
        blank=True,
        help_text="Full Avalara API response"
    )

    # Calculation Date
    calculated_at = models.DateTimeField(auto_now_add=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Tax Calculation"
        verbose_name_plural = "Tax Calculations"
        ordering = ['-calculated_at']
        indexes = [
            models.Index(fields=['payment_transaction']),
            models.Index(fields=['subscription_invoice']),
            models.Index(fields=['-calculated_at']),
        ]

    def __str__(self):
        return f"Tax Calculation - {self.currency} {self.tax_amount} ({self.get_source_display()})"

    @property
    def effective_tax_rate(self):
        """Calculate effective tax rate"""
        if self.subtotal > 0:
            return (self.tax_amount / self.subtotal) * 100
        return Decimal('0.00')


class TaxExemption(TenantAwareModel):
    """
    Tax exemption certificate for customers.

    Customers can be exempt from certain taxes (e.g., resale certificates, nonprofit status).
    """
    class ExemptionType(models.TextChoices):
        RESALE = 'resale', 'Resale Certificate'
        NONPROFIT = 'nonprofit', 'Nonprofit Organization'
        GOVERNMENT = 'government', 'Government Entity'
        EDUCATIONAL = 'educational', 'Educational Institution'
        RELIGIOUS = 'religious', 'Religious Organization'
        DIPLOMATIC = 'diplomatic', 'Diplomatic/Consular'
        OTHER = 'other', 'Other'

    class ExemptionStatus(models.TextChoices):
        ACTIVE = 'active', 'Active'
        EXPIRED = 'expired', 'Expired'
        REVOKED = 'revoked', 'Revoked'
        PENDING = 'pending', 'Pending Verification'

    # Customer
    customer = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='tax_exemptions'
    )

    # Exemption Details
    exemption_type = models.CharField(
        max_length=20,
        choices=ExemptionType.choices
    )
    exemption_number = models.CharField(
        max_length=100,
        help_text="Certificate or exemption number"
    )

    # Jurisdiction
    country = models.CharField(max_length=2, default='US')
    state_province = models.CharField(
        max_length=100,
        blank=True,
        help_text="State/province where exemption applies"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=ExemptionStatus.choices,
        default=ExemptionStatus.PENDING,
        db_index=True
    )

    # Dates
    issue_date = models.DateField()
    expiration_date = models.DateField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    # Certificate
    certificate_file = models.FileField(
        upload_to='tax_exemptions/%Y/%m/',
        blank=True,
        null=True,
        help_text="Uploaded exemption certificate"
    )

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Tax Exemption"
        verbose_name_plural = "Tax Exemptions"
        ordering = ['-issue_date']
        indexes = [
            models.Index(fields=['customer', 'status']),
            models.Index(fields=['exemption_number']),
        ]

    def __str__(self):
        return f"{self.customer.get_full_name()} - {self.get_exemption_type_display()} ({self.exemption_number})"

    @property
    def is_valid(self):
        """Check if exemption is currently valid"""
        if self.status != self.ExemptionStatus.ACTIVE:
            return False
        if self.expiration_date and self.expiration_date < timezone.now().date():
            return False
        return True


class TaxRemittance(TenantAwareModel):
    """
    Tax remittance/payment to tax authorities.

    Tracks tax payments to federal, state, and local governments.
    """
    class RemittanceStatus(models.TextChoices):
        SCHEDULED = 'scheduled', 'Scheduled'
        PAID = 'paid', 'Paid'
        FAILED = 'failed', 'Failed'
        OVERDUE = 'overdue', 'Overdue'

    # Remittance Identifier
    remittance_id = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique remittance identifier (auto-generated)"
    )

    # Jurisdiction
    country = models.CharField(max_length=2, default='US')
    state_province = models.CharField(max_length=100, blank=True)
    authority_name = models.CharField(
        max_length=200,
        help_text="Tax authority name (e.g., 'California Department of Tax and Fee Administration')"
    )

    # Period
    period_start = models.DateField()
    period_end = models.DateField()

    # Amounts
    tax_collected = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Total tax collected during period"
    )
    tax_owed = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Total tax owed to authority"
    )
    amount_paid = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Amount paid"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Status
    status = models.CharField(
        max_length=20,
        choices=RemittanceStatus.choices,
        default=RemittanceStatus.SCHEDULED,
        db_index=True
    )

    # Due Date
    due_date = models.DateField()
    paid_at = models.DateTimeField(null=True, blank=True)

    # Filing Information
    filing_frequency = models.CharField(
        max_length=20,
        choices=[
            ('monthly', 'Monthly'),
            ('quarterly', 'Quarterly'),
            ('annual', 'Annual'),
        ],
        default='quarterly'
    )
    filing_reference = models.CharField(
        max_length=100,
        blank=True,
        help_text="Confirmation or filing reference number"
    )

    # Payment Transaction
    payment_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='tax_remittances'
    )

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Tax Remittance"
        verbose_name_plural = "Tax Remittances"
        ordering = ['-due_date']
        indexes = [
            models.Index(fields=['remittance_id']),
            models.Index(fields=['status', 'due_date']),
            models.Index(fields=['country', 'state_province']),
        ]

    def __str__(self):
        location = f"{self.state_province}, {self.country}" if self.state_province else self.country
        return f"{self.remittance_id} - {location} - {self.currency} {self.tax_owed}"

    def save(self, *args, **kwargs):
        # Generate remittance ID if not set
        if not self.remittance_id:
            import uuid
            from datetime import datetime
            date_str = datetime.now().strftime('%Y%m')
            unique_id = uuid.uuid4().hex[:6].upper()
            self.remittance_id = f"TAX-{date_str}-{unique_id}"

        super().save(*args, **kwargs)


class TaxReport(TenantAwareModel):
    """
    Tax report for a specific period.

    Summary of tax collected, exemptions, and remittances.
    """
    class ReportType(models.TextChoices):
        MONTHLY = 'monthly', 'Monthly Report'
        QUARTERLY = 'quarterly', 'Quarterly Report'
        ANNUAL = 'annual', 'Annual Report'
        CUSTOM = 'custom', 'Custom Period'

    # Report Identifier
    report_number = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique report number (auto-generated)"
    )

    # Report Type and Period
    report_type = models.CharField(
        max_length=20,
        choices=ReportType.choices
    )
    period_start = models.DateField()
    period_end = models.DateField()

    # Totals
    total_taxable_sales = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total taxable sales"
    )
    total_exempt_sales = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total tax-exempt sales"
    )
    total_tax_collected = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total tax collected"
    )
    total_tax_remitted = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total tax remitted to authorities"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Breakdown by Jurisdiction
    jurisdiction_breakdown = models.JSONField(
        default=list,
        help_text="Tax breakdown by jurisdiction"
    )

    # Generated By
    generated_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        related_name='tax_reports_generated'
    )
    generated_at = models.DateTimeField(auto_now_add=True)

    # PDF Report
    pdf_file = models.FileField(
        upload_to='tax_reports/%Y/%m/',
        blank=True,
        null=True
    )

    # Metadata
    notes = models.TextField(blank=True)

    class Meta:
        verbose_name = "Tax Report"
        verbose_name_plural = "Tax Reports"
        ordering = ['-period_end']
        indexes = [
            models.Index(fields=['report_number']),
            models.Index(fields=['report_type', '-period_end']),
        ]

    def __str__(self):
        return f"{self.report_number} - {self.get_report_type_display()} ({self.period_start} to {self.period_end})"

    def save(self, *args, **kwargs):
        # Generate report number if not set
        if not self.report_number:
            import uuid
            from datetime import datetime
            date_str = self.period_end.strftime('%Y%m')
            unique_id = uuid.uuid4().hex[:6].upper()
            self.report_number = f"TAXRPT-{date_str}-{unique_id}"

        super().save(*args, **kwargs)
