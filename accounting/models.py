"""
Accounting App Models - Accounting Integration (TENANT Schema)

This app handles accounting software integration:
- QuickBooks Online API integration
- Xero API integration
- Chart of accounts mapping
- Journal entries (double-entry bookkeeping)
- Financial reports (P&L, Balance Sheet, Cash Flow)
- Bank reconciliation

Integrates with payments, invoices, and expenses for automatic accounting sync.
"""

from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator
from django.utils import timezone
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from core.models import TenantAwareModel  # Import from core.models instead of defining here


class AccountingProvider(TenantAwareModel):
    """
    Per-tenant accounting software configuration.

    Supports QuickBooks Online and Xero.
    """
    class ProviderType(models.TextChoices):
        QUICKBOOKS = 'quickbooks', 'QuickBooks Online'
        XERO = 'xero', 'Xero'
        MANUAL = 'manual', 'Manual Entry'

    class SyncStatus(models.TextChoices):
        CONNECTED = 'connected', 'Connected'
        DISCONNECTED = 'disconnected', 'Disconnected'
        ERROR = 'error', 'Error'
        SYNCING = 'syncing', 'Syncing'

    # Provider Details
    provider = models.CharField(
        max_length=20,
        choices=ProviderType.choices,
        db_index=True
    )

    # OAuth Credentials (should be encrypted in production)
    access_token = models.CharField(
        max_length=500,
        blank=True,
        help_text="OAuth access token (should be encrypted)"
    )
    refresh_token = models.CharField(
        max_length=500,
        blank=True,
        help_text="OAuth refresh token (should be encrypted)"
    )
    token_expires_at = models.DateTimeField(null=True, blank=True)

    # Provider-Specific IDs
    realm_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="QuickBooks Company ID"
    )
    xero_tenant_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Xero Tenant ID"
    )

    # Company Information
    company_name = models.CharField(max_length=255)
    base_currency = models.CharField(max_length=3, default='USD')

    # Sync Settings
    auto_sync = models.BooleanField(
        default=False,
        help_text="Automatically sync transactions"
    )
    sync_frequency = models.CharField(
        max_length=20,
        choices=[
            ('realtime', 'Real-time'),
            ('hourly', 'Hourly'),
            ('daily', 'Daily'),
            ('manual', 'Manual Only'),
        ],
        default='daily'
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=SyncStatus.choices,
        default=SyncStatus.DISCONNECTED,
        db_index=True
    )
    last_sync = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Accounting Provider"
        verbose_name_plural = "Accounting Providers"

    def __str__(self):
        return f"{self.company_name} - {self.get_provider_display()} ({self.get_status_display()})"

    @property
    def is_token_expired(self):
        """Check if OAuth token is expired"""
        if self.token_expires_at:
            return timezone.now() >= self.token_expires_at
        return True


class ChartOfAccounts(TenantAwareModel):
    """
    Chart of accounts from accounting software.

    Maps general ledger accounts from QuickBooks/Xero.
    """
    class AccountType(models.TextChoices):
        ASSET = 'asset', 'Asset'
        LIABILITY = 'liability', 'Liability'
        EQUITY = 'equity', 'Equity'
        REVENUE = 'revenue', 'Revenue'
        EXPENSE = 'expense', 'Expense'
        COST_OF_GOODS_SOLD = 'cost_of_goods_sold', 'Cost of Goods Sold'

    # Accounting Provider
    provider = models.ForeignKey(
        AccountingProvider,
        on_delete=models.CASCADE,
        related_name='accounts'
    )

    # Account Details
    account_name = models.CharField(max_length=255)
    account_number = models.CharField(max_length=50, blank=True)
    account_type = models.CharField(
        max_length=30,
        choices=AccountType.choices
    )
    description = models.TextField(blank=True)

    # Parent Account (for sub-accounts)
    parent_account = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='sub_accounts'
    )

    # Provider Account ID
    provider_account_id = models.CharField(
        max_length=255,
        help_text="Account ID in QuickBooks/Xero"
    )

    # Balance
    current_balance = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Current account balance"
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    last_synced = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Chart of Accounts"
        verbose_name_plural = "Chart of Accounts"
        ordering = ['account_type', 'account_number', 'account_name']
        indexes = [
            models.Index(fields=['provider', 'account_type']),
            models.Index(fields=['provider_account_id']),
        ]

    def __str__(self):
        if self.account_number:
            return f"{self.account_number} - {self.account_name}"
        return self.account_name


class JournalEntry(TenantAwareModel):
    """
    Journal entry for double-entry bookkeeping.

    Records financial transactions with debits and credits.
    """
    class EntryStatus(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        POSTED = 'posted', 'Posted'
        VOID = 'void', 'Void'

    # Entry Identifier
    entry_number = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique journal entry number (auto-generated)"
    )

    # Entry Details
    entry_date = models.DateField(db_index=True)
    description = models.TextField()
    reference = models.CharField(
        max_length=100,
        blank=True,
        help_text="Reference number or document"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=EntryStatus.choices,
        default=EntryStatus.DRAFT,
        db_index=True
    )

    # Related Transaction (optional)
    payment_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='journal_entries'
    )
    invoice = models.ForeignKey(
        'subscriptions.SubscriptionInvoice',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='journal_entries'
    )
    expense_report = models.ForeignKey(
        'expenses.ExpenseReport',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='journal_entries'
    )

    # Created By
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='journal_entries_created'
    )

    # Accounting Provider Sync
    provider = models.ForeignKey(
        AccountingProvider,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='journal_entries'
    )
    provider_entry_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Journal entry ID in QuickBooks/Xero"
    )
    synced_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Journal Entry"
        verbose_name_plural = "Journal Entries"
        ordering = ['-entry_date', '-entry_number']
        indexes = [
            models.Index(fields=['entry_number']),
            models.Index(fields=['status', '-entry_date']),
            models.Index(fields=['provider_entry_id']),
        ]

    def __str__(self):
        return f"{self.entry_number} - {self.entry_date} - {self.description}"

    def save(self, *args, **kwargs):
        # Generate entry number if not set
        if not self.entry_number:
            import uuid
            from datetime import datetime
            date_str = self.entry_date.strftime('%Y%m')
            unique_id = uuid.uuid4().hex[:6].upper()
            self.entry_number = f"JE-{date_str}-{unique_id}"

        super().save(*args, **kwargs)

    @property
    def total_debits(self):
        """Calculate total debits from all lines"""
        return sum(line.debit for line in self.lines.all())

    @property
    def total_credits(self):
        """Calculate total credits from all lines"""
        return sum(line.credit for line in self.lines.all())

    @property
    def is_balanced(self):
        """Check if debits equal credits"""
        return self.total_debits == self.total_credits


class JournalEntryLine(models.Model):
    """
    Individual line in journal entry (debit or credit).
    """
    # Journal Entry
    entry = models.ForeignKey(
        JournalEntry,
        on_delete=models.CASCADE,
        related_name='lines'
    )

    # Account
    account = models.ForeignKey(
        ChartOfAccounts,
        on_delete=models.PROTECT,
        related_name='journal_lines'
    )

    # Debit/Credit
    debit = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    credit = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))]
    )

    # Description
    description = models.CharField(max_length=500, blank=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Journal Entry Line"
        verbose_name_plural = "Journal Entry Lines"
        ordering = ['id']

    def __str__(self):
        if self.debit > 0:
            return f"{self.account.account_name} - Debit ${self.debit}"
        return f"{self.account.account_name} - Credit ${self.credit}"


class AccountingSyncLog(TenantAwareModel):
    """
    Log of accounting sync operations.

    Tracks sync history and errors for troubleshooting.
    """
    class SyncType(models.TextChoices):
        FULL = 'full', 'Full Sync'
        INCREMENTAL = 'incremental', 'Incremental Sync'
        MANUAL = 'manual', 'Manual Sync'

    class SyncStatus(models.TextChoices):
        STARTED = 'started', 'Started'
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
        PARTIAL = 'partial', 'Partially Completed'

    # Sync Identifier
    sync_id = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique sync identifier (auto-generated)"
    )

    # Provider
    provider = models.ForeignKey(
        AccountingProvider,
        on_delete=models.CASCADE,
        related_name='sync_logs'
    )

    # Sync Details
    sync_type = models.CharField(
        max_length=20,
        choices=SyncType.choices
    )
    status = models.CharField(
        max_length=20,
        choices=SyncStatus.choices,
        default=SyncStatus.STARTED,
        db_index=True
    )

    # Counts
    records_processed = models.PositiveIntegerField(default=0)
    records_synced = models.PositiveIntegerField(default=0)
    records_failed = models.PositiveIntegerField(default=0)

    # Error Details
    error_message = models.TextField(blank=True)
    error_details = models.JSONField(default=dict, blank=True)

    # Triggered By
    triggered_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='accounting_syncs_triggered'
    )

    # Dates
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Accounting Sync Log"
        verbose_name_plural = "Accounting Sync Logs"
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['sync_id']),
            models.Index(fields=['provider', 'status']),
            models.Index(fields=['-started_at']),
        ]

    def __str__(self):
        return f"{self.sync_id} - {self.provider.company_name} - {self.get_status_display()}"

    def save(self, *args, **kwargs):
        # Generate sync ID if not set
        if not self.sync_id:
            import uuid
            from datetime import datetime
            date_str = datetime.now().strftime('%Y%m%d%H%M')
            unique_id = uuid.uuid4().hex[:4].upper()
            self.sync_id = f"SYNC-{date_str}-{unique_id}"

        super().save(*args, **kwargs)


class FinancialReport(TenantAwareModel):
    """
    Generated financial reports.

    Supports P&L, Balance Sheet, Cash Flow statements.
    """
    class ReportType(models.TextChoices):
        PROFIT_LOSS = 'profit_loss', 'Profit & Loss (Income Statement)'
        BALANCE_SHEET = 'balance_sheet', 'Balance Sheet'
        CASH_FLOW = 'cash_flow', 'Cash Flow Statement'
        TRIAL_BALANCE = 'trial_balance', 'Trial Balance'
        AR_AGING = 'ar_aging', 'Accounts Receivable Aging'
        AP_AGING = 'ap_aging', 'Accounts Payable Aging'

    # Report Identifier
    report_number = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique report number (auto-generated)"
    )

    # Report Details
    report_type = models.CharField(
        max_length=20,
        choices=ReportType.choices
    )
    report_name = models.CharField(max_length=255)

    # Period
    period_start = models.DateField()
    period_end = models.DateField()

    # Report Data
    report_data = models.JSONField(
        default=dict,
        help_text="Full report data (JSON)"
    )

    # Generated From
    provider = models.ForeignKey(
        AccountingProvider,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reports'
    )
    source = models.CharField(
        max_length=20,
        choices=[
            ('system', 'System Generated'),
            ('quickbooks', 'QuickBooks'),
            ('xero', 'Xero'),
        ],
        default='system'
    )

    # Generated By
    generated_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        related_name='financial_reports_generated'
    )
    generated_at = models.DateTimeField(auto_now_add=True)

    # PDF Export
    pdf_file = models.FileField(
        upload_to='financial_reports/%Y/%m/',
        blank=True,
        null=True
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Financial Report"
        verbose_name_plural = "Financial Reports"
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
            self.report_number = f"RPT-{date_str}-{unique_id}"

        super().save(*args, **kwargs)


class ReconciliationRecord(TenantAwareModel):
    """
    Bank reconciliation record.

    Tracks bank statement reconciliation process.
    """
    class ReconciliationStatus(models.TextChoices):
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        ABANDONED = 'abandoned', 'Abandoned'

    # Reconciliation Identifier
    reconciliation_id = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Unique reconciliation identifier (auto-generated)"
    )

    # Account
    account = models.ForeignKey(
        ChartOfAccounts,
        on_delete=models.PROTECT,
        related_name='reconciliations',
        help_text="Bank or cash account being reconciled"
    )

    # Statement Details
    statement_date = models.DateField()
    statement_ending_balance = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        help_text="Ending balance per bank statement"
    )

    # Reconciliation
    opening_balance = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        help_text="Opening balance"
    )
    cleared_debits = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total cleared debits"
    )
    cleared_credits = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Total cleared credits"
    )
    calculated_balance = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        help_text="Calculated ending balance"
    )
    difference = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Difference between statement and calculated balance"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=ReconciliationStatus.choices,
        default=ReconciliationStatus.IN_PROGRESS,
        db_index=True
    )

    # Reconciled By
    reconciled_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        related_name='reconciliations_done'
    )
    reconciled_at = models.DateTimeField(null=True, blank=True)

    # Notes
    notes = models.TextField(blank=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Reconciliation Record"
        verbose_name_plural = "Reconciliation Records"
        ordering = ['-statement_date']
        indexes = [
            models.Index(fields=['reconciliation_id']),
            models.Index(fields=['account', 'status']),
            models.Index(fields=['-statement_date']),
        ]

    def __str__(self):
        return f"{self.reconciliation_id} - {self.account.account_name} - {self.statement_date}"

    def save(self, *args, **kwargs):
        # Generate reconciliation ID if not set
        if not self.reconciliation_id:
            import uuid
            from datetime import datetime
            date_str = self.statement_date.strftime('%Y%m')
            unique_id = uuid.uuid4().hex[:6].upper()
            self.reconciliation_id = f"REC-{date_str}-{unique_id}"

        # Calculate balance and difference
        self.calculated_balance = self.opening_balance + self.cleared_credits - self.cleared_debits
        self.difference = self.statement_ending_balance - self.calculated_balance

        super().save(*args, **kwargs)

    @property
    def is_balanced(self):
        """Check if reconciliation is balanced"""
        return self.difference == Decimal('0.00')
