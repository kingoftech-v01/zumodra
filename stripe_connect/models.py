"""
Stripe Connect App Models - Marketplace Payment Infrastructure (TENANT Schema)

This app handles Stripe Connect for marketplace payments:
- Provider onboarding to Stripe Express accounts
- Payouts to freelancers/service providers
- Platform fee collection
- Transfer tracking

Uses Stripe Connect Express accounts for providers.
"""

from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from core.models import TenantAwareModel  # Import from core.models instead of defining here


class ConnectedAccount(TenantAwareModel):
    """
    Provider's Stripe Connect Express account.

    Each marketplace provider (freelancer/service provider) has their own
    Stripe Express account for receiving payouts.
    """
    class AccountType(models.TextChoices):
        EXPRESS = 'express', 'Stripe Express'
        STANDARD = 'standard', 'Stripe Standard'
        CUSTOM = 'custom', 'Stripe Custom'

    class AccountStatus(models.TextChoices):
        INCOMPLETE = 'incomplete', 'Incomplete'
        PENDING = 'pending', 'Pending Verification'
        ENABLED = 'enabled', 'Enabled'
        DISABLED = 'disabled', 'Disabled'
        REJECTED = 'rejected', 'Rejected'

    # Provider
    provider = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='stripe_connected_account'
    )

    # Stripe Account Details
    stripe_account_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Stripe Connect account ID (acct_xxxxx)"
    )
    account_type = models.CharField(
        max_length=20,
        choices=AccountType.choices,
        default=AccountType.EXPRESS
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=AccountStatus.choices,
        default=AccountStatus.INCOMPLETE,
        db_index=True
    )

    # Capabilities (what the account can do)
    charges_enabled = models.BooleanField(
        default=False,
        help_text="Can receive charges"
    )
    payouts_enabled = models.BooleanField(
        default=False,
        help_text="Can receive payouts"
    )
    transfers_enabled = models.BooleanField(
        default=False,
        help_text="Can receive transfers"
    )

    # Requirements (what's needed for full activation)
    requirements = models.JSONField(
        default=dict,
        help_text="Stripe requirements data (currently_due, eventually_due, etc.)"
    )
    requirements_pending = models.BooleanField(
        default=True,
        help_text="Whether account has pending requirements"
    )

    # Verification
    verification_status = models.CharField(max_length=50, blank=True)
    verification_disabled_reason = models.CharField(max_length=255, blank=True)

    # Business Details
    business_type = models.CharField(
        max_length=50,
        blank=True,
        help_text="individual, company, etc."
    )
    country = models.CharField(max_length=2, default='US')
    default_currency = models.CharField(max_length=3, default='USD')

    # Email and Contact
    email = models.EmailField(blank=True)

    # Dashboard Login Link
    dashboard_link_expires = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Expiration of Stripe Dashboard login link"
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Connected Account"
        verbose_name_plural = "Connected Accounts"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['stripe_account_id']),
            models.Index(fields=['provider']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.provider.get_full_name()} - {self.stripe_account_id} ({self.get_status_display()})"

    @property
    def is_fully_onboarded(self):
        """Check if account is fully onboarded and can receive payouts"""
        return (
            self.status == self.AccountStatus.ENABLED and
            self.payouts_enabled and
            not self.requirements_pending
        )

    @property
    def needs_verification(self):
        """Check if account needs additional verification"""
        return self.requirements_pending or self.status in [
            self.AccountStatus.INCOMPLETE,
            self.AccountStatus.PENDING
        ]


class StripeConnectOnboarding(TenantAwareModel):
    """
    Tracks Stripe Connect onboarding flow for providers.

    Stores onboarding links, completion status, and progress.
    """
    class OnboardingStatus(models.TextChoices):
        NOT_STARTED = 'not_started', 'Not Started'
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    # Connected Account
    connected_account = models.OneToOneField(
        ConnectedAccount,
        on_delete=models.CASCADE,
        related_name='onboarding'
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=OnboardingStatus.choices,
        default=OnboardingStatus.NOT_STARTED
    )

    # Onboarding Link
    onboarding_url = models.URLField(
        blank=True,
        help_text="Stripe Connect onboarding URL"
    )
    onboarding_url_expires = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When onboarding URL expires"
    )

    # Completion
    completed_at = models.DateTimeField(null=True, blank=True)

    # Return URLs
    return_url = models.URLField(
        blank=True,
        help_text="URL to return to after onboarding"
    )
    refresh_url = models.URLField(
        blank=True,
        help_text="URL to refresh onboarding if user exits"
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Stripe Connect Onboarding"
        verbose_name_plural = "Stripe Connect Onboardings"

    def __str__(self):
        return f"Onboarding for {self.connected_account.provider.get_full_name()} - {self.get_status_display()}"

    @property
    def is_onboarding_url_valid(self):
        """Check if onboarding URL is still valid"""
        if self.onboarding_url_expires:
            return timezone.now() < self.onboarding_url_expires
        return False


class PlatformFee(TenantAwareModel):
    """
    Platform fee configuration for marketplace transactions.

    Defines how much the platform charges for facilitating transactions.
    Can be percentage-based, fixed, or both.
    """
    # Fee Name
    name = models.CharField(
        max_length=100,
        help_text="Fee name (e.g., 'Standard Marketplace Fee', 'Premium Service Fee')"
    )

    # Fee Structure
    percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('10.00'),
        validators=[MinValueValidator(Decimal('0.00')), MaxValueValidator(Decimal('100.00'))],
        help_text="Percentage fee (0-100)"
    )
    fixed_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Fixed fee amount"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Minimum and Maximum Fees
    min_fee = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Minimum fee amount (null = no minimum)"
    )
    max_fee = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Maximum fee amount (null = no maximum)"
    )

    # Application (which transactions this applies to)
    applies_to = models.CharField(
        max_length=50,
        default='all',
        help_text="What this fee applies to (all, services, projects, etc.)"
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    description = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Platform Fee"
        verbose_name_plural = "Platform Fees"
        ordering = ['name']

    def __str__(self):
        fee_display = []
        if self.percentage > 0:
            fee_display.append(f"{self.percentage}%")
        if self.fixed_amount > 0:
            fee_display.append(f"{self.currency} {self.fixed_amount}")
        return f"{self.name} - {' + '.join(fee_display)}"

    def calculate_fee(self, amount):
        """Calculate fee for a given amount"""
        # Calculate percentage fee
        percentage_fee = amount * (self.percentage / 100)

        # Total fee
        total_fee = percentage_fee + self.fixed_amount

        # Apply min/max constraints
        if self.min_fee and total_fee < self.min_fee:
            total_fee = self.min_fee
        if self.max_fee and total_fee > self.max_fee:
            total_fee = self.max_fee

        return total_fee


class PayoutSchedule(TenantAwareModel):
    """
    Payout schedule for connected accounts.

    Defines when and how often providers receive payouts.
    """
    class Interval(models.TextChoices):
        MANUAL = 'manual', 'Manual'
        DAILY = 'daily', 'Daily'
        WEEKLY = 'weekly', 'Weekly'
        MONTHLY = 'monthly', 'Monthly'

    class WeekAnchor(models.TextChoices):
        MONDAY = 'monday', 'Monday'
        TUESDAY = 'tuesday', 'Tuesday'
        WEDNESDAY = 'wednesday', 'Wednesday'
        THURSDAY = 'thursday', 'Thursday'
        FRIDAY = 'friday', 'Friday'

    # Connected Account
    connected_account = models.OneToOneField(
        ConnectedAccount,
        on_delete=models.CASCADE,
        related_name='payout_schedule'
    )

    # Schedule
    interval = models.CharField(
        max_length=20,
        choices=Interval.choices,
        default=Interval.WEEKLY
    )

    # Weekly Anchor (for weekly intervals)
    weekly_anchor = models.CharField(
        max_length=20,
        choices=WeekAnchor.choices,
        default=WeekAnchor.FRIDAY,
        blank=True,
        help_text="Day of week for weekly payouts"
    )

    # Monthly Anchor (for monthly intervals)
    monthly_anchor = models.PositiveSmallIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(31)],
        help_text="Day of month for monthly payouts (1-31)"
    )

    # Delay Days
    delay_days = models.PositiveIntegerField(
        default=2,
        help_text="Days to delay payout after period end (Stripe standard is 2)"
    )

    # Minimum Payout Amount
    minimum_payout = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('10.00'),
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Minimum amount required for payout"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Payout Schedule"
        verbose_name_plural = "Payout Schedules"

    def __str__(self):
        schedule_detail = self.get_interval_display()
        if self.interval == self.Interval.WEEKLY:
            schedule_detail = f"{schedule_detail} ({self.get_weekly_anchor_display()})"
        elif self.interval == self.Interval.MONTHLY:
            schedule_detail = f"{schedule_detail} (Day {self.monthly_anchor})"
        return f"{self.connected_account.provider.get_full_name()} - {schedule_detail}"


class Transfer(TenantAwareModel):
    """
    Stripe transfer to connected account.

    Tracks individual transfers of funds to providers via Stripe Connect.
    """
    class TransferStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        IN_TRANSIT = 'in_transit', 'In Transit'
        PAID = 'paid', 'Paid'
        FAILED = 'failed', 'Failed'
        CANCELED = 'canceled', 'Canceled'

    # Transfer Identifier
    transfer_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Internal transfer ID"
    )

    # Stripe Transfer
    stripe_transfer_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Stripe transfer ID (tr_xxxxx)"
    )

    # Connected Account
    connected_account = models.ForeignKey(
        ConnectedAccount,
        on_delete=models.PROTECT,
        related_name='transfers'
    )

    # Amount
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))]
    )
    currency = models.CharField(max_length=3, default='USD')

    # Status
    status = models.CharField(
        max_length=20,
        choices=TransferStatus.choices,
        default=TransferStatus.PENDING,
        db_index=True
    )

    # Source (escrow transaction, payout, etc.)
    source_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='stripe_transfers'
    )

    # Description
    description = models.TextField(blank=True)

    # Dates
    created_at_stripe = models.DateTimeField(
        help_text="When transfer was created in Stripe"
    )
    arrival_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Expected arrival date in provider's bank"
    )

    # Failure Details
    failure_code = models.CharField(max_length=100, blank=True)
    failure_message = models.TextField(blank=True)

    # Reversal
    reversed = models.BooleanField(default=False)
    reversed_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Transfer"
        verbose_name_plural = "Transfers"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['transfer_id']),
            models.Index(fields=['stripe_transfer_id']),
            models.Index(fields=['connected_account', '-created_at']),
            models.Index(fields=['status', '-created_at']),
        ]

    def __str__(self):
        return f"Transfer {self.transfer_id} - {self.amount} {self.currency} to {self.connected_account.provider.get_full_name()}"

    def save(self, *args, **kwargs):
        # Generate transfer ID if not set
        if not self.transfer_id:
            import uuid
            self.transfer_id = f"TRF-{uuid.uuid4().hex[:16].upper()}"

        super().save(*args, **kwargs)


class BalanceTransaction(TenantAwareModel):
    """
    Stripe balance transaction record.

    Tracks all balance changes for connected accounts.
    """
    class TransactionType(models.TextChoices):
        CHARGE = 'charge', 'Charge'
        REFUND = 'refund', 'Refund'
        TRANSFER = 'transfer', 'Transfer'
        PAYOUT = 'payout', 'Payout'
        FEE = 'fee', 'Fee'
        ADJUSTMENT = 'adjustment', 'Adjustment'

    # Stripe Balance Transaction
    stripe_balance_transaction_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Stripe balance transaction ID (txn_xxxxx)"
    )

    # Connected Account
    connected_account = models.ForeignKey(
        ConnectedAccount,
        on_delete=models.CASCADE,
        related_name='balance_transactions'
    )

    # Amount
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Gross amount (positive = credit, negative = debit)"
    )
    fee = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Fees deducted from amount"
    )
    net = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Net amount (amount - fee)"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Type
    transaction_type = models.CharField(
        max_length=20,
        choices=TransactionType.choices,
        db_index=True
    )

    # Description
    description = models.TextField(blank=True)

    # Source
    source_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Stripe ID of source object (charge, transfer, etc.)"
    )

    # Related Transfer
    transfer = models.ForeignKey(
        Transfer,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='balance_transactions'
    )

    # Available On
    available_on = models.DateTimeField(
        help_text="When funds become available for payout"
    )

    # Dates
    created_at_stripe = models.DateTimeField(
        help_text="When transaction was created in Stripe"
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Balance Transaction"
        verbose_name_plural = "Balance Transactions"
        ordering = ['-created_at_stripe']
        indexes = [
            models.Index(fields=['stripe_balance_transaction_id']),
            models.Index(fields=['connected_account', '-created_at_stripe']),
            models.Index(fields=['transaction_type', '-created_at_stripe']),
        ]

    def __str__(self):
        sign = "+" if self.net >= 0 else ""
        return f"{self.get_transaction_type_display()} - {sign}{self.net} {self.currency}"

    @property
    def is_credit(self):
        """Check if this is a credit to the account"""
        return self.net > 0

    @property
    def is_debit(self):
        """Check if this is a debit from the account"""
        return self.net < 0
