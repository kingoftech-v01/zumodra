"""
Escrow App Models - Secure Funds Holding for Marketplace (TENANT Schema)

This app handles escrow transactions for:
- Service contracts (freelancer marketplace)
- Project contracts (mission-based work)
- Milestone-based payments

Escrow ensures funds are held securely until work is completed and approved.
"""

from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from core.models import TenantAwareModel  # Import from core.models instead of defining here


class EscrowTransaction(TenantAwareModel):
    """
    Escrow transaction for holding funds securely.

    Funds are held until:
    - Work is completed and approved by client
    - Milestone is reached
    - Dispute is resolved
    """
    class EscrowStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        FUNDED = 'funded', 'Funded'
        RELEASED = 'released', 'Released'
        REFUNDED = 'refunded', 'Refunded'
        DISPUTED = 'disputed', 'Disputed'
        CANCELED = 'canceled', 'Canceled'

    # Escrow Identifier
    escrow_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Unique escrow identifier (auto-generated)"
    )

    # Amount
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text="Escrow amount"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Platform Fee (deducted on release)
    platform_fee_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('10.00'),
        validators=[MinValueValidator(Decimal('0.00')), MinValueValidator(Decimal('100.00'))],
        help_text="Platform fee percentage (0-100)"
    )
    platform_fee_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Calculated platform fee amount"
    )

    # Payout Amount (after fees)
    payout_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Amount to be paid out to provider (amount - platform_fee)"
    )

    # Parties
    client = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='escrow_as_client',
        help_text="Client funding the escrow"
    )
    provider = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='escrow_as_provider',
        help_text="Provider receiving funds upon release"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=EscrowStatus.choices,
        default=EscrowStatus.PENDING,
        db_index=True
    )

    # Related Object (ServiceContract, ProjectContract, etc.)
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    related_object = GenericForeignKey('content_type', 'object_id')

    # Description
    description = models.TextField(blank=True)

    # Release Conditions
    auto_release_days = models.PositiveIntegerField(
        default=7,
        help_text="Days after work completion before auto-release (0 = manual only)"
    )
    work_completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When provider marked work as complete"
    )
    auto_release_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Calculated auto-release datetime"
    )

    # Payment Integration
    payment_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='escrow_transactions',
        help_text="Payment transaction that funded this escrow"
    )

    # Dates
    funded_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)
    refunded_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Escrow Transaction"
        verbose_name_plural = "Escrow Transactions"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['escrow_id']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['client', '-created_at']),
            models.Index(fields=['provider', '-created_at']),
            models.Index(fields=['content_type', 'object_id']),
        ]

    def __str__(self):
        return f"Escrow {self.escrow_id} - {self.amount} {self.currency} ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        # Generate escrow ID if not set
        if not self.escrow_id:
            import uuid
            self.escrow_id = f"ESC-{uuid.uuid4().hex[:16].upper()}"

        # Calculate platform fee and payout amount
        self.platform_fee_amount = self.amount * (self.platform_fee_percentage / 100)
        self.payout_amount = self.amount - self.platform_fee_amount

        # Calculate auto-release datetime if work completed
        if self.work_completed_at and self.auto_release_days > 0 and not self.auto_release_at:
            from datetime import timedelta
            self.auto_release_at = self.work_completed_at + timedelta(days=self.auto_release_days)

        super().save(*args, **kwargs)

    @property
    def is_releasable(self):
        """Check if escrow can be released"""
        return self.status == self.EscrowStatus.FUNDED

    @property
    def can_auto_release(self):
        """Check if escrow is ready for auto-release"""
        if self.status == self.EscrowStatus.FUNDED and self.auto_release_at:
            return timezone.now() >= self.auto_release_at
        return False


class MilestonePayment(TenantAwareModel):
    """
    Milestone-based payment for projects.

    Projects can have multiple milestones, each with its own escrow.
    """
    class MilestoneStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        FUNDED = 'funded', 'Funded'
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        APPROVED = 'approved', 'Approved'
        PAID = 'paid', 'Paid'
        DISPUTED = 'disputed', 'Disputed'

    # Milestone Info
    milestone_number = models.PositiveIntegerField(
        help_text="Milestone sequence number (1, 2, 3, ...)"
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)

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
        choices=MilestoneStatus.choices,
        default=MilestoneStatus.PENDING,
        db_index=True
    )

    # Escrow
    escrow_transaction = models.OneToOneField(
        EscrowTransaction,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='milestone'
    )

    # Deliverables
    deliverables = models.JSONField(
        default=list,
        help_text="List of expected deliverables for this milestone"
    )
    delivered_files = models.JSONField(
        default=list,
        help_text="List of delivered files/URLs"
    )

    # Dates
    due_date = models.DateField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Related Project (will be linked to projects.ProjectMilestone)
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    related_object = GenericForeignKey('content_type', 'object_id')

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Milestone Payment"
        verbose_name_plural = "Milestone Payments"
        ordering = ['milestone_number']
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['content_type', 'object_id']),
        ]

    def __str__(self):
        return f"Milestone #{self.milestone_number}: {self.title} - {self.amount} {self.currency}"

    @property
    def is_paid(self):
        """Check if milestone has been paid"""
        return self.status == self.MilestoneStatus.PAID


class EscrowRelease(TenantAwareModel):
    """
    Controlled release of escrow funds.

    Tracks who approved the release and when.
    """
    class ReleaseType(models.TextChoices):
        FULL = 'full', 'Full Release'
        PARTIAL = 'partial', 'Partial Release'
        REFUND = 'refund', 'Refund to Client'

    # Escrow Transaction
    escrow_transaction = models.ForeignKey(
        EscrowTransaction,
        on_delete=models.CASCADE,
        related_name='releases'
    )

    # Release Details
    release_type = models.CharField(
        max_length=20,
        choices=ReleaseType.choices,
        default=ReleaseType.FULL
    )
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text="Amount being released"
    )

    # Approval
    approved_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        related_name='escrow_releases_approved'
    )
    approval_reason = models.TextField(blank=True)

    # Automatic Release
    is_automatic = models.BooleanField(
        default=False,
        help_text="Whether this was an auto-release or manual"
    )

    # Payout Transaction
    payout_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='escrow_releases'
    )

    # Dates
    released_at = models.DateTimeField(auto_now_add=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Escrow Release"
        verbose_name_plural = "Escrow Releases"
        ordering = ['-released_at']
        indexes = [
            models.Index(fields=['escrow_transaction', '-released_at']),
        ]

    def __str__(self):
        return f"{self.get_release_type_display()} - {self.amount} {self.escrow_transaction.currency}"


class Dispute(TenantAwareModel):
    """
    Dispute for escrow transaction.

    When client and provider disagree on work completion/quality.
    """
    class DisputeStatus(models.TextChoices):
        OPEN = 'open', 'Open'
        UNDER_REVIEW = 'under_review', 'Under Review'
        RESOLVED = 'resolved', 'Resolved'
        ESCALATED = 'escalated', 'Escalated'
        CLOSED = 'closed', 'Closed'

    class DisputeResolution(models.TextChoices):
        RELEASE_TO_PROVIDER = 'release_to_provider', 'Release to Provider'
        REFUND_TO_CLIENT = 'refund_to_client', 'Refund to Client'
        PARTIAL_RELEASE = 'partial_release', 'Partial Release'
        NO_ACTION = 'no_action', 'No Action'

    # Dispute Identifier
    dispute_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Unique dispute identifier (auto-generated)"
    )

    # Escrow Transaction
    escrow_transaction = models.ForeignKey(
        EscrowTransaction,
        on_delete=models.CASCADE,
        related_name='disputes'
    )

    # Parties
    initiated_by = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='disputes_initiated'
    )

    # Dispute Details
    reason = models.TextField(help_text="Reason for dispute")
    evidence = models.JSONField(
        default=list,
        help_text="Evidence submitted (file URLs, descriptions)"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=DisputeStatus.choices,
        default=DisputeStatus.OPEN,
        db_index=True
    )

    # Resolution
    resolution = models.CharField(
        max_length=30,
        choices=DisputeResolution.choices,
        blank=True,
        null=True
    )
    resolution_notes = models.TextField(blank=True)
    resolved_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='disputes_resolved'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)

    # Amounts (if partial release)
    provider_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Amount released to provider (if partial)"
    )
    client_refund_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Amount refunded to client (if partial)"
    )

    # Dates
    opened_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Dispute"
        verbose_name_plural = "Disputes"
        ordering = ['-opened_at']
        indexes = [
            models.Index(fields=['dispute_id']),
            models.Index(fields=['escrow_transaction', 'status']),
            models.Index(fields=['status', '-opened_at']),
        ]

    def __str__(self):
        return f"Dispute {self.dispute_id} - {self.escrow_transaction.escrow_id} ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        # Generate dispute ID if not set
        if not self.dispute_id:
            import uuid
            self.dispute_id = f"DIS-{uuid.uuid4().hex[:16].upper()}"

        super().save(*args, **kwargs)


class EscrowPayout(TenantAwareModel):
    """
    Payout from escrow to provider's account.

    Tracks the transfer of funds from escrow to provider.
    """
    class PayoutStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        PAID = 'paid', 'Paid'
        FAILED = 'failed', 'Failed'
        CANCELED = 'canceled', 'Canceled'

    # Payout Identifier
    payout_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Unique payout identifier (auto-generated)"
    )

    # Escrow Transaction
    escrow_transaction = models.ForeignKey(
        EscrowTransaction,
        on_delete=models.CASCADE,
        related_name='payouts'
    )

    # Provider
    provider = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='escrow_payouts'
    )

    # Amount
    gross_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Amount before platform fee"
    )
    platform_fee = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Platform fee deducted"
    )
    net_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Amount paid to provider (gross - fee)"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Status
    status = models.CharField(
        max_length=20,
        choices=PayoutStatus.choices,
        default=PayoutStatus.PENDING,
        db_index=True
    )

    # Payment Details
    payment_transaction = models.ForeignKey(
        'payments.PaymentTransaction',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='escrow_payouts'
    )

    # Stripe Connect
    stripe_transfer_id = models.CharField(max_length=255, blank=True)

    # Dates
    initiated_at = models.DateTimeField(auto_now_add=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)

    # Failure Details
    failure_reason = models.TextField(blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Escrow Payout"
        verbose_name_plural = "Escrow Payouts"
        ordering = ['-initiated_at']
        indexes = [
            models.Index(fields=['payout_id']),
            models.Index(fields=['provider', '-initiated_at']),
            models.Index(fields=['status', '-initiated_at']),
        ]

    def __str__(self):
        return f"Payout {self.payout_id} - {self.net_amount} {self.currency} to {self.provider.get_full_name()}"

    def save(self, *args, **kwargs):
        # Generate payout ID if not set
        if not self.payout_id:
            import uuid
            self.payout_id = f"PAY-{uuid.uuid4().hex[:16].upper()}"

        super().save(*args, **kwargs)


class EscrowAudit(TenantAwareModel):
    """
    Audit trail for escrow transactions.

    Records all state changes and actions for compliance and tracking.
    """
    class AuditAction(models.TextChoices):
        CREATED = 'created', 'Created'
        FUNDED = 'funded', 'Funded'
        WORK_COMPLETED = 'work_completed', 'Work Completed'
        APPROVED = 'approved', 'Approved'
        RELEASED = 'released', 'Released'
        REFUNDED = 'refunded', 'Refunded'
        DISPUTED = 'disputed', 'Disputed'
        DISPUTE_RESOLVED = 'dispute_resolved', 'Dispute Resolved'
        CANCELED = 'canceled', 'Canceled'

    # Escrow Transaction
    escrow_transaction = models.ForeignKey(
        EscrowTransaction,
        on_delete=models.CASCADE,
        related_name='audit_logs'
    )

    # Action
    action = models.CharField(
        max_length=30,
        choices=AuditAction.choices,
        db_index=True
    )
    description = models.TextField()

    # Actor
    actor = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="User who performed this action (null = system)"
    )

    # Previous and New State
    previous_state = models.JSONField(
        default=dict,
        blank=True,
        help_text="State before action"
    )
    new_state = models.JSONField(
        default=dict,
        blank=True,
        help_text="State after action"
    )

    # IP Address and User Agent (for security)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = "Escrow Audit Log"
        verbose_name_plural = "Escrow Audit Logs"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['escrow_transaction', '-created_at']),
            models.Index(fields=['action', '-created_at']),
        ]

    def __str__(self):
        actor_name = self.actor.get_full_name() if self.actor else "System"
        return f"{self.escrow_transaction.escrow_id} - {self.get_action_display()} by {actor_name}"
