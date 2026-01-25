"""
Billing App Models - Platform Subscription Management (PUBLIC Schema)

Handles Zumodra's subscription charges to tenants.
This is platform billing, NOT tenant payment processing.
"""

from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator
from decimal import Decimal


class SubscriptionPlan(models.Model):
    """
    Platform subscription tiers (Starter, Professional, Enterprise).
    These are Zumodra's pricing plans for tenants.
    """

    class PlanTier(models.TextChoices):
        STARTER = "starter", "Starter"
        PROFESSIONAL = "professional", "Professional"
        ENTERPRISE = "enterprise", "Enterprise"
        CUSTOM = "custom", "Custom"

    # Basic Info
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    tier = models.CharField(max_length=20, choices=PlanTier.choices)
    description = models.TextField(blank=True)

    # Pricing
    price_monthly = models.DecimalField(
        max_digits=10, decimal_places=2, validators=[MinValueValidator(Decimal("0.00"))]
    )
    price_yearly = models.DecimalField(
        max_digits=10, decimal_places=2, validators=[MinValueValidator(Decimal("0.00"))]
    )
    currency = models.CharField(max_length=3, default="USD")

    # Limits
    max_users = models.PositiveIntegerField(help_text="Maximum users allowed")
    max_jobs = models.PositiveIntegerField(help_text="Maximum active job postings")
    max_storage_gb = models.PositiveIntegerField(help_text="Storage limit in GB")
    max_api_calls_per_month = models.PositiveIntegerField(
        default=10000, help_text="API rate limit per month"
    )

    # Features (JSON field for flexible feature flags)
    features = models.JSONField(
        default=list,
        help_text="List of enabled features: ['advanced_analytics', 'priority_support', etc.]",
    )

    # Trial
    trial_days = models.PositiveIntegerField(default=14, help_text="Free trial period in days")

    # Stripe Integration
    stripe_price_id_monthly = models.CharField(max_length=255, blank=True)
    stripe_price_id_yearly = models.CharField(max_length=255, blank=True)
    stripe_product_id = models.CharField(max_length=255, blank=True)

    # Status
    is_active = models.BooleanField(default=True)
    is_public = models.BooleanField(
        default=True, help_text="Show on public pricing page"
    )
    sort_order = models.PositiveIntegerField(default=0, help_text="Display order on pricing page")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["sort_order", "price_monthly"]
        verbose_name = "Subscription Plan"
        verbose_name_plural = "Subscription Plans"

    def __str__(self):
        return f"{self.name} - ${self.price_monthly}/month"

    def get_yearly_discount_percentage(self):
        """Calculate discount percentage for yearly vs monthly billing"""
        if self.price_monthly == 0:
            return 0
        monthly_equivalent = self.price_monthly * 12
        if monthly_equivalent == 0:
            return 0
        discount = ((monthly_equivalent - self.price_yearly) / monthly_equivalent) * 100
        return round(discount, 1)


class TenantSubscription(models.Model):
    """
    Tenant's subscription to Zumodra platform.
    Tracks which plan a tenant is on and billing status.
    """

    class SubscriptionStatus(models.TextChoices):
        ACTIVE = "active", "Active"
        TRIALING = "trialing", "Trial"
        PAST_DUE = "past_due", "Past Due"
        CANCELED = "canceled", "Canceled"
        UNPAID = "unpaid", "Unpaid"
        PAUSED = "paused", "Paused"

    class BillingCycle(models.TextChoices):
        MONTHLY = "monthly", "Monthly"
        YEARLY = "yearly", "Yearly"

    # Tenant & Plan
    tenant = models.ForeignKey(
        "tenants.Tenant", on_delete=models.CASCADE, related_name="platform_subscriptions"
    )
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.PROTECT)

    # Status
    status = models.CharField(max_length=20, choices=SubscriptionStatus.choices)

    # Billing
    billing_cycle = models.CharField(max_length=20, choices=BillingCycle.choices)
    quantity = models.PositiveIntegerField(
        default=1, help_text="For usage-based billing or seat-based pricing"
    )

    # Billing Periods
    current_period_start = models.DateTimeField()
    current_period_end = models.DateTimeField()
    trial_start = models.DateTimeField(null=True, blank=True)
    trial_end = models.DateTimeField(null=True, blank=True)
    canceled_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    # Stripe Integration
    stripe_subscription_id = models.CharField(max_length=255, unique=True, blank=True)
    stripe_customer_id = models.CharField(max_length=255, blank=True)

    # Cancellation
    cancel_at_period_end = models.BooleanField(default=False)
    cancellation_reason = models.TextField(blank=True)

    # Metadata
    metadata = models.JSONField(
        default=dict, help_text="Additional subscription metadata"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Tenant Subscription"
        verbose_name_plural = "Tenant Subscriptions"
        indexes = [
            models.Index(fields=["tenant", "status"]),
            models.Index(fields=["status", "current_period_end"]),
        ]

    def __str__(self):
        return f"{self.tenant.name} - {self.plan.name} ({self.status})"

    @property
    def is_trialing(self):
        """Check if subscription is in trial period"""
        return self.status == self.SubscriptionStatus.TRIALING

    @property
    def is_active(self):
        """Check if subscription is active (including trial)"""
        return self.status in [
            self.SubscriptionStatus.ACTIVE,
            self.SubscriptionStatus.TRIALING,
        ]

    @property
    def days_until_renewal(self):
        """Calculate days until next billing period"""
        if not self.current_period_end:
            return None
        delta = self.current_period_end - timezone.now()
        return max(0, delta.days)


class PlatformInvoice(models.Model):
    """
    Invoices from Zumodra to tenants for platform subscription.
    """

    class InvoiceStatus(models.TextChoices):
        DRAFT = "draft", "Draft"
        OPEN = "open", "Open"
        PAID = "paid", "Paid"
        VOID = "void", "Void"
        UNCOLLECTIBLE = "uncollectible", "Uncollectible"

    # Tenant & Subscription
    tenant = models.ForeignKey(
        "tenants.Tenant", on_delete=models.CASCADE, related_name="platform_invoices"
    )
    subscription = models.ForeignKey(
        TenantSubscription, on_delete=models.SET_NULL, null=True, blank=True
    )

    # Invoice Details
    invoice_number = models.CharField(max_length=50, unique=True)
    status = models.CharField(max_length=20, choices=InvoiceStatus.choices)

    # Amounts
    subtotal = models.DecimalField(max_digits=12, decimal_places=2)
    tax = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    total = models.DecimalField(max_digits=12, decimal_places=2)
    amount_paid = models.DecimalField(
        max_digits=12, decimal_places=2, default=Decimal("0.00")
    )
    amount_due = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default="USD")

    # Line Items (JSON for flexibility)
    line_items = models.JSONField(
        default=list,
        help_text="List of invoice line items with description, quantity, unit_price",
    )

    # Dates
    invoice_date = models.DateField(default=timezone.now)
    due_date = models.DateField()
    paid_at = models.DateTimeField(null=True, blank=True)

    # Stripe Integration
    stripe_invoice_id = models.CharField(max_length=255, unique=True, blank=True)
    stripe_payment_intent_id = models.CharField(max_length=255, blank=True)

    # PDF
    pdf_url = models.URLField(blank=True)

    # Notes
    notes = models.TextField(blank=True, help_text="Internal notes")
    customer_notes = models.TextField(blank=True, help_text="Notes visible to customer")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-invoice_date"]
        verbose_name = "Platform Invoice"
        verbose_name_plural = "Platform Invoices"
        indexes = [
            models.Index(fields=["tenant", "status"]),
            models.Index(fields=["invoice_date"]),
            models.Index(fields=["due_date", "status"]),
        ]

    def __str__(self):
        return f"Invoice {self.invoice_number} - {self.tenant.name}"

    @property
    def is_overdue(self):
        """Check if invoice is overdue"""
        if self.status == self.InvoiceStatus.PAID:
            return False
        return timezone.now().date() > self.due_date


class BillingHistory(models.Model):
    """
    Tracks subscription changes for auditing.
    """

    class ChangeType(models.TextChoices):
        CREATED = "created", "Subscription Created"
        UPGRADED = "upgraded", "Plan Upgraded"
        DOWNGRADED = "downgraded", "Plan Downgraded"
        CANCELED = "canceled", "Subscription Canceled"
        REACTIVATED = "reactivated", "Subscription Reactivated"
        RENEWED = "renewed", "Subscription Renewed"
        TRIAL_STARTED = "trial_started", "Trial Started"
        TRIAL_ENDED = "trial_ended", "Trial Ended"
        PAYMENT_FAILED = "payment_failed", "Payment Failed"
        PAYMENT_SUCCEEDED = "payment_succeeded", "Payment Succeeded"

    # Subscription & Tenant
    subscription = models.ForeignKey(
        TenantSubscription, on_delete=models.CASCADE, related_name="history"
    )
    tenant = models.ForeignKey(
        "tenants.Tenant", on_delete=models.CASCADE, related_name="billing_history"
    )

    # Change Details
    change_type = models.CharField(max_length=20, choices=ChangeType.choices)
    description = models.TextField()

    # Before/After State
    old_plan = models.ForeignKey(
        SubscriptionPlan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="history_old_plan",
    )
    new_plan = models.ForeignKey(
        SubscriptionPlan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="history_new_plan",
    )
    old_status = models.CharField(max_length=20, blank=True)
    new_status = models.CharField(max_length=20, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, help_text="Additional change metadata")

    # User who made the change (if applicable)
    changed_by = models.ForeignKey(
        "core_identity.CustomUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="User who initiated the change",
    )

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Billing History"
        verbose_name_plural = "Billing History"
        indexes = [
            models.Index(fields=["subscription", "-created_at"]),
            models.Index(fields=["tenant", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.tenant.name} - {self.get_change_type_display()} - {self.created_at.date()}"
