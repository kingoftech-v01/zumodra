"""
Subscriptions App Models - Tenant's Own Subscription Products (TENANT Schema)

This app handles tenants selling subscription products to THEIR clients.
Example: Company ABC (tenant) sells their own SaaS product to their customers.

This is DIFFERENT from billing app:
- billing app = Zumodra charges tenants (platform subscription)
- subscriptions app = Tenants charge their clients (tenant's products)
"""

from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from datetime import timedelta
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from core.models import TenantAwareModel  # Import from core.models instead of defining here


class SubscriptionProduct(TenantAwareModel):
    """
    Product that tenant offers to their customers.

    Example: Company ABC sells "Professional Plan" subscription to their clients.
    """
    class ProductType(models.TextChoices):
        STANDARD = 'standard', 'Standard'
        METERED = 'metered', 'Metered (Usage-Based)'
        LICENSED = 'licensed', 'Licensed (Per-Seat)'

    # Product Info
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True, db_index=True)
    description = models.TextField(blank=True)

    # Product Type
    product_type = models.CharField(
        max_length=20,
        choices=ProductType.choices,
        default=ProductType.STANDARD
    )

    # Pricing (base pricing, can have multiple tiers)
    base_price_monthly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Base monthly price"
    )
    base_price_yearly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Base yearly price"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Trial
    trial_period_days = models.PositiveIntegerField(
        default=0,
        help_text="Number of days for trial period (0 = no trial)"
    )

    # Features
    features = models.JSONField(
        default=list,
        help_text="List of features included in this product"
    )

    # Limits (for SaaS products)
    max_users = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Maximum users allowed (null = unlimited)"
    )
    max_storage_gb = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Maximum storage in GB (null = unlimited)"
    )
    max_api_calls_per_month = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Maximum API calls per month (null = unlimited)"
    )

    # Stripe Integration
    stripe_product_id = models.CharField(max_length=255, blank=True)
    stripe_price_id_monthly = models.CharField(max_length=255, blank=True)
    stripe_price_id_yearly = models.CharField(max_length=255, blank=True)

    # Status
    is_active = models.BooleanField(default=True)
    is_public = models.BooleanField(
        default=True,
        help_text="Whether product is shown on public pricing page"
    )

    # Sorting
    sort_order = models.PositiveIntegerField(default=0)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Subscription Product"
        verbose_name_plural = "Subscription Products"
        ordering = ['sort_order', 'name']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['is_active', 'is_public']),
            models.Index(fields=['sort_order']),
        ]

    def __str__(self):
        return self.name

    def get_yearly_discount_percentage(self):
        """Calculate discount percentage for yearly vs monthly"""
        if self.base_price_monthly > 0:
            monthly_annual = self.base_price_monthly * 12
            if monthly_annual > self.base_price_yearly:
                discount = ((monthly_annual - self.base_price_yearly) / monthly_annual) * 100
                return round(discount, 0)
        return 0


class SubscriptionTier(TenantAwareModel):
    """
    Pricing tiers for a subscription product.

    Allows volume-based pricing (e.g., 1-10 users: $10/user, 11-50 users: $8/user)
    """
    product = models.ForeignKey(
        SubscriptionProduct,
        on_delete=models.CASCADE,
        related_name='tiers'
    )

    # Tier Info
    name = models.CharField(max_length=100)
    min_quantity = models.PositiveIntegerField(
        validators=[MinValueValidator(1)],
        help_text="Minimum quantity for this tier"
    )
    max_quantity = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Maximum quantity for this tier (null = unlimited)"
    )

    # Pricing
    price_per_unit_monthly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    price_per_unit_yearly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))]
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Subscription Tier"
        verbose_name_plural = "Subscription Tiers"
        ordering = ['product', 'min_quantity']
        unique_together = [('product', 'min_quantity')]
        indexes = [
            models.Index(fields=['product', 'min_quantity']),
        ]

    def __str__(self):
        max_qty = self.max_quantity or '∞'
        return f"{self.product.name} - {self.min_quantity}-{max_qty}"


class CustomerSubscription(TenantAwareModel):
    """
    Customer's subscription to tenant's product.

    Example: Customer John subscribed to Company ABC's "Professional Plan"
    """
    class SubscriptionStatus(models.TextChoices):
        ACTIVE = 'active', 'Active'
        TRIALING = 'trialing', 'Trialing'
        PAST_DUE = 'past_due', 'Past Due'
        CANCELED = 'canceled', 'Canceled'
        UNPAID = 'unpaid', 'Unpaid'
        PAUSED = 'paused', 'Paused'

    class BillingCycle(models.TextChoices):
        MONTHLY = 'monthly', 'Monthly'
        YEARLY = 'yearly', 'Yearly'

    # Customer
    customer = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='customer_subscriptions'
    )

    # Product
    product = models.ForeignKey(
        SubscriptionProduct,
        on_delete=models.PROTECT,
        related_name='customer_subscriptions'
    )

    # Tier (if applicable)
    tier = models.ForeignKey(
        SubscriptionTier,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='customer_subscriptions'
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=SubscriptionStatus.choices,
        default=SubscriptionStatus.ACTIVE,
        db_index=True
    )

    # Billing
    billing_cycle = models.CharField(
        max_length=20,
        choices=BillingCycle.choices,
        default=BillingCycle.MONTHLY
    )
    quantity = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        help_text="Number of units (e.g., seats, licenses)"
    )

    # Pricing (captured at subscription time)
    price_per_unit = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text="Price per unit at subscription time"
    )
    total_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text="Total subscription price (quantity * price_per_unit)"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Billing Periods
    current_period_start = models.DateTimeField()
    current_period_end = models.DateTimeField()

    # Trial
    trial_start = models.DateTimeField(null=True, blank=True)
    trial_end = models.DateTimeField(null=True, blank=True)

    # Cancellation
    cancel_at_period_end = models.BooleanField(default=False)
    canceled_at = models.DateTimeField(null=True, blank=True)
    cancellation_reason = models.TextField(blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    # Stripe Integration
    stripe_subscription_id = models.CharField(max_length=255, unique=True, blank=True)
    stripe_customer_id = models.CharField(max_length=255, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Customer Subscription"
        verbose_name_plural = "Customer Subscriptions"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['customer', 'status']),
            models.Index(fields=['product', 'status']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['stripe_subscription_id']),
        ]

    def __str__(self):
        return f"{self.customer.get_full_name()} - {self.product.name} ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        # Calculate total price
        self.total_price = self.price_per_unit * self.quantity
        super().save(*args, **kwargs)

    @property
    def is_active(self):
        """Check if subscription is currently active"""
        return self.status in [
            self.SubscriptionStatus.ACTIVE,
            self.SubscriptionStatus.TRIALING
        ]

    @property
    def is_trialing(self):
        """Check if subscription is in trial period"""
        if self.status == self.SubscriptionStatus.TRIALING and self.trial_end:
            return timezone.now() < self.trial_end
        return False

    @property
    def days_until_renewal(self):
        """Calculate days until next renewal"""
        if self.current_period_end:
            delta = self.current_period_end - timezone.now()
            return max(0, delta.days)
        return None


class SubscriptionInvoice(TenantAwareModel):
    """
    Recurring invoices for customer subscriptions.

    Generated automatically for each billing cycle.
    """
    class InvoiceStatus(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        OPEN = 'open', 'Open'
        PAID = 'paid', 'Paid'
        VOID = 'void', 'Void'
        UNCOLLECTIBLE = 'uncollectible', 'Uncollectible'

    # Invoice Identifier
    invoice_number = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        help_text="Unique invoice number (auto-generated)"
    )

    # Subscription
    subscription = models.ForeignKey(
        CustomerSubscription,
        on_delete=models.CASCADE,
        related_name='invoices'
    )

    # Customer (denormalized for convenience)
    customer = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='subscription_invoices'
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=InvoiceStatus.choices,
        default=InvoiceStatus.DRAFT,
        db_index=True
    )

    # Amounts
    subtotal = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Subtotal before tax"
    )
    tax = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Tax amount"
    )
    total = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Total amount (subtotal + tax)"
    )
    amount_paid = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00')
    )
    amount_due = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Amount still owed"
    )
    currency = models.CharField(max_length=3, default='USD')

    # Line Items
    line_items = models.JSONField(
        default=list,
        help_text="Invoice line items (JSON)"
    )

    # Dates
    invoice_date = models.DateField()
    due_date = models.DateField()
    paid_at = models.DateTimeField(null=True, blank=True)

    # Billing Period
    period_start = models.DateField()
    period_end = models.DateField()

    # Stripe Integration
    stripe_invoice_id = models.CharField(max_length=255, unique=True, blank=True)
    stripe_payment_intent_id = models.CharField(max_length=255, blank=True)

    # PDF
    pdf_url = models.URLField(blank=True)

    # Notes
    notes = models.TextField(blank=True)
    customer_notes = models.TextField(blank=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Subscription Invoice"
        verbose_name_plural = "Subscription Invoices"
        ordering = ['-invoice_date']
        indexes = [
            models.Index(fields=['invoice_number']),
            models.Index(fields=['subscription', '-invoice_date']),
            models.Index(fields=['customer', '-invoice_date']),
            models.Index(fields=['status', '-invoice_date']),
            models.Index(fields=['due_date']),
        ]

    def __str__(self):
        return f"Invoice {self.invoice_number} - {self.customer.get_full_name()}"

    def save(self, *args, **kwargs):
        # Generate invoice number if not set
        if not self.invoice_number:
            import uuid
            from datetime import datetime
            date_str = datetime.now().strftime('%Y%m')
            unique_id = uuid.uuid4().hex[:8].upper()
            self.invoice_number = f"INV-{date_str}-{unique_id}"

        # Calculate total
        self.total = self.subtotal + self.tax
        self.amount_due = self.total - self.amount_paid

        super().save(*args, **kwargs)

    @property
    def is_overdue(self):
        """Check if invoice is overdue"""
        if self.status == self.InvoiceStatus.OPEN and self.due_date:
            return timezone.now().date() > self.due_date
        return False


class UsageRecord(TenantAwareModel):
    """
    Usage tracking for metered billing.

    Example: API calls, compute hours, storage used, etc.
    """
    class UsageType(models.TextChoices):
        API_CALLS = 'api_calls', 'API Calls'
        COMPUTE_HOURS = 'compute_hours', 'Compute Hours'
        STORAGE_GB = 'storage_gb', 'Storage (GB)'
        BANDWIDTH_GB = 'bandwidth_gb', 'Bandwidth (GB)'
        TRANSACTIONS = 'transactions', 'Transactions'
        CUSTOM = 'custom', 'Custom'

    # Subscription
    subscription = models.ForeignKey(
        CustomerSubscription,
        on_delete=models.CASCADE,
        related_name='usage_records'
    )

    # Usage Details
    usage_type = models.CharField(
        max_length=50,
        choices=UsageType.choices,
        db_index=True
    )
    quantity = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Quantity of usage"
    )
    unit_price = models.DecimalField(
        max_digits=10,
        decimal_places=4,
        validators=[MinValueValidator(Decimal('0.0001'))],
        help_text="Price per unit"
    )
    total_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Total cost (quantity * unit_price)"
    )

    # Time Period
    usage_date = models.DateField(db_index=True)
    period_start = models.DateField()
    period_end = models.DateField()

    # Stripe Integration
    stripe_usage_record_id = models.CharField(max_length=255, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Usage Record"
        verbose_name_plural = "Usage Records"
        ordering = ['-usage_date']
        indexes = [
            models.Index(fields=['subscription', '-usage_date']),
            models.Index(fields=['usage_type', '-usage_date']),
            models.Index(fields=['-usage_date']),
        ]

    def __str__(self):
        return f"{self.subscription.customer.get_full_name()} - {self.get_usage_type_display()}: {self.quantity}"

    def save(self, *args, **kwargs):
        # Calculate total amount
        self.total_amount = self.quantity * self.unit_price
        super().save(*args, **kwargs)
