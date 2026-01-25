"""
Payments App Models - Multi-Currency Payment Processing (TENANT Schema)

This app handles tenant payment transactions (tenants charging their clients).
All payments are tenant-scoped with multi-currency support.
"""

from decimal import Decimal
from django.db import models
from django.core.validators import MinValueValidator
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django_tenants.models import TenantMixin
from core_identity.models import CustomUser  # Renamed from custom_account_u (Phase 10)
from core.models import TenantAwareModel  # Import from core.models instead of defining here


class Currency(TenantAwareModel):
    """
    Supported currencies for multi-currency payment processing.

    Each tenant can configure which currencies they accept.
    Exchange rates are tracked separately for historical accuracy.
    """
    code = models.CharField(
        max_length=3,
        unique=True,
        help_text="ISO 4217 currency code (USD, EUR, CAD, etc.)"
    )
    name = models.CharField(max_length=100)
    symbol = models.CharField(max_length=10)
    decimal_places = models.PositiveSmallIntegerField(
        default=2,
        validators=[MinValueValidator(0)],
        help_text="Number of decimal places for this currency"
    )

    # Status
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this currency is available for new transactions"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Currency"
        verbose_name_plural = "Currencies"
        ordering = ['code']
        indexes = [
            models.Index(fields=['code']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.code} ({self.symbol})"


class ExchangeRate(TenantAwareModel):
    """
    Historical exchange rates for currency conversion.

    Rates are stored daily and used for:
    - Converting payments to base currency (USD)
    - Historical reporting
    - Accurate refund calculations
    """
    from_currency = models.ForeignKey(
        Currency,
        on_delete=models.CASCADE,
        related_name='rates_from'
    )
    to_currency = models.ForeignKey(
        Currency,
        on_delete=models.CASCADE,
        related_name='rates_to'
    )
    rate = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        validators=[MinValueValidator(Decimal('0.00000001'))],
        help_text="Exchange rate from source to target currency"
    )
    date = models.DateField(
        help_text="Date this rate is effective for"
    )

    # Source
    source = models.CharField(
        max_length=50,
        default='api',
        help_text="Source of exchange rate (api, manual, etc.)"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Exchange Rate"
        verbose_name_plural = "Exchange Rates"
        unique_together = [('from_currency', 'to_currency', 'date')]
        ordering = ['-date', 'from_currency']
        indexes = [
            models.Index(fields=['from_currency', 'to_currency', 'date']),
            models.Index(fields=['-date']),
        ]

    def __str__(self):
        return f"{self.from_currency.code} → {self.to_currency.code}: {self.rate} ({self.date})"

    @classmethod
    def get_rate(cls, from_currency, to_currency, date=None):
        """
        Get exchange rate for a specific date.
        If date is None, use today's date.
        """
        if from_currency == to_currency:
            return Decimal('1.0')

        if date is None:
            date = timezone.now().date()

        try:
            rate = cls.objects.get(
                from_currency=from_currency,
                to_currency=to_currency,
                date=date
            )
            return rate.rate
        except cls.DoesNotExist:
            # Try to find most recent rate before this date
            rate = cls.objects.filter(
                from_currency=from_currency,
                to_currency=to_currency,
                date__lte=date
            ).order_by('-date').first()

            if rate:
                return rate.rate

            raise ValueError(
                f"No exchange rate found for {from_currency.code} → {to_currency.code} "
                f"on or before {date}"
            )


class PaymentMethod(TenantAwareModel):
    """
    Stored payment methods for customers.

    Supports:
    - Credit/debit cards (via Stripe)
    - Bank accounts
    - Digital wallets
    """
    class PaymentMethodType(models.TextChoices):
        CARD = 'card', 'Credit/Debit Card'
        BANK_ACCOUNT = 'bank_account', 'Bank Account'
        WALLET = 'wallet', 'Digital Wallet'
        OTHER = 'other', 'Other'

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='payment_methods'
    )

    # Method Details
    method_type = models.CharField(
        max_length=20,
        choices=PaymentMethodType.choices,
        default=PaymentMethodType.CARD
    )

    # Card Details (if applicable)
    card_brand = models.CharField(max_length=50, blank=True)
    card_last4 = models.CharField(max_length=4, blank=True)
    card_exp_month = models.PositiveSmallIntegerField(null=True, blank=True)
    card_exp_year = models.PositiveSmallIntegerField(null=True, blank=True)

    # Bank Account Details (if applicable)
    bank_name = models.CharField(max_length=100, blank=True)
    account_last4 = models.CharField(max_length=4, blank=True)

    # Stripe Integration
    stripe_payment_method_id = models.CharField(max_length=255, unique=True, blank=True)

    # Status
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Payment Method"
        verbose_name_plural = "Payment Methods"
        ordering = ['-is_default', '-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['stripe_payment_method_id']),
        ]

    def __str__(self):
        if self.method_type == self.PaymentMethodType.CARD:
            return f"{self.card_brand} ****{self.card_last4}"
        elif self.method_type == self.PaymentMethodType.BANK_ACCOUNT:
            return f"{self.bank_name} ****{self.account_last4}"
        return f"{self.get_method_type_display()}"

    def save(self, *args, **kwargs):
        # If setting as default, unset other defaults for this user
        if self.is_default:
            PaymentMethod.objects.filter(
                user=self.user,
                is_default=True
            ).exclude(pk=self.pk).update(is_default=False)
        super().save(*args, **kwargs)


class PaymentTransaction(TenantAwareModel):
    """
    Individual payment transaction records.

    Tracks all payment activity for this tenant with multi-currency support.
    Each transaction stores the original amount, currency, exchange rate, and
    normalized USD amount for reporting.
    """
    class PaymentStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        SUCCEEDED = 'succeeded', 'Succeeded'
        FAILED = 'failed', 'Failed'
        CANCELED = 'canceled', 'Canceled'
        REFUNDED = 'refunded', 'Refunded'
        PARTIALLY_REFUNDED = 'partially_refunded', 'Partially Refunded'

    # Unique identifier
    transaction_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Unique transaction identifier (auto-generated)"
    )

    # Amount (multi-currency)
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text="Transaction amount in original currency"
    )
    currency = models.ForeignKey(
        Currency,
        on_delete=models.PROTECT,
        help_text="Currency of the transaction"
    )
    exchange_rate = models.ForeignKey(
        ExchangeRate,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        help_text="Exchange rate used for this transaction"
    )
    amount_usd = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Amount normalized to USD for reporting",
        editable=False
    )

    # Parties
    payer = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='payments_made',
        help_text="User making the payment"
    )
    payee = models.ForeignKey(
        CustomUser,
        on_delete=models.PROTECT,
        related_name='payments_received',
        help_text="User receiving the payment"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=PaymentStatus.choices,
        default=PaymentStatus.PENDING,
        db_index=True
    )

    # Payment Method
    payment_method = models.ForeignKey(
        PaymentMethod,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='transactions'
    )

    # Stripe Integration
    stripe_payment_intent_id = models.CharField(max_length=255, blank=True, db_index=True)
    stripe_charge_id = models.CharField(max_length=255, blank=True, db_index=True)
    stripe_transfer_id = models.CharField(max_length=255, blank=True)

    # Description
    description = models.TextField(blank=True)

    # Related Object (generic FK to link to Appointment, Project, etc.)
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    related_object = GenericForeignKey('content_type', 'object_id')

    # Dates
    succeeded_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)
    refunded_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional metadata (JSON)"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Payment Transaction"
        verbose_name_plural = "Payment Transactions"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['transaction_id']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['payer', '-created_at']),
            models.Index(fields=['payee', '-created_at']),
            models.Index(fields=['stripe_payment_intent_id']),
            models.Index(fields=['content_type', 'object_id']),
        ]

    def __str__(self):
        return f"{self.transaction_id} - {self.amount} {self.currency.code} ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        # Generate transaction ID if not set
        if not self.transaction_id:
            import uuid
            self.transaction_id = f"TXN-{uuid.uuid4().hex[:16].upper()}"

        # Calculate USD amount if not set
        if not self.amount_usd:
            usd_currency = Currency.objects.get(code='USD')
            if self.currency.code == 'USD':
                self.amount_usd = self.amount
            else:
                rate = ExchangeRate.get_rate(
                    self.currency,
                    usd_currency,
                    self.created_at.date() if self.created_at else timezone.now().date()
                )
                self.amount_usd = self.amount * rate

        super().save(*args, **kwargs)

    @property
    def is_successful(self):
        """Check if payment succeeded"""
        return self.status == self.PaymentStatus.SUCCEEDED

    @property
    def can_be_refunded(self):
        """Check if payment can be refunded"""
        return self.status == self.PaymentStatus.SUCCEEDED


class RefundRequest(TenantAwareModel):
    """
    Refund tracking for payment transactions.

    Supports:
    - Full refunds
    - Partial refunds
    - Multiple refunds per transaction
    """
    class RefundStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        SUCCEEDED = 'succeeded', 'Succeeded'
        FAILED = 'failed', 'Failed'
        CANCELED = 'canceled', 'Canceled'

    class RefundReason(models.TextChoices):
        DUPLICATE = 'duplicate', 'Duplicate Payment'
        FRAUDULENT = 'fraudulent', 'Fraudulent'
        REQUESTED_BY_CUSTOMER = 'requested_by_customer', 'Requested by Customer'
        SERVICE_NOT_PROVIDED = 'service_not_provided', 'Service Not Provided'
        PRODUCT_DEFECT = 'product_defect', 'Product Defect'
        OTHER = 'other', 'Other'

    # Refund identifier
    refund_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Unique refund identifier (auto-generated)"
    )

    # Original transaction
    transaction = models.ForeignKey(
        PaymentTransaction,
        on_delete=models.CASCADE,
        related_name='refunds'
    )

    # Refund Amount
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text="Refund amount (can be partial)"
    )

    # Status and Reason
    status = models.CharField(
        max_length=20,
        choices=RefundStatus.choices,
        default=RefundStatus.PENDING,
        db_index=True
    )
    reason = models.CharField(
        max_length=50,
        choices=RefundReason.choices,
        default=RefundReason.REQUESTED_BY_CUSTOMER
    )
    reason_details = models.TextField(blank=True)

    # Requested by
    requested_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        related_name='refunds_requested'
    )

    # Stripe Integration
    stripe_refund_id = models.CharField(max_length=255, blank=True, db_index=True)

    # Dates
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Refund Request"
        verbose_name_plural = "Refund Requests"
        ordering = ['-requested_at']
        indexes = [
            models.Index(fields=['refund_id']),
            models.Index(fields=['transaction', '-requested_at']),
            models.Index(fields=['status', '-requested_at']),
            models.Index(fields=['stripe_refund_id']),
        ]

    def __str__(self):
        return f"Refund {self.refund_id} - {self.amount} {self.transaction.currency.code}"

    def save(self, *args, **kwargs):
        # Generate refund ID if not set
        if not self.refund_id:
            import uuid
            self.refund_id = f"REF-{uuid.uuid4().hex[:16].upper()}"

        # Validate refund amount doesn't exceed transaction amount
        if self.amount > self.transaction.amount:
            raise ValueError(
                f"Refund amount ({self.amount}) cannot exceed "
                f"transaction amount ({self.transaction.amount})"
            )

        super().save(*args, **kwargs)

    @property
    def is_successful(self):
        """Check if refund succeeded"""
        return self.status == self.RefundStatus.SUCCEEDED


class PaymentIntent(TenantAwareModel):
    """
    Stripe payment intent tracking.

    Tracks the lifecycle of a Stripe payment intent from creation to completion.
    Used for 3D Secure, payment method updates, and complex payment flows.
    """
    class IntentStatus(models.TextChoices):
        REQUIRES_PAYMENT_METHOD = 'requires_payment_method', 'Requires Payment Method'
        REQUIRES_CONFIRMATION = 'requires_confirmation', 'Requires Confirmation'
        REQUIRES_ACTION = 'requires_action', 'Requires Action'
        PROCESSING = 'processing', 'Processing'
        REQUIRES_CAPTURE = 'requires_capture', 'Requires Capture'
        CANCELED = 'canceled', 'Canceled'
        SUCCEEDED = 'succeeded', 'Succeeded'

    # Stripe Payment Intent ID
    stripe_payment_intent_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True
    )

    # Amount
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))]
    )
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)

    # Status
    status = models.CharField(
        max_length=30,
        choices=IntentStatus.choices,
        db_index=True
    )

    # Customer
    customer = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='payment_intents'
    )

    # Payment Method
    payment_method = models.ForeignKey(
        PaymentMethod,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    # Related Transaction (if completed)
    transaction = models.OneToOneField(
        PaymentTransaction,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='payment_intent'
    )

    # Client Secret (for frontend)
    client_secret = models.CharField(max_length=255, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Payment Intent"
        verbose_name_plural = "Payment Intents"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['stripe_payment_intent_id']),
            models.Index(fields=['customer', '-created_at']),
            models.Index(fields=['status', '-created_at']),
        ]

    def __str__(self):
        return f"{self.stripe_payment_intent_id} - {self.amount} {self.currency.code} ({self.get_status_display()})"

    @property
    def is_successful(self):
        """Check if payment intent succeeded"""
        return self.status == self.IntentStatus.SUCCEEDED
