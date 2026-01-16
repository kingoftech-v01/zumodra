import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone

# Create your models here.

User = settings.AUTH_USER_MODEL


class PaymentTransaction(models.Model):
    """
    Records each payment transaction attempt.
    Stores essential Stripe or gateway info, status, and links to user and order (if any).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2, db_index=True)  # Index for financial queries
    currency = models.CharField(max_length=10, default='USD')
    stripe_payment_intent_id = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for timeline queries
    succeeded = models.BooleanField(default=False, db_index=True)  # Index for status filtering
    failure_code = models.CharField(max_length=100, blank=True, null=True)
    failure_message = models.TextField(blank=True, null=True)

    def __str__(self):
        status = "Succeeded" if self.succeeded else "Failed/Processing"
        return f"Payment {self.id} by {self.user} - {status} - ${self.amount}"


class SubscriptionPlan(models.Model):
    """
    Subscription plans offered to users.
    """
    name = models.CharField(max_length=100)
    stripe_product_id = models.CharField(max_length=255)  # Stripe Product ID
    stripe_price_id = models.CharField(max_length=255)  # Stripe Price ID (recurring)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default='USD')
    interval = models.CharField(max_length=20, choices=[('month', 'Monthly'), ('year', 'Yearly')])
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.name} - {self.price} {self.currency} / {self.interval}"


class UserSubscription(models.Model):
    """
    Tracks the user's subscription status.
    Linked to Stripe subscription ID and current active status.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='subscription_status_user')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.SET_NULL, null=True, db_index=True)  # Index for plan-based queries
    stripe_subscription_id = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=50, db_index=True)  # Index for subscription status filtering (active, past_due, canceled)
    current_period_start = models.DateTimeField()
    current_period_end = models.DateTimeField()

    def __str__(self):
        return f"{self.user} subscription {self.plan} status: {self.status}"


class Invoice(models.Model):
    """
    Represents payment invoices generated for transactions or subscriptions.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='invoices')
    invoice_number = models.CharField(max_length=100, unique=True)
    stripe_invoice_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    amount_due = models.DecimalField(max_digits=10, decimal_places=2, db_index=True)  # Index for financial reporting
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0, db_index=True)  # Index for payment tracking
    currency = models.CharField(max_length=10, default='USD')
    due_date = models.DateTimeField(null=True, blank=True)
    paid = models.BooleanField(default=False, db_index=True)  # Index for invoice status filtering
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for invoice timeline queries
    paid_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for payment date filtering

    def __str__(self):
        return f"Invoice {self.invoice_number} - User {self.user} - Paid: {self.paid}"


class RefundRequest(models.Model):
    """
    Model managing refund requests for payments.
    """
    payment = models.OneToOneField(PaymentTransaction, on_delete=models.CASCADE, related_name='refund_request')
    requested_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for refund timeline queries
    approved = models.BooleanField(default=False, db_index=True)  # Index for refund status filtering
    processed_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for processed refund tracking
    processed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='processed_refunds')
    reason = models.TextField(blank=True)

    def __str__(self):
        return f"Refund for {self.payment.id} - Approved: {self.approved}"


class PaymentMethod(models.Model):
    """
    Stores information about user's saved payment methods.
    Useful for subscriptions or one-click payments.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payment_methods')
    stripe_payment_method_id = models.CharField(max_length=255, unique=True)
    card_brand = models.CharField(max_length=50)
    card_last4 = models.CharField(max_length=4)
    card_exp_month = models.PositiveIntegerField()
    card_exp_year = models.PositiveIntegerField()
    is_default = models.BooleanField(default=False, db_index=True)  # Index for default payment method lookup
    added_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for payment method timeline

    def __str__(self):
        return f"{self.card_brand} ****{self.card_last4} for {self.user}"


# Optionally: Model for storing webhooks event history for audit
class StripeWebhookEvent(models.Model):
    """
    Logs Stripe webhook notifications for audit and troubleshooting.
    """
    event_id = models.CharField(max_length=255, unique=True)
    json_payload = models.JSONField()
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for webhook event timeline
    processed = models.BooleanField(default=False, db_index=True)  # Index for unprocessed webhook filtering
    processed_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for processed webhook tracking
    error_message = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Stripe event {self.event_id} – Processed: {self.processed}"


class EscrowTransaction(models.Model):
    """
    Represents a transaction held in escrow.
    Funds are held securely until agreed conditions (like service delivery)
    are met, then released or refunded based on approvals.
    """
    ESCROW_STATUS_CHOICES = [
        ('initialized', 'Initialized'),
        ('funded', 'Funded'),
        ('service_delivered', 'Service Delivered'),
        ('dispute', 'Dispute Raised'),
        ('released', 'Funds Released'),
        ('refunded', 'Funds Refunded'),
        ('cancelled', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    buyer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='escrow_buyer_transactions')
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='escrow_seller_transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2, db_index=True)  # Index for escrow financial queries
    currency = models.CharField(max_length=10, default='USD')
    status = models.CharField(max_length=20, choices=ESCROW_STATUS_CHOICES, default='initialized', db_index=True)  # Index for escrow status filtering
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for escrow timeline queries
    funded_at = models.DateTimeField(null=True, blank=True)
    service_delivered_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)
    refunded_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    dispute_raised_at = models.DateTimeField(null=True, blank=True)

    # Payment gateway integration fields (e.g. Stripe charge or payment intent ID)
    payment_intent_id = models.CharField(max_length=255, blank=True, null=True)
    payout_id = models.CharField(max_length=255, blank=True, null=True)  # record payout transaction

    # Optional: Conditions summary or contract link
    agreement_details = models.TextField(blank=True)

    def __str__(self):
        return f"EscrowTransaction {self.id} - {self.status} - ${self.amount}"

    def mark_funded(self):
        self.status = 'funded'
        self.funded_at = timezone.now()
        self.save()

    def mark_service_delivered(self):
        self.status = 'service_delivered'
        self.service_delivered_at = timezone.now()
        self.save()

    def mark_released(self):
        self.status = 'released'
        self.released_at = timezone.now()
        self.save()

    def mark_refunded(self):
        self.status = 'refunded'
        self.refunded_at = timezone.now()
        self.save()

    def raise_dispute(self):
        self.status = 'dispute'
        self.dispute_raised_at = timezone.now()
        self.save()

    def cancel(self):
        self.status = 'cancelled'
        self.cancelled_at = timezone.now()
        self.save()


class Dispute(models.Model):
    """
    Represents a dispute raised by either party regarding the escrow transaction.
    Can be resolved by manual intervention or automated workflows.
    """
    escrow = models.ForeignKey(EscrowTransaction, on_delete=models.CASCADE, related_name='disputes')
    raised_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='raised_disputes')
    reason = models.TextField()
    details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for dispute timeline
    resolved = models.BooleanField(default=False, db_index=True)  # Index for unresolved dispute filtering
    resolved_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for dispute resolution tracking
    resolution_notes = models.TextField(blank=True)

    def __str__(self):
        return f"Dispute on {self.escrow} by {self.raised_by} - Resolved: {self.resolved}"


class EscrowPayout(models.Model):
    """
    Records payout transactions to the seller after funds are released from escrow.
    """
    escrow = models.OneToOneField(EscrowTransaction, on_delete=models.CASCADE, related_name='payout')
    payout_id = models.CharField(max_length=255, unique=True)  # payout transaction id from payment gateway
    amount = models.DecimalField(max_digits=10, decimal_places=2, db_index=True)  # Index for payout amount queries
    currency = models.CharField(max_length=10, default='USD')
    paid_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for payout timeline queries
    status = models.CharField(max_length=50, default='completed', db_index=True)  # Index for payout status filtering
    failure_reason = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Payout {self.payout_id} - {self.status} - ${self.amount}"


class EscrowAudit(models.Model):
    """
    Logs all significant status changes and actions on escrow transactions
    for compliance, transparency, and troubleshooting.
    """
    escrow = models.ForeignKey(EscrowTransaction, on_delete=models.CASCADE, related_name='audit_logs')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=100)  # e.g. 'funded', 'dispute_raised', 'payout_initiated'
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for audit log timeline queries
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"Audit on {self.escrow} by {self.user} - {self.action} at {self.timestamp}"


# =============================================================================
# Stripe Connect Marketplace Integration Models
# =============================================================================

class ConnectedAccount(models.Model):
    """
    Stripe Connect account for sellers/freelancers.
    Enables marketplace payments where the platform facilitates transactions
    between buyers and sellers, taking a commission.
    """
    ACCOUNT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('onboarding', 'Onboarding'),
        ('active', 'Active'),
        ('restricted', 'Restricted'),
        ('disabled', 'Disabled'),
    ]

    BUSINESS_TYPE_CHOICES = [
        ('individual', 'Individual'),
        ('company', 'Company'),
        ('non_profit', 'Non-Profit'),
        ('government_entity', 'Government Entity'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='connected_account')

    # Stripe Connect account identifiers
    account_id = models.CharField(max_length=255, unique=True, blank=True, null=True)
    account_status = models.CharField(max_length=20, choices=ACCOUNT_STATUS_CHOICES, default='pending', db_index=True)  # Index for account status filtering

    # Account capabilities
    charges_enabled = models.BooleanField(default=False)
    payouts_enabled = models.BooleanField(default=False)
    details_submitted = models.BooleanField(default=False)

    # Capability statuses (JSON for flexibility with Stripe's capability structure)
    capabilities = models.JSONField(default=dict, blank=True)
    # Example: {"transfers": "active", "card_payments": "active"}

    # Business information
    country = models.CharField(max_length=2, default='US')  # ISO 3166-1 alpha-2
    default_currency = models.CharField(max_length=10, default='USD')
    business_type = models.CharField(max_length=20, choices=BUSINESS_TYPE_CHOICES, default='individual')

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for account creation timeline
    updated_at = models.DateTimeField(auto_now=True, db_index=True)  # Index for recently updated accounts
    activated_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for activated account tracking

    # Additional Stripe metadata
    stripe_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = 'Connected Account'
        verbose_name_plural = 'Connected Accounts'

    def __str__(self):
        return f"ConnectedAccount {self.account_id} for {self.user} - {self.account_status}"

    def create_connect_account(self, stripe_client=None):
        """
        Creates a Stripe Connect Express account for the user.
        Returns the account object or raises an exception on failure.
        """
        import stripe
        if stripe_client is None:
            stripe_client = stripe

        try:
            account = stripe_client.Account.create(
                type='express',
                country=self.country,
                email=self.user.email,
                business_type=self.business_type,
                capabilities={
                    'transfers': {'requested': True},
                    'card_payments': {'requested': True},
                },
                metadata={
                    'user_id': str(self.user.id),
                    'platform': 'zumodra',
                },
            )
            self.account_id = account.id
            self.account_status = 'onboarding'
            self.stripe_metadata = dict(account)
            self.save()
            return account
        except stripe.error.StripeError as e:
            raise e

    def create_account_link(self, return_url, refresh_url, stripe_client=None):
        """
        Creates an account link for Stripe Connect onboarding.
        Returns the account link URL for redirecting the user.
        """
        import stripe
        if stripe_client is None:
            stripe_client = stripe

        if not self.account_id:
            raise ValueError("Account ID is required to create an account link.")

        try:
            account_link = stripe_client.AccountLink.create(
                account=self.account_id,
                refresh_url=refresh_url,
                return_url=return_url,
                type='account_onboarding',
            )
            return account_link.url
        except stripe.error.StripeError as e:
            raise e

    def handle_capability_updated(self, capability_name, status):
        """
        Updates the capability status for this connected account.
        Called when receiving Stripe webhook events for capability updates.
        """
        self.capabilities[capability_name] = status

        # Update overall account status based on capabilities
        if self.capabilities.get('transfers') == 'active' and self.capabilities.get('card_payments') == 'active':
            if self.account_status != 'active':
                self.account_status = 'active'
                self.activated_at = timezone.now()
        elif status == 'inactive' or status == 'pending':
            if self.account_status == 'active':
                self.account_status = 'restricted'

        self.save()

    def refresh_account_status(self, stripe_client=None):
        """
        Fetches the latest account status from Stripe and updates local fields.
        """
        import stripe
        if stripe_client is None:
            stripe_client = stripe

        if not self.account_id:
            return

        try:
            account = stripe_client.Account.retrieve(self.account_id)
            self.charges_enabled = account.charges_enabled
            self.payouts_enabled = account.payouts_enabled
            self.details_submitted = account.details_submitted

            # Update capabilities from Stripe
            if hasattr(account, 'capabilities'):
                self.capabilities = dict(account.capabilities)

            # Determine account status
            if account.charges_enabled and account.payouts_enabled:
                self.account_status = 'active'
                if not self.activated_at:
                    self.activated_at = timezone.now()
            elif account.details_submitted:
                self.account_status = 'restricted'
            else:
                self.account_status = 'onboarding'

            self.stripe_metadata = dict(account)
            self.save()
            return account
        except stripe.error.StripeError as e:
            raise e

    def initiate_payout(self, amount, currency=None, stripe_client=None):
        """
        Initiates a payout to the connected account's bank account.
        Returns the payout object or raises an exception.
        """
        import stripe
        if stripe_client is None:
            stripe_client = stripe

        if not self.account_id:
            raise ValueError("Account ID is required to initiate a payout.")

        if not self.payouts_enabled:
            raise ValueError("Payouts are not enabled for this account.")

        currency = currency or self.default_currency

        try:
            payout = stripe_client.Payout.create(
                amount=int(amount * 100),  # Convert to cents
                currency=currency.lower(),
                stripe_account=self.account_id,
            )
            return payout
        except stripe.error.StripeError as e:
            raise e


class PayoutSchedule(models.Model):
    """
    Configurable payout schedules for connected accounts.
    Allows customization of when and how often payouts occur.
    """
    INTERVAL_CHOICES = [
        ('manual', 'Manual'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]

    WEEKLY_ANCHOR_CHOICES = [
        ('monday', 'Monday'),
        ('tuesday', 'Tuesday'),
        ('wednesday', 'Wednesday'),
        ('thursday', 'Thursday'),
        ('friday', 'Friday'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connected_account = models.OneToOneField(
        ConnectedAccount,
        on_delete=models.CASCADE,
        related_name='payout_schedule'
    )

    interval = models.CharField(max_length=20, choices=INTERVAL_CHOICES, default='daily')
    weekly_anchor = models.CharField(
        max_length=10,
        choices=WEEKLY_ANCHOR_CHOICES,
        default='friday',
        blank=True
    )
    monthly_anchor = models.PositiveIntegerField(
        default=1,
        help_text="Day of the month for monthly payouts (1-31)"
    )
    delay_days = models.PositiveIntegerField(
        default=2,
        help_text="Number of days to delay payouts after funds are available"
    )

    # Minimum payout threshold
    minimum_payout_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        help_text="Minimum balance required to trigger a payout"
    )

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for schedule creation timeline
    updated_at = models.DateTimeField(auto_now=True, db_index=True)  # Index for recently updated schedules

    class Meta:
        verbose_name = 'Payout Schedule'
        verbose_name_plural = 'Payout Schedules'

    def __str__(self):
        return f"PayoutSchedule for {self.connected_account} - {self.interval}"

    def apply_to_stripe(self, stripe_client=None):
        """
        Applies this payout schedule configuration to Stripe.
        """
        import stripe
        if stripe_client is None:
            stripe_client = stripe

        if not self.connected_account.account_id:
            raise ValueError("Connected account must have a Stripe account ID.")

        schedule_config = {
            'interval': self.interval,
            'delay_days': self.delay_days,
        }

        if self.interval == 'weekly':
            schedule_config['weekly_anchor'] = self.weekly_anchor
        elif self.interval == 'monthly':
            schedule_config['monthly_anchor'] = self.monthly_anchor

        try:
            account = stripe_client.Account.modify(
                self.connected_account.account_id,
                settings={
                    'payouts': {
                        'schedule': schedule_config,
                    },
                },
            )
            return account
        except stripe.error.StripeError as e:
            raise e


class PlatformFee(models.Model):
    """
    Platform commission tracking for marketplace transactions.
    Records the platform's take from each transaction processed through Stripe Connect.
    """
    FEE_TYPE_CHOICES = [
        ('percentage', 'Percentage'),
        ('fixed', 'Fixed Amount'),
        ('combined', 'Percentage + Fixed'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('collected', 'Collected'),
        ('refunded', 'Refunded'),
        ('partially_refunded', 'Partially Refunded'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Related transaction
    escrow = models.ForeignKey(
        EscrowTransaction,
        on_delete=models.CASCADE,
        related_name='platform_fees',
        null=True,
        blank=True
    )
    payment_transaction = models.ForeignKey(
        PaymentTransaction,
        on_delete=models.CASCADE,
        related_name='platform_fees',
        null=True,
        blank=True
    )
    connected_account = models.ForeignKey(
        ConnectedAccount,
        on_delete=models.CASCADE,
        related_name='platform_fees'
    )

    # Fee details
    fee_type = models.CharField(max_length=20, choices=FEE_TYPE_CHOICES, default='percentage')
    percentage_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        help_text="Percentage rate (e.g., 10.00 for 10%)"
    )
    fixed_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        help_text="Fixed fee amount"
    )

    # Calculated fee
    transaction_amount = models.DecimalField(max_digits=10, decimal_places=2)
    fee_amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default='USD')

    # Stripe references
    stripe_application_fee_id = models.CharField(max_length=255, blank=True, null=True)
    stripe_transfer_id = models.CharField(max_length=255, blank=True, null=True)

    # Status tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', db_index=True)  # Index for fee status filtering
    collected_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for collected fee tracking
    refunded_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for refunded fee tracking
    refunded_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0, db_index=True)  # Index for refund amount queries

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for fee creation timeline
    updated_at = models.DateTimeField(auto_now=True, db_index=True)  # Index for recently updated fees

    class Meta:
        verbose_name = 'Platform Fee'
        verbose_name_plural = 'Platform Fees'

    def __str__(self):
        return f"PlatformFee {self.id} - {self.fee_amount} {self.currency} ({self.status})"

    def calculate_fee(self):
        """
        Calculates the fee amount based on fee type and rates.
        """
        if self.fee_type == 'percentage':
            self.fee_amount = self.transaction_amount * (self.percentage_rate / 100)
        elif self.fee_type == 'fixed':
            self.fee_amount = self.fixed_amount
        elif self.fee_type == 'combined':
            percentage_fee = self.transaction_amount * (self.percentage_rate / 100)
            self.fee_amount = percentage_fee + self.fixed_amount

        self.save()
        return self.fee_amount

    def mark_collected(self, stripe_application_fee_id=None):
        """
        Marks the fee as collected.
        """
        self.status = 'collected'
        self.collected_at = timezone.now()
        if stripe_application_fee_id:
            self.stripe_application_fee_id = stripe_application_fee_id
        self.save()

    def refund_fee(self, amount=None, stripe_client=None):
        """
        Refunds the platform fee (fully or partially).
        """
        import stripe
        if stripe_client is None:
            stripe_client = stripe

        if not self.stripe_application_fee_id:
            raise ValueError("No Stripe application fee ID to refund.")

        refund_amount = amount if amount else self.fee_amount

        try:
            refund = stripe_client.ApplicationFee.create_refund(
                self.stripe_application_fee_id,
                amount=int(refund_amount * 100),  # Convert to cents
            )

            self.refunded_amount += refund_amount
            self.refunded_at = timezone.now()

            if self.refunded_amount >= self.fee_amount:
                self.status = 'refunded'
            else:
                self.status = 'partially_refunded'

            self.save()
            return refund
        except stripe.error.StripeError as e:
            raise e


class StripeConnectOnboarding(models.Model):
    """
    Tracks the onboarding status and progress for Stripe Connect accounts.
    Manages the multi-step onboarding flow and stores relevant URLs.
    """
    ONBOARDING_STATUS_CHOICES = [
        ('not_started', 'Not Started'),
        ('in_progress', 'In Progress'),
        ('pending_verification', 'Pending Verification'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('expired', 'Expired'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connected_account = models.OneToOneField(
        ConnectedAccount,
        on_delete=models.CASCADE,
        related_name='onboarding'
    )

    # Onboarding status
    status = models.CharField(
        max_length=25,
        choices=ONBOARDING_STATUS_CHOICES,
        default='not_started',
        db_index=True  # Index for onboarding status filtering
    )

    # Onboarding URLs
    onboarding_url = models.URLField(max_length=500, blank=True, null=True)
    return_url = models.URLField(max_length=500, blank=True, null=True)
    refresh_url = models.URLField(max_length=500, blank=True, null=True)

    # Progress tracking
    requirements_current = models.JSONField(
        default=list,
        blank=True,
        help_text="Current requirements from Stripe"
    )
    requirements_past_due = models.JSONField(
        default=list,
        blank=True,
        help_text="Past due requirements from Stripe"
    )
    requirements_eventually_due = models.JSONField(
        default=list,
        blank=True,
        help_text="Eventually due requirements from Stripe"
    )
    requirements_pending_verification = models.JSONField(
        default=list,
        blank=True,
        help_text="Requirements pending verification"
    )

    # Timestamps
    started_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for onboarding start tracking
    completed_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for completed onboarding tracking
    last_updated_at = models.DateTimeField(auto_now=True, db_index=True)  # Index for recently updated onboardings
    link_expires_at = models.DateTimeField(null=True, blank=True, db_index=True)  # Index for expired link detection

    # Error tracking
    error_message = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for onboarding creation timeline

    class Meta:
        verbose_name = 'Stripe Connect Onboarding'
        verbose_name_plural = 'Stripe Connect Onboardings'

    def __str__(self):
        return f"Onboarding for {self.connected_account} - {self.status}"

    def generate_onboarding_link(self, return_url, refresh_url, stripe_client=None):
        """
        Generates a new onboarding link for the connected account.
        Updates the URLs and status accordingly.
        """
        self.return_url = return_url
        self.refresh_url = refresh_url

        try:
            onboarding_url = self.connected_account.create_account_link(
                return_url=return_url,
                refresh_url=refresh_url,
                stripe_client=stripe_client
            )
            self.onboarding_url = onboarding_url
            self.status = 'in_progress'
            if not self.started_at:
                self.started_at = timezone.now()

            # Stripe account links expire after a short time
            self.link_expires_at = timezone.now() + timezone.timedelta(minutes=30)
            self.save()
            return onboarding_url
        except Exception as e:
            self.status = 'failed'
            self.error_message = str(e)
            self.save()
            raise e

    def update_requirements(self, requirements_data):
        """
        Updates the requirements fields from Stripe webhook data.
        """
        self.requirements_current = requirements_data.get('currently_due', [])
        self.requirements_past_due = requirements_data.get('past_due', [])
        self.requirements_eventually_due = requirements_data.get('eventually_due', [])
        self.requirements_pending_verification = requirements_data.get('pending_verification', [])

        # Update status based on requirements
        if not any([
            self.requirements_current,
            self.requirements_past_due,
            self.requirements_eventually_due,
            self.requirements_pending_verification
        ]):
            self.status = 'completed'
            self.completed_at = timezone.now()
        elif self.requirements_pending_verification:
            self.status = 'pending_verification'
        elif self.requirements_past_due:
            self.status = 'failed'

        self.save()

    def is_link_expired(self):
        """
        Checks if the current onboarding link has expired.
        """
        if not self.link_expires_at:
            return True
        return timezone.now() > self.link_expires_at

    def refresh_onboarding_link(self, stripe_client=None):
        """
        Refreshes the onboarding link if it has expired.
        """
        if not self.return_url or not self.refresh_url:
            raise ValueError("Return URL and refresh URL are required.")

        return self.generate_onboarding_link(
            return_url=self.return_url,
            refresh_url=self.refresh_url,
            stripe_client=stripe_client
        )
