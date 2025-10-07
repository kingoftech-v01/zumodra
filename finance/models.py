import uuid
from django.db import models
from zumodra import settings
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
    amount = models.DecimalField(max_digits=10, decimal_places=2)  # amount in USD or your currency
    currency = models.CharField(max_length=10, default='USD')
    stripe_payment_intent_id = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    succeeded = models.BooleanField(default=False)
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
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='subscription')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.SET_NULL, null=True)
    stripe_subscription_id = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=50)  # e.g. active, past_due, canceled
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
    amount_due = models.DecimalField(max_digits=10, decimal_places=2)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    currency = models.CharField(max_length=10, default='USD')
    due_date = models.DateTimeField(null=True, blank=True)
    paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Invoice {self.invoice_number} - User {self.user} - Paid: {self.paid}"


class RefundRequest(models.Model):
    """
    Model managing refund requests for payments.
    """
    payment = models.OneToOneField(PaymentTransaction, on_delete=models.CASCADE, related_name='refund_request')
    requested_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(default=False)
    processed_at = models.DateTimeField(null=True, blank=True)
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
    is_default = models.BooleanField(default=False)
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.card_brand} ****{self.card_last4} for {self.user}"


# Optionally: Model for storing webhooks event history for audit
class StripeWebhookEvent(models.Model):
    """
    Logs Stripe webhook notifications for audit and troubleshooting.
    """
    event_id = models.CharField(max_length=255, unique=True)
    json_payload = models.JSONField()
    received_at = models.DateTimeField(auto_now_add=True)
    processed = models.BooleanField(default=False)
    processed_at = models.DateTimeField(null=True, blank=True)
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
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default='USD')
    status = models.CharField(max_length=20, choices=ESCROW_STATUS_CHOICES, default='initialized')
    created_at = models.DateTimeField(auto_now_add=True)
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
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)

    def __str__(self):
        return f"Dispute on {self.escrow} by {self.raised_by} - Resolved: {self.resolved}"


class EscrowPayout(models.Model):
    """
    Records payout transactions to the seller after funds are released from escrow.
    """
    escrow = models.OneToOneField(EscrowTransaction, on_delete=models.CASCADE, related_name='payout')
    payout_id = models.CharField(max_length=255, unique=True)  # payout transaction id from payment gateway
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default='USD')
    paid_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, default='completed')  # e.g. pending, completed, failed
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
    timestamp = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"Audit on {self.escrow} by {self.user} - {self.action} at {self.timestamp}"
