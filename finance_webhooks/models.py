"""
Finance Webhooks Models - Webhook Event Handling

Handles webhooks from:
- Stripe (payments, subscriptions, Connect)
- Avalara (tax updates)
- QuickBooks/Xero (accounting sync)
"""

from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from decimal import Decimal
import uuid


class WebhookSource(models.TextChoices):
    """Webhook source providers"""
    STRIPE = 'stripe', 'Stripe'
    AVALARA = 'avalara', 'Avalara'
    QUICKBOOKS = 'quickbooks', 'QuickBooks'
    XERO = 'xero', 'Xero'


class WebhookStatus(models.TextChoices):
    """Webhook processing status"""
    PENDING = 'pending', 'Pending'
    PROCESSING = 'processing', 'Processing'
    SUCCEEDED = 'succeeded', 'Succeeded'
    FAILED = 'failed', 'Failed'
    IGNORED = 'ignored', 'Ignored'


class WebhookEvent(models.Model):
    """
    Incoming webhook event log.
    Records all webhook events from finance integrations.
    """

    # Primary Key
    webhook_id = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        editable=False,
        help_text="Auto-generated webhook ID"
    )

    # Source
    source = models.CharField(
        max_length=20,
        choices=WebhookSource.choices,
        db_index=True,
        help_text="Webhook source provider"
    )

    # Event Details
    event_type = models.CharField(
        max_length=100,
        db_index=True,
        help_text="Event type (e.g., payment_intent.succeeded)"
    )

    event_id = models.CharField(
        max_length=255,
        db_index=True,
        help_text="External event ID from provider"
    )

    # Payload
    payload = models.JSONField(
        help_text="Full webhook payload"
    )

    # Processing Status
    status = models.CharField(
        max_length=20,
        choices=WebhookStatus.choices,
        default=WebhookStatus.PENDING,
        db_index=True
    )

    # Processing Details
    processed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the webhook was processed"
    )

    error_message = models.TextField(
        blank=True,
        help_text="Error message if processing failed"
    )

    # Related Object (generic)
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Type of related object"
    )
    object_id = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="ID of related object"
    )
    related_object = GenericForeignKey('content_type', 'object_id')

    # Signature Verification
    signature_verified = models.BooleanField(
        default=False,
        help_text="Whether webhook signature was verified"
    )

    signature = models.TextField(
        blank=True,
        help_text="Webhook signature from provider"
    )

    # Retry Count
    retry_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of processing retries"
    )

    # Metadata
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional metadata"
    )

    # Timestamps
    received_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="When webhook was received"
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    class Meta:
        db_table = 'finance_webhooks_event'
        ordering = ['-received_at']
        indexes = [
            models.Index(fields=['source', 'event_type']),
            models.Index(fields=['source', 'status']),
            models.Index(fields=['event_id', 'source']),
            models.Index(fields=['received_at', 'status']),
        ]
        verbose_name = 'Webhook Event'
        verbose_name_plural = 'Webhook Events'

    def __str__(self):
        return f"{self.webhook_id} - {self.source}:{self.event_type}"

    def save(self, *args, **kwargs):
        if not self.webhook_id:
            self.webhook_id = f"WHK-{uuid.uuid4().hex[:12].upper()}"
        super().save(*args, **kwargs)

    def mark_processing(self):
        """Mark webhook as being processed"""
        self.status = WebhookStatus.PROCESSING
        self.save(update_fields=['status', 'updated_at'])

    def mark_succeeded(self, related_object=None):
        """Mark webhook processing as successful"""
        self.status = WebhookStatus.SUCCEEDED
        self.processed_at = timezone.now()

        if related_object:
            self.content_type = ContentType.objects.get_for_model(related_object)
            self.object_id = related_object.pk

        self.save(update_fields=[
            'status',
            'processed_at',
            'content_type',
            'object_id',
            'updated_at'
        ])

    def mark_failed(self, error_message):
        """Mark webhook processing as failed"""
        self.status = WebhookStatus.FAILED
        self.processed_at = timezone.now()
        self.error_message = error_message
        self.save(update_fields=[
            'status',
            'processed_at',
            'error_message',
            'updated_at'
        ])

    def mark_ignored(self, reason=''):
        """Mark webhook as ignored (not relevant)"""
        self.status = WebhookStatus.IGNORED
        self.processed_at = timezone.now()
        if reason:
            self.error_message = reason
        self.save(update_fields=[
            'status',
            'processed_at',
            'error_message',
            'updated_at'
        ])

    def increment_retry(self):
        """Increment retry count"""
        self.retry_count += 1
        self.save(update_fields=['retry_count', 'updated_at'])


class WebhookRetry(models.Model):
    """
    Webhook retry tracking.
    Logs retry attempts for failed webhook processing.
    """

    # Webhook
    webhook_event = models.ForeignKey(
        WebhookEvent,
        on_delete=models.CASCADE,
        related_name='retries',
        help_text="Related webhook event"
    )

    # Retry Details
    retry_number = models.PositiveIntegerField(
        help_text="Retry attempt number"
    )

    retry_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When retry was attempted"
    )

    # Result
    succeeded = models.BooleanField(
        default=False,
        help_text="Whether retry succeeded"
    )

    error_message = models.TextField(
        blank=True,
        help_text="Error message if retry failed"
    )

    # Next Retry
    next_retry_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When next retry is scheduled"
    )

    class Meta:
        db_table = 'finance_webhooks_retry'
        ordering = ['-retry_at']
        indexes = [
            models.Index(fields=['webhook_event', 'retry_number']),
            models.Index(fields=['next_retry_at']),
        ]
        verbose_name = 'Webhook Retry'
        verbose_name_plural = 'Webhook Retries'

    def __str__(self):
        return f"Retry #{self.retry_number} for {self.webhook_event.webhook_id}"

    @staticmethod
    def calculate_next_retry(retry_count):
        """
        Calculate next retry time using exponential backoff.

        Retry schedule:
        - 1st retry: 5 minutes
        - 2nd retry: 15 minutes
        - 3rd retry: 1 hour
        - 4th retry: 4 hours
        - 5th retry: 24 hours
        """
        from datetime import timedelta

        backoff_schedule = {
            1: timedelta(minutes=5),
            2: timedelta(minutes=15),
            3: timedelta(hours=1),
            4: timedelta(hours=4),
            5: timedelta(hours=24),
        }

        delay = backoff_schedule.get(retry_count, timedelta(hours=24))
        return timezone.now() + delay


class WebhookSignature(models.Model):
    """
    Webhook signature verification log.
    Security audit trail for webhook signatures.
    """

    # Webhook
    webhook_event = models.ForeignKey(
        WebhookEvent,
        on_delete=models.CASCADE,
        related_name='signature_logs',
        help_text="Related webhook event"
    )

    # Verification Details
    verified = models.BooleanField(
        help_text="Whether signature was valid"
    )

    signature = models.TextField(
        help_text="Webhook signature"
    )

    expected_signature = models.TextField(
        blank=True,
        help_text="Expected signature (computed)"
    )

    # Verification Method
    algorithm = models.CharField(
        max_length=50,
        help_text="Signature algorithm (e.g., HMAC-SHA256)"
    )

    # Timestamp
    timestamp = models.DateTimeField(
        auto_now_add=True,
        help_text="Verification timestamp"
    )

    # IP Address
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Request IP address"
    )

    # User Agent
    user_agent = models.TextField(
        blank=True,
        help_text="Request User-Agent header"
    )

    class Meta:
        db_table = 'finance_webhooks_signature'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['webhook_event', 'verified']),
            models.Index(fields=['verified', 'timestamp']),
        ]
        verbose_name = 'Webhook Signature'
        verbose_name_plural = 'Webhook Signatures'

    def __str__(self):
        status = "✓ Valid" if self.verified else "✗ Invalid"
        return f"{status} - {self.webhook_event.webhook_id}"


class WebhookEventType(models.Model):
    """
    Webhook event type registry.
    Defines which event types are supported and how to handle them.
    """

    # Source
    source = models.CharField(
        max_length=20,
        choices=WebhookSource.choices,
        help_text="Webhook source provider"
    )

    # Event Type
    event_type = models.CharField(
        max_length=100,
        help_text="Event type identifier"
    )

    # Handler
    handler_path = models.CharField(
        max_length=255,
        help_text="Python path to handler function (e.g., finance_webhooks.handlers.stripe.payment_succeeded)"
    )

    # Settings
    is_enabled = models.BooleanField(
        default=True,
        help_text="Whether this event type is enabled"
    )

    auto_retry = models.BooleanField(
        default=True,
        help_text="Whether to automatically retry failed events"
    )

    max_retries = models.PositiveIntegerField(
        default=5,
        help_text="Maximum retry attempts"
    )

    # Description
    description = models.TextField(
        blank=True,
        help_text="Event type description"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'finance_webhooks_event_type'
        unique_together = [('source', 'event_type')]
        ordering = ['source', 'event_type']
        verbose_name = 'Webhook Event Type'
        verbose_name_plural = 'Webhook Event Types'

    def __str__(self):
        return f"{self.source}:{self.event_type}"
