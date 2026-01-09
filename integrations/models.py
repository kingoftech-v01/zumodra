"""
Integrations Models - Third-Party Service Integration Management

This module implements:
- Integration: Base model for all third-party integrations
- IntegrationCredential: Encrypted OAuth tokens and API keys
- IntegrationSyncLog: Sync operation history and status
- WebhookEndpoint: Webhook configuration for integrations
- WebhookDelivery: Webhook delivery tracking and retry logic
"""

import uuid
import hashlib
import hmac
import secrets
from datetime import timedelta
from decimal import Decimal

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.postgres.fields import ArrayField

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


def get_encryption_key():
    """
    Generate encryption key from Django SECRET_KEY.
    Uses PBKDF2 to derive a Fernet-compatible key.
    """
    password = settings.SECRET_KEY.encode()
    salt = b'zumodra_integrations_salt_v1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


class EncryptedTextField(models.TextField):
    """
    Custom field that encrypts data at rest using Fernet symmetric encryption.
    """
    description = "Encrypted text field"

    def __init__(self, *args, **kwargs):
        kwargs['blank'] = kwargs.get('blank', True)
        super().__init__(*args, **kwargs)

    def get_fernet(self):
        return Fernet(get_encryption_key())

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        try:
            fernet = self.get_fernet()
            decrypted = fernet.decrypt(value.encode())
            return decrypted.decode()
        except Exception:
            # Return raw value if decryption fails (for migration scenarios)
            return value

    def get_prep_value(self, value):
        if value is None:
            return value
        fernet = self.get_fernet()
        encrypted = fernet.encrypt(value.encode())
        return encrypted.decode()


class Integration(models.Model):
    """
    Base model for all third-party integrations.
    Tracks integration status, configuration, and tenant association.
    """

    class IntegrationType(models.TextChoices):
        CALENDAR = 'calendar', _('Calendar')
        EMAIL = 'email', _('Email')
        JOB_BOARD = 'job_board', _('Job Board')
        BACKGROUND_CHECK = 'background_check', _('Background Check')
        ESIGN = 'esign', _('E-Signature')
        HRIS = 'hris', _('HRIS')
        MESSAGING = 'messaging', _('Messaging')
        VIDEO = 'video', _('Video Conferencing')
        PAYMENT = 'payment', _('Payment')
        ANALYTICS = 'analytics', _('Analytics')
        CRM = 'crm', _('CRM')
        STORAGE = 'storage', _('Storage')

    class ProviderName(models.TextChoices):
        # Calendar
        GOOGLE_CALENDAR = 'google_calendar', _('Google Calendar')
        OUTLOOK_CALENDAR = 'outlook_calendar', _('Outlook Calendar')
        # Email
        GMAIL = 'gmail', _('Gmail')
        OUTLOOK_EMAIL = 'outlook_email', _('Outlook Email')
        SMTP = 'smtp', _('SMTP')
        SENDGRID = 'sendgrid', _('SendGrid')
        MAILGUN = 'mailgun', _('Mailgun')
        # Job Boards
        INDEED = 'indeed', _('Indeed')
        LINKEDIN = 'linkedin', _('LinkedIn')
        GLASSDOOR = 'glassdoor', _('Glassdoor')
        ZIPRECRUITER = 'ziprecruiter', _('ZipRecruiter')
        # Background Check
        CHECKR = 'checkr', _('Checkr')
        STERLING = 'sterling', _('Sterling')
        HIRERIGHT = 'hireright', _('HireRight')
        # E-Signature
        DOCUSIGN = 'docusign', _('DocuSign')
        HELLOSIGN = 'hellosign', _('HelloSign')
        ADOBE_SIGN = 'adobe_sign', _('Adobe Sign')
        # HRIS
        BAMBOOHR = 'bamboohr', _('BambooHR')
        WORKDAY = 'workday', _('Workday')
        ADP = 'adp', _('ADP')
        GUSTO = 'gusto', _('Gusto')
        # Messaging
        SLACK = 'slack', _('Slack')
        MICROSOFT_TEAMS = 'microsoft_teams', _('Microsoft Teams')
        DISCORD = 'discord', _('Discord')
        # Video
        ZOOM = 'zoom', _('Zoom')
        TEAMS_MEETING = 'teams_meeting', _('Microsoft Teams Meeting')
        GOOGLE_MEET = 'google_meet', _('Google Meet')
        # Other
        STRIPE = 'stripe', _('Stripe')
        GOOGLE_ANALYTICS = 'google_analytics', _('Google Analytics')
        SALESFORCE = 'salesforce', _('Salesforce')
        HUBSPOT = 'hubspot', _('HubSpot')
        AWS_S3 = 'aws_s3', _('AWS S3')
        GOOGLE_DRIVE = 'google_drive', _('Google Drive')

    class Status(models.TextChoices):
        INACTIVE = 'inactive', _('Inactive')
        PENDING = 'pending', _('Pending Setup')
        CONNECTING = 'connecting', _('Connecting')
        ACTIVE = 'active', _('Active')
        ERROR = 'error', _('Error')
        EXPIRED = 'expired', _('Credentials Expired')
        SUSPENDED = 'suspended', _('Suspended')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Tenant association
    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='integrations',
        help_text=_('Tenant this integration belongs to')
    )

    # Integration details
    integration_type = models.CharField(
        max_length=30,
        choices=IntegrationType.choices,
        help_text=_('Category of integration')
    )
    provider = models.CharField(
        max_length=50,
        choices=ProviderName.choices,
        help_text=_('Third-party provider')
    )
    name = models.CharField(
        max_length=255,
        help_text=_('Display name for this integration instance')
    )
    description = models.TextField(
        blank=True,
        help_text=_('Optional description')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.INACTIVE
    )
    status_message = models.TextField(
        blank=True,
        help_text=_('Status details or error message')
    )

    # Configuration (non-sensitive settings)
    config = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Integration-specific configuration')
    )

    # Feature flags
    is_enabled = models.BooleanField(default=True)
    auto_sync = models.BooleanField(
        default=False,
        help_text=_('Enable automatic data synchronization')
    )
    sync_interval_minutes = models.PositiveIntegerField(
        default=60,
        validators=[MinValueValidator(5), MaxValueValidator(1440)],
        help_text=_('Sync interval in minutes (5-1440)')
    )

    # Sync tracking
    last_sync_at = models.DateTimeField(null=True, blank=True)
    next_sync_at = models.DateTimeField(null=True, blank=True)
    sync_error_count = models.PositiveIntegerField(default=0)

    # Ownership
    connected_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='connected_integrations'
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    connected_at = models.DateTimeField(null=True, blank=True)
    disconnected_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Integration')
        verbose_name_plural = _('Integrations')
        ordering = ['-created_at']
        unique_together = ['tenant', 'provider']
        indexes = [
            models.Index(fields=['tenant', 'integration_type']),
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['provider', 'status']),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_provider_display()}) - {self.tenant.name}"

    @property
    def is_active(self):
        return self.status == self.Status.ACTIVE and self.is_enabled

    @property
    def needs_reconnection(self):
        return self.status in [self.Status.ERROR, self.Status.EXPIRED]

    def activate(self):
        """Mark integration as active after successful connection."""
        self.status = self.Status.ACTIVE
        self.connected_at = timezone.now()
        self.status_message = ''
        self.sync_error_count = 0
        self.save(update_fields=['status', 'connected_at', 'status_message', 'sync_error_count', 'updated_at'])

    def deactivate(self, reason=''):
        """Deactivate integration."""
        self.status = self.Status.INACTIVE
        self.disconnected_at = timezone.now()
        self.status_message = reason
        self.save(update_fields=['status', 'disconnected_at', 'status_message', 'updated_at'])

    def mark_error(self, message):
        """Mark integration as having an error."""
        self.status = self.Status.ERROR
        self.status_message = message
        self.sync_error_count += 1
        self.save(update_fields=['status', 'status_message', 'sync_error_count', 'updated_at'])

    def schedule_next_sync(self):
        """Calculate and set next sync time."""
        if self.auto_sync and self.is_active:
            self.next_sync_at = timezone.now() + timedelta(minutes=self.sync_interval_minutes)
            self.save(update_fields=['next_sync_at'])


class IntegrationCredential(models.Model):
    """
    Encrypted storage for OAuth tokens and API credentials.
    Supports OAuth2 flows with automatic token refresh.
    """

    class AuthType(models.TextChoices):
        OAUTH2 = 'oauth2', _('OAuth 2.0')
        API_KEY = 'api_key', _('API Key')
        BASIC = 'basic', _('Basic Auth')
        JWT = 'jwt', _('JWT Token')
        WEBHOOK = 'webhook', _('Webhook Secret')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Integration link
    integration = models.OneToOneField(
        Integration,
        on_delete=models.CASCADE,
        related_name='credentials'
    )

    # Auth type
    auth_type = models.CharField(
        max_length=20,
        choices=AuthType.choices,
        default=AuthType.OAUTH2
    )

    # OAuth2 fields (encrypted)
    access_token = EncryptedTextField(
        blank=True,
        help_text=_('OAuth access token (encrypted)')
    )
    refresh_token = EncryptedTextField(
        blank=True,
        help_text=_('OAuth refresh token (encrypted)')
    )
    token_type = models.CharField(max_length=50, default='Bearer')
    scope = models.TextField(
        blank=True,
        help_text=_('OAuth scopes granted')
    )

    # API Key fields (encrypted)
    api_key = EncryptedTextField(
        blank=True,
        help_text=_('API key (encrypted)')
    )
    api_secret = EncryptedTextField(
        blank=True,
        help_text=_('API secret (encrypted)')
    )

    # Basic auth fields (encrypted)
    username = EncryptedTextField(blank=True)
    password = EncryptedTextField(blank=True)

    # Additional encrypted data
    extra_data = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Additional credential data')
    )

    # Token expiry
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When the access token expires')
    )
    refresh_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When the refresh token expires')
    )

    # External IDs
    external_user_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('User ID in external system')
    )
    external_account_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('Account/organization ID in external system')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_refreshed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Integration Credential')
        verbose_name_plural = _('Integration Credentials')

    def __str__(self):
        return f"Credentials for {self.integration.name}"

    @property
    def is_expired(self):
        """Check if access token is expired."""
        if not self.expires_at:
            return False
        return timezone.now() >= self.expires_at

    @property
    def needs_refresh(self):
        """Check if token should be refreshed (within 5 min of expiry)."""
        if not self.expires_at:
            return False
        buffer = timedelta(minutes=5)
        return timezone.now() >= (self.expires_at - buffer)

    @property
    def can_refresh(self):
        """Check if refresh token is available and valid."""
        if not self.refresh_token:
            return False
        if self.refresh_expires_at and timezone.now() >= self.refresh_expires_at:
            return False
        return True

    def update_tokens(self, access_token, refresh_token=None, expires_in=None, scope=None):
        """Update OAuth tokens after refresh."""
        self.access_token = access_token
        if refresh_token:
            self.refresh_token = refresh_token
        if expires_in:
            self.expires_at = timezone.now() + timedelta(seconds=expires_in)
        if scope:
            self.scope = scope
        self.last_refreshed_at = timezone.now()
        self.save()


class IntegrationSyncLog(models.Model):
    """
    Tracks synchronization operations for auditing and debugging.
    Records both successful and failed sync attempts.
    """

    class SyncType(models.TextChoices):
        FULL = 'full', _('Full Sync')
        INCREMENTAL = 'incremental', _('Incremental Sync')
        WEBHOOK = 'webhook', _('Webhook Triggered')
        MANUAL = 'manual', _('Manual Sync')
        SCHEDULED = 'scheduled', _('Scheduled Sync')

    class SyncStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        RUNNING = 'running', _('Running')
        COMPLETED = 'completed', _('Completed')
        PARTIAL = 'partial', _('Partial Success')
        FAILED = 'failed', _('Failed')
        CANCELLED = 'cancelled', _('Cancelled')

    class SyncDirection(models.TextChoices):
        INBOUND = 'inbound', _('Inbound (from external)')
        OUTBOUND = 'outbound', _('Outbound (to external)')
        BIDIRECTIONAL = 'bidirectional', _('Bidirectional')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Integration link
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name='sync_logs'
    )

    # Sync details
    sync_type = models.CharField(
        max_length=20,
        choices=SyncType.choices,
        default=SyncType.INCREMENTAL
    )
    direction = models.CharField(
        max_length=20,
        choices=SyncDirection.choices,
        default=SyncDirection.INBOUND
    )
    status = models.CharField(
        max_length=20,
        choices=SyncStatus.choices,
        default=SyncStatus.PENDING
    )

    # Resource being synced
    resource_type = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('Type of resource being synced (e.g., contacts, events)')
    )

    # Statistics
    records_processed = models.PositiveIntegerField(default=0)
    records_created = models.PositiveIntegerField(default=0)
    records_updated = models.PositiveIntegerField(default=0)
    records_deleted = models.PositiveIntegerField(default=0)
    records_failed = models.PositiveIntegerField(default=0)

    # Error tracking
    error_message = models.TextField(blank=True)
    error_details = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Detailed error information')
    )

    # Retry tracking
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=3)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    # Triggered by
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='triggered_syncs'
    )

    # Timestamps
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Sync cursor for incremental syncs
    sync_cursor = models.CharField(
        max_length=500,
        blank=True,
        help_text=_('Cursor/token for incremental sync')
    )

    class Meta:
        verbose_name = _('Integration Sync Log')
        verbose_name_plural = _('Integration Sync Logs')
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['integration', '-started_at']),
            models.Index(fields=['integration', 'status']),
        ]

    def __str__(self):
        return f"{self.integration.name} - {self.get_sync_type_display()} ({self.get_status_display()})"

    @property
    def duration_seconds(self):
        """Calculate sync duration in seconds."""
        if not self.completed_at:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def success_rate(self):
        """Calculate success rate as percentage."""
        total = self.records_processed
        if total == 0:
            return 100.0
        successful = total - self.records_failed
        return round((successful / total) * 100, 2)

    @property
    def can_retry(self):
        """Check if sync can be retried."""
        return (
            self.status == self.SyncStatus.FAILED and
            self.retry_count < self.max_retries
        )

    def mark_running(self):
        """Mark sync as running."""
        self.status = self.SyncStatus.RUNNING
        self.save(update_fields=['status'])

    def mark_completed(self, records_processed=0, created=0, updated=0, deleted=0):
        """Mark sync as completed successfully."""
        self.status = self.SyncStatus.COMPLETED
        self.completed_at = timezone.now()
        self.records_processed = records_processed
        self.records_created = created
        self.records_updated = updated
        self.records_deleted = deleted
        self.save()
        # Update integration last sync time
        self.integration.last_sync_at = self.completed_at
        self.integration.schedule_next_sync()

    def mark_failed(self, error_message, error_details=None):
        """Mark sync as failed."""
        self.status = self.SyncStatus.FAILED
        self.completed_at = timezone.now()
        self.error_message = error_message
        if error_details:
            self.error_details = error_details
        self.retry_count += 1
        # Calculate next retry with exponential backoff
        if self.can_retry:
            backoff_minutes = 2 ** self.retry_count
            self.next_retry_at = timezone.now() + timedelta(minutes=backoff_minutes)
        self.save()
        # Update integration error count
        self.integration.mark_error(error_message)


class WebhookEndpoint(models.Model):
    """
    Configuration for incoming webhooks from third-party services.
    Generates unique endpoints and manages verification.
    """

    class Status(models.TextChoices):
        INACTIVE = 'inactive', _('Inactive')
        ACTIVE = 'active', _('Active')
        SUSPENDED = 'suspended', _('Suspended')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Integration link
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name='webhook_endpoints'
    )

    # Endpoint configuration
    name = models.CharField(
        max_length=255,
        help_text=_('Descriptive name for this webhook')
    )
    endpoint_path = models.CharField(
        max_length=255,
        unique=True,
        help_text=_('Unique URL path for this webhook')
    )

    # Security
    secret_key = models.CharField(
        max_length=255,
        help_text=_('Secret for webhook signature verification')
    )
    signature_header = models.CharField(
        max_length=100,
        default='X-Webhook-Signature',
        help_text=_('Header name containing signature')
    )
    signature_algorithm = models.CharField(
        max_length=20,
        default='sha256',
        choices=[
            ('sha256', 'HMAC-SHA256'),
            ('sha1', 'HMAC-SHA1'),
            ('md5', 'HMAC-MD5'),
        ]
    )

    # Event filtering
    subscribed_events = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('List of event types to process')
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE
    )
    is_enabled = models.BooleanField(default=True)

    # Statistics
    total_received = models.PositiveIntegerField(default=0)
    total_processed = models.PositiveIntegerField(default=0)
    total_failed = models.PositiveIntegerField(default=0)
    last_received_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Webhook Endpoint')
        verbose_name_plural = _('Webhook Endpoints')
        ordering = ['-created_at']

    def __str__(self):
        return f"Webhook: {self.name} ({self.integration.name})"

    def save(self, *args, **kwargs):
        if not self.endpoint_path:
            self.endpoint_path = f"webhooks/{self.integration.provider}/{secrets.token_urlsafe(16)}"
        if not self.secret_key:
            self.secret_key = secrets.token_hex(32)
        super().save(*args, **kwargs)

    def verify_signature(self, payload, signature):
        """
        Verify webhook signature using HMAC.
        Returns True if signature is valid.
        """
        if self.signature_algorithm == 'sha256':
            hash_func = hashlib.sha256
        elif self.signature_algorithm == 'sha1':
            hash_func = hashlib.sha1
        else:
            hash_func = hashlib.md5

        if isinstance(payload, str):
            payload = payload.encode()

        expected = hmac.new(
            self.secret_key.encode(),
            payload,
            hash_func
        ).hexdigest()

        return hmac.compare_digest(expected, signature)

    def get_full_url(self):
        """Get the full webhook URL."""
        base_url = getattr(settings, 'BASE_URL', 'http://localhost:8000')
        return f"{base_url}/api/integrations/{self.endpoint_path}/"

    def record_received(self, success=True):
        """Update statistics after receiving a webhook."""
        self.total_received += 1
        if success:
            self.total_processed += 1
        else:
            self.total_failed += 1
        self.last_received_at = timezone.now()
        self.save(update_fields=['total_received', 'total_processed', 'total_failed', 'last_received_at'])


class WebhookDelivery(models.Model):
    """
    Records individual webhook deliveries for auditing and retry handling.
    """

    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        PROCESSING = 'processing', _('Processing')
        DELIVERED = 'delivered', _('Delivered')
        FAILED = 'failed', _('Failed')
        RETRYING = 'retrying', _('Retrying')
        EXPIRED = 'expired', _('Expired')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Webhook endpoint link
    endpoint = models.ForeignKey(
        WebhookEndpoint,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )

    # Delivery details
    event_type = models.CharField(
        max_length=100,
        help_text=_('Type of event received')
    )
    event_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('External event ID for deduplication')
    )

    # Payload
    headers = models.JSONField(
        default=dict,
        help_text=_('Request headers')
    )
    payload = models.JSONField(
        default=dict,
        help_text=_('Webhook payload')
    )

    # Signature verification
    signature_valid = models.BooleanField(
        default=False,
        help_text=_('Whether signature verification passed')
    )
    signature_received = models.CharField(max_length=255, blank=True)

    # Status
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    status_message = models.TextField(blank=True)

    # Response tracking (for outbound webhooks)
    response_status_code = models.PositiveIntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)

    # Retry handling
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=5)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    # Processing result
    processed_at = models.DateTimeField(null=True, blank=True)
    processing_result = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Result of webhook processing')
    )

    # Request metadata
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)

    # Timestamps
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Webhook Delivery')
        verbose_name_plural = _('Webhook Deliveries')
        ordering = ['-received_at']
        indexes = [
            models.Index(fields=['endpoint', '-received_at']),
            models.Index(fields=['endpoint', 'status']),
            models.Index(fields=['event_id']),
        ]

    def __str__(self):
        return f"Webhook {self.event_type} to {self.endpoint.name} ({self.get_status_display()})"

    @property
    def can_retry(self):
        """Check if delivery can be retried."""
        return (
            self.status == self.Status.FAILED and
            self.retry_count < self.max_retries
        )

    @property
    def processing_time_ms(self):
        """Calculate processing time in milliseconds."""
        if not self.processed_at:
            return None
        delta = self.processed_at - self.received_at
        return int(delta.total_seconds() * 1000)

    def is_duplicate(self):
        """Check if this event has already been processed."""
        if not self.event_id:
            return False
        return WebhookDelivery.objects.filter(
            endpoint=self.endpoint,
            event_id=self.event_id,
            status=self.Status.DELIVERED
        ).exclude(pk=self.pk).exists()

    def mark_processing(self):
        """Mark delivery as being processed."""
        self.status = self.Status.PROCESSING
        self.save(update_fields=['status'])

    def mark_delivered(self, result=None):
        """Mark delivery as successfully processed."""
        self.status = self.Status.DELIVERED
        self.processed_at = timezone.now()
        if result:
            self.processing_result = result
        self.save()
        self.endpoint.record_received(success=True)

    def mark_failed(self, message, schedule_retry=True):
        """Mark delivery as failed with optional retry scheduling."""
        self.status = self.Status.FAILED
        self.status_message = message
        self.retry_count += 1

        if schedule_retry and self.can_retry:
            # Exponential backoff: 1, 2, 4, 8, 16 minutes
            backoff_minutes = 2 ** (self.retry_count - 1)
            self.next_retry_at = timezone.now() + timedelta(minutes=backoff_minutes)
            self.status = self.Status.RETRYING

        self.save()
        self.endpoint.record_received(success=False)


class IntegrationEvent(models.Model):
    """
    Tracks significant events in integration lifecycle.
    Used for auditing and debugging integration issues.
    """

    class EventType(models.TextChoices):
        CONNECTED = 'connected', _('Connected')
        DISCONNECTED = 'disconnected', _('Disconnected')
        TOKEN_REFRESHED = 'token_refreshed', _('Token Refreshed')
        SYNC_STARTED = 'sync_started', _('Sync Started')
        SYNC_COMPLETED = 'sync_completed', _('Sync Completed')
        SYNC_FAILED = 'sync_failed', _('Sync Failed')
        WEBHOOK_RECEIVED = 'webhook_received', _('Webhook Received')
        CONFIG_CHANGED = 'config_changed', _('Configuration Changed')
        ERROR = 'error', _('Error')
        RATE_LIMITED = 'rate_limited', _('Rate Limited')

    # Identity
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)

    # Integration link
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name='events'
    )

    # Event details
    event_type = models.CharField(
        max_length=30,
        choices=EventType.choices
    )
    message = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)

    # Actor
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Integration Event')
        verbose_name_plural = _('Integration Events')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['integration', '-created_at']),
            models.Index(fields=['integration', 'event_type']),
        ]

    def __str__(self):
        return f"{self.integration.name} - {self.get_event_type_display()}"


# Register models with auditlog
from auditlog.registry import auditlog
auditlog.register(Integration)
auditlog.register(IntegrationCredential, exclude_fields=['access_token', 'refresh_token', 'api_key', 'api_secret', 'password'])
auditlog.register(WebhookEndpoint, exclude_fields=['secret_key'])

# Import outbound webhook models for Django discovery
try:
    from integrations.outbound_webhooks import OutboundWebhook, OutboundWebhookDelivery
    auditlog.register(OutboundWebhook, exclude_fields=['secret'])
except ImportError:
    pass
