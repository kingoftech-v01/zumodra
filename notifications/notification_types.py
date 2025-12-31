"""
Tenant-aware NotificationType Model for Configurable Notifications.

This module provides a flexible, tenant-aware notification type system that allows
each tenant to customize notification behavior, templates, and delivery channels.
"""

import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.template import Template, Context
from django.utils.translation import gettext_lazy as _


class NotificationType(models.Model):
    """
    Tenant-aware configurable notification types with Jinja2 template support.

    Allows each tenant to customize notification behavior, templates, and channels
    for different notification categories.
    """
    CATEGORY_CHOICES = [
        ('hr', _('HR & Recruitment')),
        ('finance', _('Payments & Finance')),
        ('services', _('Services & Contracts')),
        ('appointments', _('Appointments')),
        ('messages', _('Messages & Communication')),
        ('reviews', _('Reviews & Ratings')),
        ('account', _('Account & Security')),
        ('system', _('System & Administrative')),
        ('marketing', _('Marketing & Engagement')),
        ('custom', _('Custom')),
    ]

    PRIORITY_CHOICES = [
        ('low', _('Low')),
        ('normal', _('Normal')),
        ('high', _('High')),
        ('urgent', _('Urgent')),
    ]

    # Identification
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    slug = models.SlugField(
        max_length=100,
        help_text=_("Unique identifier for this notification type (e.g., 'appointment_reminder')")
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # Categorization
    category = models.CharField(
        max_length=50,
        choices=CATEGORY_CHOICES,
        default='custom'
    )

    # Default channels for this notification type
    default_channels = models.ManyToManyField(
        'notifications.NotificationChannel',
        related_name='notification_types',
        blank=True,
        help_text=_("Default channels to send this notification type through")
    )

    # Jinja2 Templates for content rendering
    subject_template = models.CharField(
        max_length=500,
        blank=True,
        help_text=_("Jinja2 template for subject line. Variables: {{ user }}, {{ data }}, etc.")
    )
    body_template = models.TextField(
        blank=True,
        help_text=_("Jinja2 template for notification body (plain text)")
    )
    html_template = models.TextField(
        blank=True,
        help_text=_("Jinja2 template for HTML body (for email)")
    )

    # Behavior settings
    default_priority = models.CharField(
        max_length=10,
        choices=PRIORITY_CHOICES,
        default='normal'
    )
    is_active = models.BooleanField(default=True)
    is_user_configurable = models.BooleanField(
        default=True,
        help_text=_("Whether users can disable this notification type")
    )
    requires_immediate_delivery = models.BooleanField(
        default=False,
        help_text=_("Bypass digest mode and send immediately")
    )

    # Rate limiting
    max_per_hour = models.PositiveIntegerField(
        default=0,
        help_text=_("Maximum notifications of this type per hour per user (0 = unlimited)")
    )
    cooldown_minutes = models.PositiveIntegerField(
        default=0,
        help_text=_("Minimum minutes between notifications of this type to same user (0 = no cooldown)")
    )

    # Expiration
    default_ttl_hours = models.PositiveIntegerField(
        default=0,
        help_text=_("Default time-to-live in hours (0 = never expires)")
    )

    # Schema for required context data
    context_schema = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("JSON schema defining required context variables for this notification type")
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_notification_types'
    )

    class Meta:
        ordering = ['category', 'name']
        verbose_name = _('Notification Type')
        verbose_name_plural = _('Notification Types')
        constraints = [
            models.UniqueConstraint(
                fields=['slug'],
                name='unique_notification_type_slug'
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_category_display()})"

    def render_subject(self, context: dict) -> str:
        """Render subject using Jinja2 template."""
        if not self.subject_template:
            return ""
        try:
            from jinja2 import Template as Jinja2Template
            template = Jinja2Template(self.subject_template)
            return template.render(**context)
        except ImportError:
            # Fallback to Django template if Jinja2 not available
            template = Template(self.subject_template)
            return template.render(Context(context))
        except Exception as e:
            return self.subject_template

    def render_body(self, context: dict) -> str:
        """Render body using Jinja2 template."""
        if not self.body_template:
            return ""
        try:
            from jinja2 import Template as Jinja2Template
            template = Jinja2Template(self.body_template)
            return template.render(**context)
        except ImportError:
            template = Template(self.body_template)
            return template.render(Context(context))
        except Exception as e:
            return self.body_template

    def render_html(self, context: dict) -> str:
        """Render HTML body using Jinja2 template."""
        if not self.html_template:
            return ""
        try:
            from jinja2 import Template as Jinja2Template
            template = Jinja2Template(self.html_template)
            return template.render(**context)
        except ImportError:
            template = Template(self.html_template)
            return template.render(Context(context))
        except Exception as e:
            return self.html_template

    def validate_context(self, context: dict) -> bool:
        """Validate context data against the schema."""
        if not self.context_schema:
            return True
        try:
            import jsonschema
            jsonschema.validate(context, self.context_schema)
            return True
        except ImportError:
            # jsonschema not installed, skip validation
            return True
        except Exception:
            return False

    def get_channels_for_user(self, user) -> list:
        """Get enabled channels for this notification type for a specific user."""
        try:
            pref = user.notification_preferences
            if not pref.notifications_enabled or pref.global_unsubscribe:
                return []

            enabled_channels = []
            for channel in self.default_channels.filter(is_active=True):
                if pref.is_type_enabled(self.slug, channel.channel_type):
                    enabled_channels.append(channel)
            return enabled_channels
        except Exception:
            return list(self.default_channels.filter(is_active=True))

    def can_send_to_user(self, user) -> tuple:
        """
        Check if this notification type can be sent to a user.

        Returns:
            tuple: (can_send: bool, reason: str)
        """
        try:
            pref = user.notification_preferences

            if not pref.notifications_enabled:
                return False, "User has disabled all notifications"

            if pref.global_unsubscribe:
                return False, "User has globally unsubscribed"

            if self.slug in pref.unsubscribed_types:
                return False, f"User has unsubscribed from {self.name}"

            if not self.is_user_configurable:
                return True, "Notification type is mandatory"

            # Check rate limiting
            if self.max_per_hour > 0:
                from .models import Notification
                from datetime import timedelta

                one_hour_ago = timezone.now() - timedelta(hours=1)
                recent_count = Notification.objects.filter(
                    recipient=user,
                    notification_type=self.slug,
                    created_at__gte=one_hour_ago,
                ).count()

                if recent_count >= self.max_per_hour:
                    return False, f"Rate limit exceeded ({self.max_per_hour}/hour)"

            # Check cooldown
            if self.cooldown_minutes > 0:
                from .models import Notification
                from datetime import timedelta

                cooldown_start = timezone.now() - timedelta(minutes=self.cooldown_minutes)
                recent = Notification.objects.filter(
                    recipient=user,
                    notification_type=self.slug,
                    created_at__gte=cooldown_start,
                ).exists()

                if recent:
                    return False, f"Cooldown period active ({self.cooldown_minutes} minutes)"

            return True, "OK"

        except Exception as e:
            return True, f"Check failed, allowing: {str(e)}"


class NotificationLog(models.Model):
    """
    Per-channel delivery log for tracking notification delivery across multiple channels.

    This complements NotificationDeliveryLog by providing a more detailed view
    of the delivery status per channel for multi-channel notifications.
    """
    STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('queued', _('Queued')),
        ('sending', _('Sending')),
        ('sent', _('Sent')),
        ('delivered', _('Delivered')),
        ('failed', _('Failed')),
        ('bounced', _('Bounced')),
        ('rejected', _('Rejected')),
    ]

    # Identification
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Related notification
    notification = models.ForeignKey(
        'notifications.Notification',
        on_delete=models.CASCADE,
        related_name='channel_logs'
    )

    # Channel info
    channel = models.ForeignKey(
        'notifications.NotificationChannel',
        on_delete=models.CASCADE,
        related_name='delivery_logs_v2'
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )

    # External tracking
    external_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Message ID from external service (e.g., SendGrid ID, Twilio SID)")
    )
    external_status = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Status from external service webhook")
    )

    # Error handling
    error_code = models.CharField(max_length=50, blank=True)
    error_message = models.TextField(blank=True)
    error_details = models.JSONField(default=dict, blank=True)

    # Retry tracking
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=3)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    # Timing
    queued_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)

    # Request/Response tracking
    request_payload = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Request sent to external service")
    )
    response_payload = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Response from external service")
    )
    response_code = models.IntegerField(null=True, blank=True)

    # Cost tracking (for SMS, etc.)
    cost = models.DecimalField(
        max_digits=10,
        decimal_places=4,
        null=True,
        blank=True,
        help_text=_("Cost of sending this notification (if applicable)")
    )
    currency = models.CharField(max_length=3, blank=True, default='USD')

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['notification', 'channel']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['external_id']),
            models.Index(fields=['next_retry_at']),
        ]
        verbose_name = _('Notification Log')
        verbose_name_plural = _('Notification Logs')

    def __str__(self):
        return f"{self.notification.uuid} - {self.channel.channel_type}: {self.status}"

    def mark_queued(self):
        """Mark as queued for sending."""
        self.status = 'queued'
        self.queued_at = timezone.now()
        self.save(update_fields=['status', 'queued_at', 'updated_at'])

    def mark_sent(self, external_id: str = None, response: dict = None):
        """Mark as sent."""
        self.status = 'sent'
        self.sent_at = timezone.now()
        if external_id:
            self.external_id = external_id
        if response:
            self.response_payload = response
        self.save(update_fields=['status', 'sent_at', 'external_id', 'response_payload', 'updated_at'])

    def mark_delivered(self, external_status: str = None):
        """Mark as delivered (confirmed by external service)."""
        self.status = 'delivered'
        self.delivered_at = timezone.now()
        if external_status:
            self.external_status = external_status
        self.save(update_fields=['status', 'delivered_at', 'external_status', 'updated_at'])

    def mark_failed(self, error_message: str, error_code: str = '', error_details: dict = None):
        """Mark as failed."""
        from datetime import timedelta

        self.status = 'failed'
        self.failed_at = timezone.now()
        self.error_message = error_message
        self.error_code = error_code
        if error_details:
            self.error_details = error_details
        self.retry_count += 1

        # Schedule retry with exponential backoff
        if self.can_retry():
            backoff_minutes = 2 ** self.retry_count  # 2, 4, 8, 16...
            self.next_retry_at = timezone.now() + timedelta(minutes=backoff_minutes)

        self.save()

    def can_retry(self) -> bool:
        """Check if this delivery can be retried."""
        return self.retry_count < self.max_retries and self.status == 'failed'

    def record_cost(self, amount: float, currency: str = 'USD'):
        """Record the cost of sending this notification."""
        from decimal import Decimal
        self.cost = Decimal(str(amount))
        self.currency = currency
        self.save(update_fields=['cost', 'currency', 'updated_at'])


# Register for audit logging
try:
    from auditlog.registry import auditlog
    auditlog.register(NotificationType)
    auditlog.register(NotificationLog)
except ImportError:
    pass
