"""
Notification Models for Multi-Channel Notification System.

Supports email, SMS, push notifications, in-app, Slack, and scheduled notifications
with template rendering, delivery tracking, and user preferences.
"""

import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.template import Template, Context
from django.utils.translation import gettext_lazy as _


class NotificationChannel(models.Model):
    """
    Available notification channels (email, SMS, push, in-app, Slack, etc.)
    """
    CHANNEL_TYPES = [
        ('email', _('Email')),
        ('sms', _('SMS')),
        ('push', _('Push Notification')),
        ('in_app', _('In-App Notification')),
        ('slack', _('Slack')),
        ('webhook', _('Webhook')),
    ]

    name = models.CharField(max_length=50, unique=True)
    channel_type = models.CharField(max_length=20, choices=CHANNEL_TYPES)
    is_active = models.BooleanField(default=True)
    description = models.TextField(blank=True)

    # Channel-specific configuration (JSON)
    config = models.JSONField(default=dict, blank=True, help_text=_("Channel-specific configuration"))

    # Rate limiting
    rate_limit_per_hour = models.PositiveIntegerField(
        default=100,
        help_text=_("Maximum notifications per hour for this channel")
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        verbose_name = _('Notification Channel')
        verbose_name_plural = _('Notification Channels')

    def __str__(self):
        return f"{self.name} ({self.get_channel_type_display()})"


class NotificationTemplate(models.Model):
    """
    Reusable notification templates for different channels.
    Supports Django template syntax for dynamic content.
    """
    TEMPLATE_TYPES = [
        # HR & Recruitment
        ('application_received', _('Application Received')),
        ('application_reviewed', _('Application Reviewed')),
        ('interview_scheduled', _('Interview Scheduled')),
        ('interview_reminder', _('Interview Reminder')),
        ('interview_cancelled', _('Interview Cancelled')),
        ('offer_sent', _('Offer Sent')),
        ('offer_accepted', _('Offer Accepted')),
        ('offer_declined', _('Offer Declined')),
        ('onboarding_task_due', _('Onboarding Task Due')),
        ('onboarding_complete', _('Onboarding Complete')),

        # Time & Attendance
        ('time_off_requested', _('Time Off Requested')),
        ('time_off_approved', _('Time Off Approved')),
        ('time_off_denied', _('Time Off Denied')),
        ('timesheet_reminder', _('Timesheet Reminder')),
        ('timesheet_approved', _('Timesheet Approved')),

        # Services & Contracts
        ('proposal_received', _('Proposal Received')),
        ('proposal_accepted', _('Proposal Accepted')),
        ('proposal_rejected', _('Proposal Rejected')),
        ('contract_created', _('Contract Created')),
        ('contract_signed', _('Contract Signed')),
        ('contract_completed', _('Contract Completed')),
        ('contract_cancelled', _('Contract Cancelled')),

        # Payments & Finance
        ('payment_received', _('Payment Received')),
        ('payment_sent', _('Payment Sent')),
        ('payment_failed', _('Payment Failed')),
        ('invoice_generated', _('Invoice Generated')),
        ('escrow_funded', _('Escrow Funded')),
        ('escrow_released', _('Escrow Released')),
        ('refund_processed', _('Refund Processed')),

        # Reviews & Ratings
        ('review_received', _('Review Received')),
        ('review_response', _('Review Response')),

        # Messages & Communication
        ('new_message', _('New Message')),
        ('message_reply', _('Message Reply')),

        # Appointments
        ('appointment_booked', _('Appointment Booked')),
        ('appointment_reminder', _('Appointment Reminder')),
        ('appointment_cancelled', _('Appointment Cancelled')),
        ('appointment_rescheduled', _('Appointment Rescheduled')),

        # Account & Security
        ('account_created', _('Account Created')),
        ('password_changed', _('Password Changed')),
        ('login_alert', _('Login Alert')),
        ('two_factor_enabled', _('Two Factor Enabled')),
        ('account_suspended', _('Account Suspended')),
        ('account_reactivated', _('Account Reactivated')),

        # System & Administrative
        ('system_maintenance', _('System Maintenance')),
        ('feature_announcement', _('Feature Announcement')),
        ('policy_update', _('Policy Update')),

        # Marketing & Engagement
        ('welcome_email', _('Welcome Email')),
        ('weekly_digest', _('Weekly Digest')),
        ('daily_digest', _('Daily Digest')),
        ('promotional', _('Promotional')),
        ('event_invitation', _('Event Invitation')),

        # Custom
        ('custom', _('Custom')),
    ]

    name = models.CharField(max_length=100, unique=True)
    template_type = models.CharField(max_length=50, choices=TEMPLATE_TYPES)
    channel = models.ForeignKey(
        NotificationChannel,
        on_delete=models.CASCADE,
        related_name='templates'
    )

    # Template content
    subject = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Subject line (for email/push). Supports Django template syntax.")
    )
    body = models.TextField(
        help_text=_("Notification body. Supports Django template syntax.")
    )
    html_body = models.TextField(
        blank=True,
        help_text=_("HTML version of the body (for email). Supports Django template syntax.")
    )

    # Localization
    language = models.CharField(
        max_length=10,
        default='en',
        help_text=_("Language code (e.g., 'en', 'fr', 'es')")
    )

    # Metadata
    is_active = models.BooleanField(default=True)
    description = models.TextField(blank=True)

    # Default context variables (JSON schema for validation)
    default_context = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Default context variables for template rendering")
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_templates'
    )

    class Meta:
        ordering = ['template_type', 'channel', 'language']
        unique_together = ['template_type', 'channel', 'language']
        verbose_name = _('Notification Template')
        verbose_name_plural = _('Notification Templates')

    def __str__(self):
        return f"{self.name} ({self.channel.name} - {self.language})"

    def render_subject(self, context: dict) -> str:
        """Render subject with context variables."""
        if not self.subject:
            return ""
        template = Template(self.subject)
        return template.render(Context(context))

    def render_body(self, context: dict) -> str:
        """Render plain text body with context variables."""
        template = Template(self.body)
        return template.render(Context(context))

    def render_html_body(self, context: dict) -> str:
        """Render HTML body with context variables."""
        if not self.html_body:
            return ""
        template = Template(self.html_body)
        return template.render(Context(context))


class NotificationPreference(models.Model):
    """
    User preferences for notifications across different channels and types.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notification_preferences'
    )

    # Global settings
    notifications_enabled = models.BooleanField(
        default=True,
        help_text=_("Master switch for all notifications")
    )
    quiet_hours_enabled = models.BooleanField(default=False)
    quiet_hours_start = models.TimeField(null=True, blank=True)
    quiet_hours_end = models.TimeField(null=True, blank=True)
    timezone = models.CharField(max_length=50, default='UTC')

    # Channel preferences (JSON: {"email": true, "sms": false, ...})
    channel_preferences = models.JSONField(
        default=dict,
        help_text=_("Per-channel enable/disable settings")
    )

    # Notification type preferences (JSON: {"proposal": {"email": true, "push": true}, ...})
    type_preferences = models.JSONField(
        default=dict,
        help_text=_("Per-type and per-channel preferences")
    )

    # Contact info for notifications
    phone_number = models.CharField(max_length=20, blank=True)
    slack_user_id = models.CharField(max_length=50, blank=True)
    fcm_token = models.TextField(blank=True, help_text=_("Firebase Cloud Messaging token"))
    apns_token = models.TextField(blank=True, help_text=_("Apple Push Notification token"))

    # Digest settings
    email_digest_frequency = models.CharField(
        max_length=20,
        choices=[
            ('realtime', _('Real-time')),
            ('hourly', _('Hourly')),
            ('daily', _('Daily')),
            ('weekly', _('Weekly')),
            ('never', _('Never')),
        ],
        default='realtime'
    )

    # Unsubscribe tracking
    unsubscribe_token = models.UUIDField(default=uuid.uuid4, unique=True)
    global_unsubscribe = models.BooleanField(default=False)
    unsubscribed_types = models.JSONField(
        default=list,
        help_text=_("List of notification types user has unsubscribed from")
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Notification Preference')
        verbose_name_plural = _('Notification Preferences')

    def __str__(self):
        return f"Notification preferences for {self.user}"

    def is_channel_enabled(self, channel_type: str) -> bool:
        """Check if a specific channel is enabled for this user."""
        if not self.notifications_enabled or self.global_unsubscribe:
            return False
        return self.channel_preferences.get(channel_type, True)

    def is_type_enabled(self, notification_type: str, channel_type: str) -> bool:
        """Check if a specific notification type on a channel is enabled."""
        if not self.is_channel_enabled(channel_type):
            return False
        if notification_type in self.unsubscribed_types:
            return False
        type_prefs = self.type_preferences.get(notification_type, {})
        return type_prefs.get(channel_type, True)

    def is_quiet_hours(self) -> bool:
        """Check if current time is within quiet hours."""
        if not self.quiet_hours_enabled or not self.quiet_hours_start or not self.quiet_hours_end:
            return False

        from pytz import timezone as pytz_timezone
        try:
            tz = pytz_timezone(self.timezone)
            now = timezone.now().astimezone(tz).time()

            start = self.quiet_hours_start
            end = self.quiet_hours_end

            if start <= end:
                return start <= now <= end
            else:
                # Quiet hours span midnight
                return now >= start or now <= end
        except Exception:
            return False


class Notification(models.Model):
    """
    Individual notification instance with delivery tracking.
    """
    NOTIFICATION_TYPES = NotificationTemplate.TEMPLATE_TYPES

    STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('queued', _('Queued')),
        ('sending', _('Sending')),
        ('sent', _('Sent')),
        ('delivered', _('Delivered')),
        ('read', _('Read')),
        ('failed', _('Failed')),
        ('cancelled', _('Cancelled')),
    ]

    PRIORITY_CHOICES = [
        ('low', _('Low')),
        ('normal', _('Normal')),
        ('high', _('High')),
        ('urgent', _('Urgent')),
    ]

    # Identification
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Recipients
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notifications',
        help_text=_("User who receives this notification")
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sent_notifications',
        help_text=_("User who triggered this notification (optional)")
    )

    # Channel and type
    channel = models.ForeignKey(
        NotificationChannel,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    notification_type = models.CharField(
        max_length=50,
        choices=NOTIFICATION_TYPES,
        default='custom',
        db_index=True
    )
    template = models.ForeignKey(
        NotificationTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='notifications'
    )

    # Content
    title = models.CharField(max_length=255)
    message = models.TextField()
    html_message = models.TextField(blank=True)
    action_url = models.URLField(blank=True, max_length=500)
    action_text = models.CharField(max_length=100, blank=True, default=_("View"))

    # Context data used for rendering
    context_data = models.JSONField(default=dict, blank=True)

    # Generic relation to any model
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    # Status and tracking
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        db_index=True
    )
    priority = models.CharField(
        max_length=10,
        choices=PRIORITY_CHOICES,
        default='normal'
    )

    # Read/interaction tracking
    is_read = models.BooleanField(default=False, db_index=True)
    read_at = models.DateTimeField(null=True, blank=True)
    is_dismissed = models.BooleanField(default=False)
    dismissed_at = models.DateTimeField(null=True, blank=True)

    # Delivery tracking
    sent_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=3)

    # External IDs (for tracking via external services)
    external_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("ID from external service (e.g., Twilio SID, SendGrid ID)")
    )

    # Expiration
    expires_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Batch processing
    batch_id = models.UUIDField(null=True, blank=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['recipient', '-created_at']),
            models.Index(fields=['recipient', 'is_read']),
            models.Index(fields=['recipient', 'status']),
            models.Index(fields=['channel', 'status']),
            models.Index(fields=['notification_type', 'created_at']),
            models.Index(fields=['batch_id']),
        ]
        verbose_name = _('Notification')
        verbose_name_plural = _('Notifications')

    def __str__(self):
        return f"{self.notification_type}: {self.title} -> {self.recipient}"

    def mark_as_read(self):
        """Mark notification as read."""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.status = 'read'
            self.save(update_fields=['is_read', 'read_at', 'status', 'updated_at'])

    def mark_as_unread(self):
        """Mark notification as unread."""
        if self.is_read:
            self.is_read = False
            self.read_at = None
            self.status = 'delivered'
            self.save(update_fields=['is_read', 'read_at', 'status', 'updated_at'])

    def dismiss(self):
        """Dismiss the notification."""
        if not self.is_dismissed:
            self.is_dismissed = True
            self.dismissed_at = timezone.now()
            self.save(update_fields=['is_dismissed', 'dismissed_at', 'updated_at'])

    def mark_as_sent(self, external_id: str = None):
        """Mark notification as sent."""
        self.status = 'sent'
        self.sent_at = timezone.now()
        if external_id:
            self.external_id = external_id
        self.save(update_fields=['status', 'sent_at', 'external_id', 'updated_at'])

    def mark_as_delivered(self):
        """Mark notification as delivered."""
        self.status = 'delivered'
        self.delivered_at = timezone.now()
        self.save(update_fields=['status', 'delivered_at', 'updated_at'])

    def mark_as_failed(self, error_message: str):
        """Mark notification as failed."""
        self.status = 'failed'
        self.error_message = error_message
        self.retry_count += 1
        self.save(update_fields=['status', 'error_message', 'retry_count', 'updated_at'])

    def can_retry(self) -> bool:
        """Check if notification can be retried."""
        return self.status == 'failed' and self.retry_count < self.max_retries

    @property
    def is_expired(self) -> bool:
        """Check if notification has expired."""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False


class ScheduledNotification(models.Model):
    """
    Scheduled notifications for future delivery.
    """
    RECURRENCE_CHOICES = [
        ('once', _('Once')),
        ('daily', _('Daily')),
        ('weekly', _('Weekly')),
        ('monthly', _('Monthly')),
        ('yearly', _('Yearly')),
    ]

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Recipients (can be single user, group, or all users matching criteria)
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='scheduled_notifications',
        help_text=_("Specific user recipient (leave blank for broadcast)")
    )
    recipient_filter = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Filter criteria for selecting recipients (for broadcasts)")
    )

    # Template and content
    template = models.ForeignKey(
        NotificationTemplate,
        on_delete=models.CASCADE,
        related_name='scheduled_notifications'
    )
    context_data = models.JSONField(default=dict, blank=True)

    # Related object
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    # Scheduling
    scheduled_at = models.DateTimeField(db_index=True)
    recurrence = models.CharField(
        max_length=20,
        choices=RECURRENCE_CHOICES,
        default='once'
    )
    recurrence_end_date = models.DateTimeField(null=True, blank=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    next_run_at = models.DateTimeField(null=True, blank=True)

    # Status
    is_active = models.BooleanField(default=True)
    is_processed = models.BooleanField(default=False)

    # Metadata
    name = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_scheduled_notifications'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['scheduled_at']
        indexes = [
            models.Index(fields=['scheduled_at', 'is_active', 'is_processed']),
            models.Index(fields=['next_run_at', 'is_active']),
        ]
        verbose_name = _('Scheduled Notification')
        verbose_name_plural = _('Scheduled Notifications')

    def __str__(self):
        return f"{self.name or self.template.name} - {self.scheduled_at}"

    def calculate_next_run(self):
        """Calculate the next run time based on recurrence."""
        from dateutil.relativedelta import relativedelta

        if self.recurrence == 'once':
            self.next_run_at = None
            return

        base_time = self.last_run_at or self.scheduled_at

        if self.recurrence == 'daily':
            self.next_run_at = base_time + relativedelta(days=1)
        elif self.recurrence == 'weekly':
            self.next_run_at = base_time + relativedelta(weeks=1)
        elif self.recurrence == 'monthly':
            self.next_run_at = base_time + relativedelta(months=1)
        elif self.recurrence == 'yearly':
            self.next_run_at = base_time + relativedelta(years=1)

        # Check if past end date
        if self.recurrence_end_date and self.next_run_at > self.recurrence_end_date:
            self.next_run_at = None
            self.is_active = False


class NotificationDeliveryLog(models.Model):
    """
    Detailed delivery log for tracking notification attempts.
    """
    notification = models.ForeignKey(
        Notification,
        on_delete=models.CASCADE,
        related_name='delivery_logs'
    )

    attempt_number = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=20)

    # Request/Response details
    request_payload = models.JSONField(default=dict, blank=True)
    response_payload = models.JSONField(default=dict, blank=True)
    response_code = models.IntegerField(null=True, blank=True)

    # Error details
    error_type = models.CharField(max_length=100, blank=True)
    error_message = models.TextField(blank=True)
    error_traceback = models.TextField(blank=True)

    # Timing
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)

    # External service info
    external_id = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['notification', 'attempt_number']),
        ]
        verbose_name = _('Notification Delivery Log')
        verbose_name_plural = _('Notification Delivery Logs')

    def __str__(self):
        return f"Delivery log for {self.notification.uuid} - Attempt {self.attempt_number}"


# Audit logging
from auditlog.registry import auditlog

auditlog.register(NotificationChannel)
auditlog.register(NotificationTemplate)
auditlog.register(NotificationPreference)
auditlog.register(Notification)
auditlog.register(ScheduledNotification)
