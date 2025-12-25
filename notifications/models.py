from django.db import models
from custom_account_u.models import User
from django.utils import timezone
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType


class Notification(models.Model):
    """
    In-app notification system.
    Separate from messages - this is for system notifications like:
    - New proposal received
    - Contract status changed
    - Service review posted
    - Payment received
    etc.
    """
    NOTIFICATION_TYPES = [
        ('info', 'Information'),
        ('success', 'Success'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('proposal', 'Proposal'),
        ('contract', 'Contract'),
        ('payment', 'Payment'),
        ('review', 'Review'),
        ('message', 'Message'),
    ]

    recipient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='notifications',
        help_text="User who receives this notification"
    )

    sender = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sent_notifications',
        help_text="User who triggered this notification (optional)"
    )

    notification_type = models.CharField(
        max_length=20,
        choices=NOTIFICATION_TYPES,
        default='info',
        help_text="Type of notification"
    )

    title = models.CharField(
        max_length=255,
        help_text="Notification title"
    )

    message = models.TextField(
        help_text="Notification message/description"
    )

    # Generic relation to any model
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    # Link/action URL
    action_url = models.CharField(
        max_length=500,
        blank=True,
        help_text="URL to navigate to when notification is clicked"
    )

    # Status
    is_read = models.BooleanField(
        default=False,
        help_text="Whether notification has been read"
    )

    read_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When notification was read"
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When notification was created"
    )

    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When notification expires (optional)"
    )

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['recipient', '-created_at']),
            models.Index(fields=['recipient', 'is_read']),
        ]

    def __str__(self):
        return f"{self.notification_type.upper()}: {self.title} -> {self.recipient.email}"

    def mark_as_read(self):
        """Mark notification as read"""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save()

    def mark_as_unread(self):
        """Mark notification as unread"""
        if self.is_read:
            self.is_read = False
            self.read_at = None
            self.save()

    @property
    def is_expired(self):
        """Check if notification has expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False


class NotificationPreference(models.Model):
    """
    User preferences for notifications
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='notification_preferences'
    )

    # Email notifications
    email_on_proposal = models.BooleanField(default=True)
    email_on_contract = models.BooleanField(default=True)
    email_on_payment = models.BooleanField(default=True)
    email_on_review = models.BooleanField(default=True)
    email_on_message = models.BooleanField(default=True)

    # In-app notifications
    app_on_proposal = models.BooleanField(default=True)
    app_on_contract = models.BooleanField(default=True)
    app_on_payment = models.BooleanField(default=True)
    app_on_review = models.BooleanField(default=True)
    app_on_message = models.BooleanField(default=True)

    # Digest settings
    daily_digest = models.BooleanField(default=False)
    weekly_digest = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Notification Preference'
        verbose_name_plural = 'Notification Preferences'

    def __str__(self):
        return f"Notification preferences for {self.user.email}"


# Audit logging
from auditlog.registry import auditlog
auditlog.register(Notification)
auditlog.register(NotificationPreference)
