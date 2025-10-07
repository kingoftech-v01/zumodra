from django.db import models

# Create your models here.
from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid

User = settings.AUTH_USER_MODEL


class AuditLogEntry(models.Model):
    """
    Generic audit log model that records CRUD operations on registered models.
    Tracks who performed the action, what action, when, and on what object.
    Designed for accountability and security compliance.
    """
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('failed_login', 'Failed Login'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='audit_log_entries')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    model_name = models.CharField(max_length=100)
    object_id = models.CharField(max_length=255)  # to support UUID and integer PKs
    object_repr = models.CharField(max_length=255)  # string representation of object
    timestamp = models.DateTimeField(auto_now_add=True)
    change_message = models.TextField(blank=True)  # Description or diff of changes

    ip_address = models.GenericIPAddressField(null=True, blank=True)  # optionally log IP address

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['actor']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['model_name']),
        ]

    def __str__(self):
        return f"{self.timestamp} - {self.actor} - {self.action} - {self.model_name}({self.object_repr})"


class SecurityEvent(models.Model):
    """
    Model to record security relevant events such as account lockouts,
    password change requests, suspicious login attempts etc.
    """
    EVENT_TYPE_CHOICES = [
        ('password_change', 'Password Change'),
        ('account_lockout', 'Account Lockout'),
        ('failed_login', 'Failed Login'),
        ('password_reset_request', 'Password Reset Request'),
        ('2fa_enabled', '2FA Enabled'),
        ('2fa_disabled', '2FA Disabled'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_events')
    event_type = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Security event '{self.event_type}' for {self.user} at {self.timestamp}"


class FailedLoginAttempt(models.Model):
    """
    Logging failed login attempts, useful for brute force protection and alerts.
    Can be used to implement lockout mechanisms when attempts exceed threshold.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='failed_logins', null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    attempted_at = models.DateTimeField(auto_now_add=True)
    username_entered = models.CharField(max_length=254, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)

    class Meta:
        ordering = ['-attempted_at']

    def __str__(self):
        return f"Failed login for {self.username_entered} from {self.ip_address} at {self.attempted_at}"


class UserSession(models.Model):
    """
    Track active user sessions for session management and security audits.
    Can be used for logout all sessions, session expiration management.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True)  # matches Django session key length
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    login_time = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-last_activity']

    def __str__(self):
        return f"Session {self.session_key} for {self.user.email}, active: {self.is_active}"


class PasswordResetRequest(models.Model):
    """
    Record password reset requests for audit and heating security.
    Track if requests are abused.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_requests')
    requested_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    used = models.BooleanField(default=False)
    token = models.CharField(max_length=128, blank=False, unique=True)  # token used for reset link

    class Meta:
        ordering = ['-requested_at']

    def __str__(self):
        status = "used" if self.used else "pending"
        return f"Password reset {status} for {self.user.email} requested at {self.requested_at}"


class AuditLogConfig(models.Model):
    """
    Optional configuration model for audit log behaviors like filters,
    ignored models or fields, masking, etc. Useful if you want to provide
    UI in admin to configure audit policies.
    """
    key = models.CharField(max_length=100, unique=True)
    value = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"AuditLogConfig - {self.key}"
