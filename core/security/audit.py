"""
Audit Logging System for Zumodra

Comprehensive audit logging for the multi-tenant ATS/HR SaaS platform:
- AuditLog model: Stores all audit records
- AuditLogger service: Log all state-changing actions
- Decorators: @audit_action, @audit_model_changes
- GDPR data export: Export audit logs for data subject requests

All audit logging is tenant-aware for multi-tenant isolation.
"""

import functools
import hashlib
import json
import logging
import traceback
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Union

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models, transaction
from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver
from django.http import HttpRequest
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger('security.audit')

User = get_user_model()


# =============================================================================
# AUDIT ACTION TYPES
# =============================================================================

class AuditAction(str, Enum):
    """Standard audit action types."""
    CREATE = 'create'
    READ = 'read'
    UPDATE = 'update'
    DELETE = 'delete'
    LOGIN = 'login'
    LOGOUT = 'logout'
    LOGIN_FAILED = 'login_failed'
    PASSWORD_CHANGE = 'password_change'
    PASSWORD_RESET = 'password_reset'
    PERMISSION_CHANGE = 'permission_change'
    ROLE_CHANGE = 'role_change'
    EXPORT = 'export'
    IMPORT = 'import'
    APPROVE = 'approve'
    REJECT = 'reject'
    SUBMIT = 'submit'
    ARCHIVE = 'archive'
    RESTORE = 'restore'
    BULK_ACTION = 'bulk_action'
    API_CALL = 'api_call'
    CONFIGURATION_CHANGE = 'configuration_change'
    SECURITY_EVENT = 'security_event'
    SYSTEM_EVENT = 'system_event'


class AuditSeverity(str, Enum):
    """Audit event severity levels."""
    DEBUG = 'debug'
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'


# =============================================================================
# AUDIT LOG MODEL
# =============================================================================

class AuditLog(models.Model):
    """
    Comprehensive audit log model for tracking all system changes.

    Stores:
    - Who performed the action (user, IP, user agent)
    - What action was performed
    - What resource was affected
    - Old and new values (for changes)
    - Tenant context
    - Request metadata

    Designed for:
    - Security compliance (SOC 2, ISO 27001)
    - GDPR audit requirements
    - Debugging and troubleshooting
    - Legal hold and e-discovery
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    # Timestamp
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name=_('Timestamp')
    )

    # Tenant context (multi-tenant isolation)
    tenant_id = models.UUIDField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_('Tenant ID')
    )

    # Actor information
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        verbose_name=_('User')
    )
    user_email = models.EmailField(
        blank=True,
        verbose_name=_('User Email'),
        help_text=_('Stored separately for when user is deleted')
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_('IP Address')
    )
    user_agent = models.CharField(
        max_length=500,
        blank=True,
        verbose_name=_('User Agent')
    )
    session_id = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_('Session ID')
    )

    # Action information
    action = models.CharField(
        max_length=50,
        db_index=True,
        verbose_name=_('Action'),
        help_text=_('The type of action performed')
    )
    action_display = models.CharField(
        max_length=200,
        blank=True,
        verbose_name=_('Action Display'),
        help_text=_('Human-readable action description')
    )
    severity = models.CharField(
        max_length=20,
        default=AuditSeverity.INFO.value,
        db_index=True,
        verbose_name=_('Severity')
    )

    # Resource information
    resource_type = models.CharField(
        max_length=100,
        db_index=True,
        verbose_name=_('Resource Type'),
        help_text=_('The type of resource affected')
    )
    resource_id = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
        verbose_name=_('Resource ID')
    )
    resource_repr = models.CharField(
        max_length=500,
        blank=True,
        verbose_name=_('Resource Representation'),
        help_text=_('String representation of the resource')
    )

    # Change tracking
    old_value = models.JSONField(
        null=True,
        blank=True,
        verbose_name=_('Old Value'),
        help_text=_('Previous state of the resource')
    )
    new_value = models.JSONField(
        null=True,
        blank=True,
        verbose_name=_('New Value'),
        help_text=_('New state of the resource')
    )
    changes = models.JSONField(
        null=True,
        blank=True,
        verbose_name=_('Changes'),
        help_text=_('Detailed list of changes made')
    )

    # Request metadata
    request_id = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_('Request ID')
    )
    request_method = models.CharField(
        max_length=10,
        blank=True,
        verbose_name=_('HTTP Method')
    )
    request_path = models.CharField(
        max_length=500,
        blank=True,
        verbose_name=_('Request Path')
    )
    response_status = models.IntegerField(
        null=True,
        blank=True,
        verbose_name=_('Response Status')
    )
    duration_ms = models.IntegerField(
        null=True,
        blank=True,
        verbose_name=_('Duration (ms)')
    )

    # Additional context
    extra_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Extra Data'),
        help_text=_('Additional context data')
    )
    error_message = models.TextField(
        blank=True,
        verbose_name=_('Error Message')
    )
    stack_trace = models.TextField(
        blank=True,
        verbose_name=_('Stack Trace')
    )

    # Compliance fields
    is_sensitive = models.BooleanField(
        default=False,
        verbose_name=_('Is Sensitive'),
        help_text=_('Whether this log contains sensitive data')
    )
    retention_expires = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Retention Expires'),
        help_text=_('When this log can be deleted')
    )
    legal_hold = models.BooleanField(
        default=False,
        verbose_name=_('Legal Hold'),
        help_text=_('Whether this log is under legal hold')
    )

    # Checksum for integrity verification
    checksum = models.CharField(
        max_length=64,
        blank=True,
        verbose_name=_('Checksum')
    )

    class Meta:
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant_id', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.timestamp} - {self.action} - {self.resource_type}"

    def save(self, *args, **kwargs):
        # Generate checksum before saving
        if not self.checksum:
            self.checksum = self._generate_checksum()

        # Set default retention
        if not self.retention_expires:
            retention_days = getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 365 * 7)
            self.retention_expires = timezone.now() + timedelta(days=retention_days)

        super().save(*args, **kwargs)

    def _generate_checksum(self) -> str:
        """Generate integrity checksum for the log entry."""
        data = {
            'timestamp': self.timestamp.isoformat() if self.timestamp else '',
            'tenant_id': str(self.tenant_id) if self.tenant_id else '',
            'user_id': str(self.user_id) if self.user_id else '',
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'old_value': self.old_value,
            'new_value': self.new_value,
        }
        json_str = json.dumps(data, sort_keys=True, cls=DjangoJSONEncoder)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify the log entry hasn't been tampered with."""
        return self.checksum == self._generate_checksum()

    @property
    def changes_summary(self) -> str:
        """Get a human-readable summary of changes."""
        if not self.changes:
            return ""

        summary_parts = []
        for change in self.changes[:5]:  # Limit to first 5 changes
            field = change.get('field', 'unknown')
            old = change.get('old', '')
            new = change.get('new', '')
            summary_parts.append(f"{field}: {old} -> {new}")

        if len(self.changes) > 5:
            summary_parts.append(f"... and {len(self.changes) - 5} more changes")

        return "; ".join(summary_parts)


# =============================================================================
# AUDIT LOGGER SERVICE
# =============================================================================

class AuditLogger:
    """
    Service class for creating audit log entries.

    Provides methods for logging various types of actions:
    - Model CRUD operations
    - Authentication events
    - API calls
    - Security events
    - System events

    Usage:
        AuditLogger.log(
            action=AuditAction.UPDATE,
            resource_type='Job',
            resource_id=job.id,
            old_value=old_data,
            new_value=new_data,
            user=request.user,
            request=request
        )
    """

    CACHE_PREFIX = 'audit_log:'

    # Fields to exclude from change tracking
    EXCLUDED_FIELDS = {
        'updated_at', 'modified_at', 'last_modified',
        'password', 'token', 'secret', 'api_key',
    }

    # Sensitive fields to mask
    SENSITIVE_FIELDS = {
        'password', 'token', 'secret', 'api_key', 'credit_card',
        'ssn', 'nas', 'sin', 'national_id', 'passport',
    }

    @classmethod
    def log(
        cls,
        action: Union[AuditAction, str],
        resource_type: str,
        resource_id: Any = None,
        old_value: Dict = None,
        new_value: Dict = None,
        user: Any = None,
        tenant_id: str = None,
        request: HttpRequest = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        extra_data: Dict = None,
        error_message: str = None,
        is_sensitive: bool = False
    ) -> Optional[AuditLog]:
        """
        Create an audit log entry.

        Args:
            action: The action being performed
            resource_type: Type of resource (model name, endpoint, etc.)
            resource_id: ID of the resource
            old_value: Previous state of the resource
            new_value: New state of the resource
            user: User performing the action
            tenant_id: Tenant context
            request: HTTP request object
            severity: Log severity level
            extra_data: Additional context data
            error_message: Error message if action failed
            is_sensitive: Whether log contains sensitive data

        Returns:
            AuditLog instance or None if logging fails
        """
        try:
            # Convert action to string
            if isinstance(action, AuditAction):
                action = action.value

            # Build audit entry
            entry_data = {
                'action': action,
                'resource_type': resource_type,
                'resource_id': str(resource_id) if resource_id else '',
                'severity': severity.value if isinstance(severity, AuditSeverity) else severity,
                'is_sensitive': is_sensitive,
                'extra_data': extra_data or {},
                'error_message': error_message or '',
            }

            # Add user info
            if user and hasattr(user, 'id'):
                entry_data['user'] = user
                entry_data['user_email'] = getattr(user, 'email', '')

            # Add tenant context
            if tenant_id:
                entry_data['tenant_id'] = tenant_id
            elif request:
                entry_data['tenant_id'] = cls._get_tenant_id_from_request(request)

            # Add request info
            if request:
                entry_data.update(cls._extract_request_info(request))

            # Process values and calculate changes
            if old_value or new_value:
                masked_old = cls._mask_sensitive_fields(old_value) if old_value else None
                masked_new = cls._mask_sensitive_fields(new_value) if new_value else None

                entry_data['old_value'] = masked_old
                entry_data['new_value'] = masked_new

                if old_value and new_value:
                    entry_data['changes'] = cls._calculate_changes(old_value, new_value)

            # Create resource representation
            if new_value:
                entry_data['resource_repr'] = cls._get_resource_repr(new_value)

            # Generate action display
            entry_data['action_display'] = cls._get_action_display(
                action, resource_type, resource_id
            )

            # Create audit log entry
            audit_log = AuditLog.objects.create(**entry_data)

            # Log to Python logger as well
            log_message = f"AUDIT: {action} {resource_type}"
            if resource_id:
                log_message += f" ({resource_id})"
            if user:
                log_message += f" by {getattr(user, 'email', user)}"

            logger.info(log_message, extra={'audit_id': str(audit_log.id)})

            return audit_log

        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
            # Don't raise - audit logging shouldn't break the application
            return None

    @classmethod
    def log_request(cls, request_data: Dict) -> Optional[AuditLog]:
        """
        Log a request from middleware.

        Args:
            request_data: Dictionary with request information

        Returns:
            AuditLog instance or None
        """
        return cls.log(
            action=AuditAction.API_CALL,
            resource_type='Request',
            resource_id=request_data.get('request_id'),
            user=None,  # Will be set from request_data
            extra_data=request_data,
        )

    @classmethod
    def log_model_change(
        cls,
        instance: models.Model,
        action: AuditAction,
        old_data: Dict = None,
        user: Any = None,
        request: HttpRequest = None
    ) -> Optional[AuditLog]:
        """
        Log a model change.

        Args:
            instance: The model instance
            action: The action performed
            old_data: Previous state of the instance
            user: User performing the action
            request: HTTP request

        Returns:
            AuditLog instance or None
        """
        model_name = instance.__class__.__name__
        model_id = str(instance.pk) if instance.pk else ''

        # Get new data
        new_data = cls._model_to_dict(instance) if instance.pk else None

        # Get tenant ID from instance if available
        tenant_id = None
        if hasattr(instance, 'tenant_id'):
            tenant_id = str(instance.tenant_id)

        return cls.log(
            action=action,
            resource_type=model_name,
            resource_id=model_id,
            old_value=old_data,
            new_value=new_data,
            user=user,
            tenant_id=tenant_id,
            request=request,
        )

    @classmethod
    def log_authentication(
        cls,
        action: AuditAction,
        user: Any = None,
        request: HttpRequest = None,
        success: bool = True,
        extra_data: Dict = None
    ) -> Optional[AuditLog]:
        """
        Log an authentication event.

        Args:
            action: Authentication action (LOGIN, LOGOUT, etc.)
            user: User involved
            request: HTTP request
            success: Whether the action succeeded
            extra_data: Additional context

        Returns:
            AuditLog instance or None
        """
        severity = AuditSeverity.INFO if success else AuditSeverity.WARNING

        return cls.log(
            action=action,
            resource_type='Authentication',
            user=user,
            request=request,
            severity=severity,
            extra_data={
                'success': success,
                **(extra_data or {})
            },
            is_sensitive=True,
        )

    @classmethod
    def log_security_event(
        cls,
        event_type: str,
        description: str,
        user: Any = None,
        request: HttpRequest = None,
        severity: AuditSeverity = AuditSeverity.WARNING,
        extra_data: Dict = None
    ) -> Optional[AuditLog]:
        """
        Log a security event.

        Args:
            event_type: Type of security event
            description: Event description
            user: User involved
            request: HTTP request
            severity: Event severity
            extra_data: Additional context

        Returns:
            AuditLog instance or None
        """
        return cls.log(
            action=AuditAction.SECURITY_EVENT,
            resource_type='SecurityEvent',
            resource_id=event_type,
            user=user,
            request=request,
            severity=severity,
            extra_data={
                'description': description,
                **(extra_data or {})
            },
            is_sensitive=True,
        )

    @classmethod
    def _extract_request_info(cls, request: HttpRequest) -> Dict:
        """Extract relevant info from HTTP request."""
        info = {
            'ip_address': cls._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
            'request_method': request.method,
            'request_path': request.path,
            'request_id': getattr(request, 'request_id', ''),
        }

        # Add session ID if available
        if hasattr(request, 'session') and request.session.session_key:
            info['session_id'] = request.session.session_key

        return info

    @classmethod
    def _get_client_ip(cls, request: HttpRequest) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    @classmethod
    def _get_tenant_id_from_request(cls, request: HttpRequest) -> Optional[str]:
        """Extract tenant ID from request."""
        try:
            from django.db import connection
            tenant = getattr(connection, 'tenant', None)
            if tenant:
                return str(tenant.id)
        except Exception:
            pass
        return getattr(request, 'tenant_id', None)

    @classmethod
    def _mask_sensitive_fields(cls, data: Dict) -> Dict:
        """Mask sensitive fields in data."""
        if not data:
            return data

        masked = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in cls.SENSITIVE_FIELDS):
                masked[key] = '***MASKED***'
            elif isinstance(value, dict):
                masked[key] = cls._mask_sensitive_fields(value)
            else:
                masked[key] = value
        return masked

    @classmethod
    def _calculate_changes(cls, old_value: Dict, new_value: Dict) -> List[Dict]:
        """Calculate changes between old and new values."""
        changes = []

        all_keys = set(old_value.keys()) | set(new_value.keys())

        for key in all_keys:
            # Skip excluded fields
            if key in cls.EXCLUDED_FIELDS:
                continue

            old_val = old_value.get(key)
            new_val = new_value.get(key)

            if old_val != new_val:
                # Mask sensitive fields in change log
                if any(sensitive in key.lower() for sensitive in cls.SENSITIVE_FIELDS):
                    old_val = '***MASKED***' if old_val else None
                    new_val = '***MASKED***' if new_val else None

                changes.append({
                    'field': key,
                    'old': old_val,
                    'new': new_val,
                })

        return changes

    @classmethod
    def _model_to_dict(cls, instance: models.Model) -> Dict:
        """Convert model instance to dictionary."""
        data = {}
        for field in instance._meta.fields:
            try:
                value = getattr(instance, field.name)
                # Handle special types
                if hasattr(value, 'pk'):
                    value = str(value.pk)
                elif hasattr(value, 'isoformat'):
                    value = value.isoformat()
                elif isinstance(value, uuid.UUID):
                    value = str(value)
                data[field.name] = value
            except Exception:
                continue
        return data

    @classmethod
    def _get_resource_repr(cls, data: Dict, max_length: int = 500) -> str:
        """Get string representation of resource."""
        repr_fields = ['name', 'title', 'email', 'id', 'pk']
        parts = []

        for field in repr_fields:
            if field in data and data[field]:
                parts.append(f"{field}={data[field]}")
                if len(', '.join(parts)) > max_length:
                    break

        return ', '.join(parts)[:max_length]

    @classmethod
    def _get_action_display(
        cls, action: str, resource_type: str, resource_id: Any
    ) -> str:
        """Generate human-readable action display."""
        action_displays = {
            'create': f"Created {resource_type}",
            'read': f"Viewed {resource_type}",
            'update': f"Updated {resource_type}",
            'delete': f"Deleted {resource_type}",
            'login': "User logged in",
            'logout': "User logged out",
            'login_failed': "Failed login attempt",
            'password_change': "Changed password",
            'password_reset': "Reset password",
        }

        display = action_displays.get(action, f"{action.title()} {resource_type}")
        if resource_id:
            display += f" ({resource_id})"

        return display


# =============================================================================
# DECORATORS
# =============================================================================

def audit_action(
    action: Union[AuditAction, str],
    resource_type: str = None,
    get_resource_id: Callable = None,
    severity: AuditSeverity = AuditSeverity.INFO
):
    """
    Decorator to audit a function/view call.

    Args:
        action: The action being performed
        resource_type: Type of resource (defaults to function name)
        get_resource_id: Function to extract resource ID from args/kwargs
        severity: Log severity level

    Usage:
        @audit_action(AuditAction.CREATE, 'Job')
        def create_job(request, data):
            ...

        @audit_action('custom_action', get_resource_id=lambda args, kwargs: kwargs.get('pk'))
        def my_view(request, pk):
            ...
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract request and user
            request = None
            user = None

            for arg in args:
                if isinstance(arg, HttpRequest):
                    request = arg
                    user = getattr(request, 'user', None)
                    if user and not user.is_authenticated:
                        user = None
                    break

            # Get resource ID
            resource_id = None
            if get_resource_id:
                try:
                    resource_id = get_resource_id(args, kwargs)
                except Exception:
                    pass

            # Execute the function
            error = None
            result = None
            try:
                result = func(*args, **kwargs)
            except Exception as e:
                error = str(e)
                raise
            finally:
                # Log the action
                AuditLogger.log(
                    action=action,
                    resource_type=resource_type or func.__name__,
                    resource_id=resource_id,
                    user=user,
                    request=request,
                    severity=AuditSeverity.ERROR if error else severity,
                    error_message=error,
                    extra_data={
                        'function': func.__name__,
                        'module': func.__module__,
                    }
                )

            return result
        return wrapper
    return decorator


def audit_model_changes(
    model_class: Type[models.Model] = None,
    exclude_fields: List[str] = None,
    track_read: bool = False
):
    """
    Decorator to audit all changes to a model.

    Can be used as a class decorator on models or on signals.

    Args:
        model_class: The model class to audit
        exclude_fields: Fields to exclude from change tracking
        track_read: Whether to track read operations

    Usage:
        @audit_model_changes
        class Job(models.Model):
            ...

        # Or manually connect signals:
        audit_model_changes(Job)
    """
    def setup_signals(cls):
        """Set up signals for the model class."""
        excluded = set(exclude_fields or [])
        excluded.update(AuditLogger.EXCLUDED_FIELDS)

        # Store original values before save
        @receiver(pre_save, sender=cls)
        def capture_old_values(sender, instance, **kwargs):
            if instance.pk:
                try:
                    old_instance = sender.objects.get(pk=instance.pk)
                    instance._audit_old_values = AuditLogger._model_to_dict(old_instance)
                except sender.DoesNotExist:
                    instance._audit_old_values = None
            else:
                instance._audit_old_values = None

        # Log after save
        @receiver(post_save, sender=cls)
        def log_save(sender, instance, created, **kwargs):
            action = AuditAction.CREATE if created else AuditAction.UPDATE
            old_data = getattr(instance, '_audit_old_values', None)

            AuditLogger.log_model_change(
                instance=instance,
                action=action,
                old_data=old_data,
            )

        # Log after delete
        @receiver(post_delete, sender=cls)
        def log_delete(sender, instance, **kwargs):
            AuditLogger.log_model_change(
                instance=instance,
                action=AuditAction.DELETE,
                old_data=AuditLogger._model_to_dict(instance),
            )

        return cls

    if model_class is not None:
        # Called with model class directly
        return setup_signals(model_class)
    else:
        # Called as decorator
        return setup_signals


# =============================================================================
# GDPR DATA EXPORT
# =============================================================================

class GDPRAuditExporter:
    """
    Export audit logs for GDPR data subject access requests.

    Provides:
    - Export user's audit logs
    - Anonymize audit logs
    - Delete audit logs (right to erasure)
    """

    @classmethod
    def export_user_audit_logs(
        cls,
        user_id: Any,
        start_date: datetime = None,
        end_date: datetime = None,
        format: str = 'json'
    ) -> Union[Dict, str]:
        """
        Export all audit logs for a user.

        Args:
            user_id: User ID to export logs for
            start_date: Start of date range
            end_date: End of date range
            format: Export format ('json' or 'csv')

        Returns:
            Exported data in requested format
        """
        queryset = AuditLog.objects.filter(user_id=user_id)

        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)

        # Exclude logs under legal hold
        queryset = queryset.filter(legal_hold=False)

        logs = list(queryset.values(
            'id', 'timestamp', 'action', 'action_display',
            'resource_type', 'resource_id', 'resource_repr',
            'ip_address', 'user_agent', 'request_path',
            'changes', 'extra_data'
        ))

        if format == 'csv':
            return cls._to_csv(logs)

        return {
            'user_id': str(user_id),
            'export_date': timezone.now().isoformat(),
            'total_records': len(logs),
            'logs': logs
        }

    @classmethod
    def _to_csv(cls, logs: List[Dict]) -> str:
        """Convert logs to CSV format."""
        import csv
        import io

        output = io.StringIO()
        if logs:
            writer = csv.DictWriter(output, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)

        return output.getvalue()

    @classmethod
    def anonymize_user_logs(cls, user_id: Any) -> int:
        """
        Anonymize audit logs for a user (soft anonymization).

        Args:
            user_id: User ID to anonymize

        Returns:
            Number of logs anonymized
        """
        count = AuditLog.objects.filter(
            user_id=user_id,
            legal_hold=False
        ).update(
            user=None,
            user_email='anonymized@example.com',
            ip_address=None,
            user_agent='',
            session_id='',
            extra_data={}
        )

        logger.info(f"Anonymized {count} audit logs for user {user_id}")
        return count

    @classmethod
    def delete_expired_logs(cls, tenant_id: str = None) -> int:
        """
        Delete audit logs past retention period.

        Args:
            tenant_id: Optional tenant ID to scope deletion

        Returns:
            Number of logs deleted
        """
        queryset = AuditLog.objects.filter(
            retention_expires__lt=timezone.now(),
            legal_hold=False
        )

        if tenant_id:
            queryset = queryset.filter(tenant_id=tenant_id)

        count = queryset.count()
        queryset.delete()

        logger.info(f"Deleted {count} expired audit logs")
        return count

    @classmethod
    def place_legal_hold(
        cls,
        user_id: Any = None,
        resource_type: str = None,
        resource_id: str = None,
        start_date: datetime = None,
        end_date: datetime = None
    ) -> int:
        """
        Place audit logs under legal hold.

        Args:
            user_id: User ID to hold logs for
            resource_type: Resource type to hold logs for
            resource_id: Resource ID to hold logs for
            start_date: Start of date range
            end_date: End of date range

        Returns:
            Number of logs placed on hold
        """
        queryset = AuditLog.objects.all()

        if user_id:
            queryset = queryset.filter(user_id=user_id)
        if resource_type:
            queryset = queryset.filter(resource_type=resource_type)
        if resource_id:
            queryset = queryset.filter(resource_id=resource_id)
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)

        count = queryset.update(legal_hold=True)

        logger.info(f"Placed {count} audit logs under legal hold")
        return count
