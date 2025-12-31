"""
Tenants Logging - Tenant-aware logging filters and formatters.

This module provides logging components that include tenant context:
- TenantContextFilter: Adds tenant info to log records
- TenantFormatter: Custom formatter with tenant prefixes

Usage in settings.py:
    LOGGING = {
        'filters': {
            'tenant_context': {
                '()': 'tenants.logging.TenantContextFilter',
            },
        },
        'handlers': {
            'console': {
                'filters': ['tenant_context'],
                ...
            },
        },
    }
"""

import logging
from typing import Optional

from .context import get_current_tenant, get_current_schema


class TenantContextFilter(logging.Filter):
    """
    Logging filter that adds tenant context to log records.

    Adds the following attributes to log records:
    - tenant: Tenant name or 'public'
    - tenant_id: Tenant ID or None
    - tenant_schema: Schema name
    - tenant_slug: Tenant slug or 'public'
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add tenant context to log record."""
        tenant = get_current_tenant()

        if tenant:
            record.tenant = tenant.name
            record.tenant_id = tenant.id
            record.tenant_schema = tenant.schema_name
            record.tenant_slug = tenant.slug
        else:
            record.tenant = 'public'
            record.tenant_id = None
            record.tenant_schema = get_current_schema()
            record.tenant_slug = 'public'

        return True


class TenantFormatter(logging.Formatter):
    """
    Custom formatter that includes tenant context.

    Default format:
        [{asctime}] [{levelname}] [tenant:{tenant}] {name}: {message}
    """

    default_format = '[{asctime}] [{levelname}] [tenant:{tenant}] {name}: {message}'

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None, style: str = '{'):
        if fmt is None:
            fmt = self.default_format
        super().__init__(fmt, datefmt, style)

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with tenant context."""
        # Ensure tenant attribute exists
        if not hasattr(record, 'tenant'):
            tenant = get_current_tenant()
            record.tenant = tenant.name if tenant else 'public'

        return super().format(record)


class TenantLoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that automatically includes tenant context.

    Usage:
        logger = TenantLoggerAdapter(logging.getLogger(__name__))
        logger.info("Something happened")  # Includes tenant in extra
    """

    def process(self, msg, kwargs):
        """Add tenant context to log extra."""
        tenant = get_current_tenant()

        extra = kwargs.setdefault('extra', {})
        if tenant:
            extra['tenant'] = tenant.name
            extra['tenant_id'] = tenant.id
            extra['tenant_schema'] = tenant.schema_name
        else:
            extra['tenant'] = 'public'
            extra['tenant_id'] = None
            extra['tenant_schema'] = 'public'

        return msg, kwargs


def get_tenant_logger(name: str) -> TenantLoggerAdapter:
    """
    Get a logger wrapped with tenant context adapter.

    Args:
        name: Logger name (typically __name__).

    Returns:
        TenantLoggerAdapter instance.

    Example:
        from tenants.logging import get_tenant_logger
        logger = get_tenant_logger(__name__)
        logger.info("Processing request")  # Logs with tenant context
    """
    return TenantLoggerAdapter(logging.getLogger(name), {})


class TenantAuditLogger:
    """
    Specialized logger for tenant audit events.

    Logs to a separate audit log file/handler with full tenant context.
    Suitable for compliance and security audit trails.
    """

    def __init__(self, name: str = 'tenant.audit'):
        self.logger = logging.getLogger(name)

    def log_action(
        self,
        action: str,
        resource_type: str,
        resource_id: str = '',
        user=None,
        details: dict = None,
        level: int = logging.INFO
    ):
        """
        Log an audit event.

        Args:
            action: Action performed (create, update, delete, login, etc.)
            resource_type: Type of resource affected
            resource_id: ID of affected resource
            user: User who performed action (optional)
            details: Additional details dict
            level: Log level (default INFO)
        """
        tenant = get_current_tenant()

        extra = {
            'tenant': tenant.name if tenant else 'public',
            'tenant_id': tenant.id if tenant else None,
            'action': action,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'user_id': user.id if user else None,
            'user_email': user.email if user and hasattr(user, 'email') else None,
            'details': details or {},
        }

        message = f"[AUDIT] {action} on {resource_type}"
        if resource_id:
            message += f" ({resource_id})"
        if user:
            message += f" by {user.email if hasattr(user, 'email') else user}"

        self.logger.log(level, message, extra=extra)

    def log_login(self, user, success: bool = True, ip_address: str = None):
        """Log user login attempt."""
        action = 'login_success' if success else 'login_failed'
        self.log_action(
            action=action,
            resource_type='auth',
            user=user,
            details={'ip_address': ip_address}
        )

    def log_permission_change(self, user, target_user, old_role: str, new_role: str):
        """Log permission/role change."""
        self.log_action(
            action='permission_change',
            resource_type='user',
            resource_id=str(target_user.id),
            user=user,
            details={
                'old_role': old_role,
                'new_role': new_role,
                'target_user': target_user.email if hasattr(target_user, 'email') else str(target_user)
            }
        )

    def log_data_export(self, user, export_type: str, record_count: int):
        """Log data export event."""
        self.log_action(
            action='data_export',
            resource_type=export_type,
            user=user,
            details={'record_count': record_count}
        )

    def log_settings_change(self, user, setting_name: str, old_value, new_value):
        """Log settings change."""
        self.log_action(
            action='settings_change',
            resource_type='tenant_settings',
            resource_id=setting_name,
            user=user,
            details={
                'old_value': str(old_value),
                'new_value': str(new_value)
            }
        )


# Module-level audit logger instance
audit_logger = TenantAuditLogger()
