# Audit Logging Enhancement Documentation

**Version:** 2.0 (Enhanced)
**Status:** Production Ready
**Location:** `core/security/audit.py`

## Overview

The Enhanced Audit Logging system provides comprehensive tracking of all security-relevant events, user actions, data access, and configuration changes across the Zumodra platform. This system is critical for compliance (GDPR, SOC 2), security incident response, and investor demonstrations.

### What's New in Version 2.0

**Extended from existing infrastructure** (v1.0 had 1088 lines of production-ready code):

- ✅ **New Audit Actions** - 12 additional action types for authentication, sensitive data, and configuration
- ✅ **Data Access Decorator** - `@audit_data_access` for automatic sensitive data logging
- ✅ **Model Change Tracking** - `@audit_model_changes` decorator for automatic model auditing
- ✅ **Enhanced Reporting** - Advanced filtering and export capabilities
- ✅ **Integration Tests** - Comprehensive test coverage for all features
- ✅ **Authentication Tracking** - Login, logout, MFA, social auth events
- ✅ **Configuration Tracking** - Tenant settings, integrations, feature flags

## Architecture

### Core Components

#### AuditLog Model

Located in: `security/models.py`

Stores comprehensive audit information:

```python
class AuditLog(models.Model):
    action = models.CharField(...)  # What happened
    user = models.ForeignKey(...)   # Who did it
    tenant = models.ForeignKey(...) # Which tenant
    resource_type = models.CharField(...)  # What was affected
    resource_id = models.CharField(...)    # Specific resource
    timestamp = models.DateTimeField(...)  # When it happened
    ip_address = models.GenericIPAddressField(...)  # From where
    user_agent = models.TextField(...)     # Browser/client info
    is_sensitive = models.BooleanField(...) # Sensitive data flag
    severity = models.CharField(...)        # DEBUG/INFO/WARNING/ERROR/CRITICAL
    old_value = models.JSONField(...)      # Before state
    new_value = models.JSONField(...)      # After state
    changes = models.JSONField(...)        # Detailed diff
    extra_data = models.JSONField(...)     # Additional context
    integrity_hash = models.CharField(...) # Tamper detection
```

#### AuditLogger Service

Located in: `core/security/audit.py`

Primary interface for logging:

```python
from core.security.audit import AuditLogger, AuditAction

# Simple logging
AuditLogger.log(
    action=AuditAction.CREATE,
    user=request.user,
    resource_type='document',
    resource_id='123',
    request=request
)

# With before/after values
AuditLogger.log(
    action=AuditAction.UPDATE,
    user=request.user,
    resource_type='user_profile',
    resource_id=str(profile.id),
    old_value={'role': 'member'},
    new_value={'role': 'admin'},
    request=request
)

# Authentication events
AuditLogger.log_authentication(
    user=request.user,
    action='LOGIN',
    success=True,
    request=request
)
```

## New Audit Actions (v2.0)

### Authentication Events

```python
# MFA Events
AuditAction.MFA_ENABLED       # User enabled 2FA/MFA
AuditAction.MFA_DISABLED      # User disabled 2FA/MFA

# Social Auth
AuditAction.SOCIAL_LOGIN      # Login via OAuth (Google, GitHub, etc.)

# Impersonation (admin-as-user)
AuditAction.IMPERSONATION_START  # Admin started impersonating user
AuditAction.IMPERSONATION_END    # Admin stopped impersonating
```

### Sensitive Data Access

```python
# Document Access
AuditAction.KYC_VIEWED                # KYC verification document viewed
AuditAction.FINANCIAL_DATA_VIEWED     # Financial information accessed
AuditAction.SENSITIVE_DATA_EXPORT     # Sensitive data exported/downloaded
```

### Configuration Changes

```python
# Settings
AuditAction.TENANT_SETTING_CHANGED    # Tenant configuration modified

# Integrations
AuditAction.INTEGRATION_ENABLED       # Integration enabled (Stripe, etc.)
AuditAction.INTEGRATION_DISABLED      # Integration disabled

# Feature Flags
AuditAction.FEATURE_FLAG_CHANGED      # Feature flag toggled
```

## Usage

### Basic Logging

#### In Views

```python
from django.views import View
from core.security.audit import AuditLogger, AuditAction

class DocumentDetailView(View):
    def get(self, request, document_id):
        document = Document.objects.get(id=document_id)

        # Log document access
        AuditLogger.log(
            action=AuditAction.READ,
            user=request.user,
            resource_type='document',
            resource_id=str(document.id),
            request=request,
            extra_data={
                'document_name': document.name,
                'document_type': document.type,
            }
        )

        return render(request, 'document_detail.html', {'document': document})
```

#### In API ViewSets

```python
from rest_framework import viewsets
from core.security.audit import AuditLogger, AuditAction

class UserViewSet(viewsets.ModelViewSet):
    def update(self, request, *args, **kwargs):
        instance = self.get_object()

        # Capture old state
        old_role = instance.role

        # Perform update
        response = super().update(request, *args, **kwargs)

        # Log the change
        instance.refresh_from_db()
        if old_role != instance.role:
            AuditLogger.log(
                action=AuditAction.UPDATE,
                user=request.user,
                resource_type='user',
                resource_id=str(instance.id),
                old_value={'role': old_role},
                new_value={'role': instance.role},
                request=request,
                extra_data={
                    'user_email': instance.email,
                    'changed_fields': ['role']
                }
            )

        return response
```

### Using Decorators

#### @audit_data_access Decorator

Automatically logs sensitive data access:

```python
from core.security.audit import audit_data_access, AuditAction

# For function-based views
@audit_data_access(
    resource_type='kyc_document',
    get_resource_id=lambda request, pk: pk,
    is_sensitive=True
)
def view_kyc_document(request, pk):
    document = KYCDocument.objects.get(pk=pk)
    return render(request, 'kyc_detail.html', {'document': document})

# For class-based views
class KYCDocumentDetailView(View):
    @method_decorator(audit_data_access(
        resource_type='kyc_document',
        get_resource_id=lambda self, request, pk: pk
    ))
    def get(self, request, pk):
        document = KYCDocument.objects.get(pk=pk)
        return render(request, 'kyc_detail.html', {'document': document})
```

**Parameters:**
- `resource_type` (str): Type of resource being accessed
- `get_resource_id` (callable): Function to extract resource ID from args
- `action` (AuditAction): Default is `AuditAction.READ`
- `is_sensitive` (bool): Mark as sensitive data (default: True)

#### @audit_model_changes Decorator

Automatically logs all model changes (create, update, delete):

```python
from core.security.audit import audit_model_changes

@audit_model_changes
class UserProfile(models.Model):
    user = models.OneToOneField(User)
    bio = models.TextField()
    avatar = models.ImageField()
    # ... other fields ...

    class Meta:
        # ... meta options ...
```

This decorator:
- Connects to `pre_save`, `post_save`, and `post_delete` signals
- Tracks all field changes
- Logs CREATE, UPDATE, and DELETE actions
- Captures before/after values
- Calculates field-level diffs

**Field Changes Tracked:**
```python
# Example audit log entry
{
    "action": "UPDATE",
    "resource_type": "user_profile",
    "resource_id": "123",
    "old_value": {
        "bio": "Old bio text",
        "avatar": "old_avatar.jpg"
    },
    "new_value": {
        "bio": "New bio text",
        "avatar": "new_avatar.jpg"
    },
    "changes": [
        {"field": "bio", "old": "Old bio text", "new": "New bio text"},
        {"field": "avatar", "old": "old_avatar.jpg", "new": "new_avatar.jpg"}
    ]
}
```

### Authentication Event Logging

#### In Middleware

```python
# core_identity/middleware.py

from core.security.audit import AuditLogger, AuditAction

class AuthSecurityMiddleware:
    def process_request(self, request):
        # Track login events
        if request.path == '/accounts/login/' and request.method == 'POST':
            if hasattr(request, 'user') and request.user.is_authenticated:
                # Successful login
                AuditLogger.log_authentication(
                    user=request.user,
                    action='LOGIN',
                    success=True,
                    request=request
                )
            else:
                # Failed login
                AuditLogger.log_authentication(
                    user=None,
                    action='LOGIN_FAILED',
                    success=False,
                    request=request,
                    details={'username_attempted': request.POST.get('username')}
                )
```

#### MFA Events

```python
# When user enables MFA
from core.security.audit import AuditLogger, AuditAction

def enable_mfa(request):
    user = request.user

    # ... MFA setup logic ...

    # Log MFA enabled
    AuditLogger.log(
        action=AuditAction.MFA_ENABLED,
        user=user,
        resource_type='user_security',
        resource_id=str(user.id),
        request=request,
        extra_data={
            'mfa_method': 'TOTP',  # or 'SMS', 'Email', etc.
            'user_email': user.email
        }
    )
```

#### Social Authentication

```python
# core_identity/adapter.py

from core.security.audit import AuditLogger, AuditAction
from allauth.socialaccount.signals import social_account_added

@receiver(social_account_added)
def log_social_signup(request, sociallogin, **kwargs):
    user = sociallogin.user
    provider = sociallogin.account.provider

    AuditLogger.log(
        action=AuditAction.SOCIAL_LOGIN,
        user=user,
        resource_type='social_auth',
        resource_id=str(user.id),
        request=request,
        extra_data={
            'provider': provider,
            'provider_uid': sociallogin.account.uid,
            'user_email': user.email,
            'is_new_user': not user.pk
        }
    )
```

### Configuration Change Tracking

#### Tenant Settings

```python
# tenants/models.py

from core.security.audit import AuditLogger, AuditAction

class TenantSettings(models.Model):
    # ... fields ...

    def save(self, *args, **kwargs):
        is_new = self.pk is None

        if not is_new:
            # Get old values
            old_instance = TenantSettings.objects.get(pk=self.pk)
            changes = []

            for field in self._meta.fields:
                field_name = field.name
                if field_name in ['id', 'created_at', 'updated_at']:
                    continue

                old_value = getattr(old_instance, field_name)
                new_value = getattr(self, field_name)

                if old_value != new_value:
                    changes.append({
                        'field': field_name,
                        'old': str(old_value),
                        'new': str(new_value)
                    })

            if changes:
                AuditLogger.log(
                    action=AuditAction.TENANT_SETTING_CHANGED,
                    user=None,  # Captured from middleware
                    tenant_id=str(self.tenant.id),
                    resource_type='tenant_settings',
                    resource_id=str(self.pk),
                    changes=changes,
                    extra_data={
                        'tenant_name': self.tenant.name,
                        'total_changes': len(changes)
                    }
                )

        super().save(*args, **kwargs)
```

#### Integration Events

```python
# When enabling Stripe integration
from core.security.audit import AuditLogger, AuditAction

def enable_stripe_integration(tenant):
    # ... enable Stripe ...

    AuditLogger.log(
        action=AuditAction.INTEGRATION_ENABLED,
        user=request.user,
        tenant_id=str(tenant.id),
        resource_type='integration',
        resource_id='stripe',
        extra_data={
            'integration_name': 'Stripe',
            'tenant_name': tenant.name
        }
    )
```

## Reporting & Analysis

### Generate Audit Reports

#### Management Command

```bash
# Basic report (last 30 days)
python manage.py generate_audit_report

# Custom date range
python manage.py generate_audit_report --days 90

# Filter by action
python manage.py generate_audit_report --action LOGIN --days 7

# Filter by user
python manage.py generate_audit_report --user admin@example.com

# Sensitive data only
python manage.py generate_audit_report --sensitive-only

# JSON format
python manage.py generate_audit_report --format json --output report.json

# Multiple filters
python manage.py generate_audit_report \
    --start-date 2026-01-01 \
    --end-date 2026-01-31 \
    --resource-type user \
    --severity warning \
    --output january_user_warnings.csv
```

#### Programmatic Queries

```python
from security.models import AuditLog
from datetime import datetime, timedelta
from django.utils import timezone

# All logins in last 7 days
last_week = timezone.now() - timedelta(days=7)
logins = AuditLog.objects.filter(
    action='LOGIN',
    timestamp__gte=last_week
).order_by('-timestamp')

# Failed login attempts
failed_logins = AuditLog.objects.filter(
    action='LOGIN_FAILED'
).order_by('-timestamp')

# Sensitive data access by user
sensitive_access = AuditLog.objects.filter(
    user__email='admin@example.com',
    is_sensitive=True
).order_by('-timestamp')

# Configuration changes
config_changes = AuditLog.objects.filter(
    action__in=[
        'TENANT_SETTING_CHANGED',
        'INTEGRATION_ENABLED',
        'FEATURE_FLAG_CHANGED'
    ]
).order_by('-timestamp')

# Group by action type
from django.db.models import Count

action_counts = AuditLog.objects.values('action').annotate(
    count=Count('id')
).order_by('-count')

print("Event Distribution:")
for item in action_counts:
    print(f"  {item['action']}: {item['count']}")
```

### Common Queries for Investors/Stakeholders

#### Security Metrics

```python
from security.models import AuditLog, FailedLoginAttempt
from django.db.models import Count, Q
from datetime import timedelta
from django.utils import timezone

# Last 30 days
thirty_days_ago = timezone.now() - timedelta(days=30)

# Total audit events
total_events = AuditLog.objects.filter(timestamp__gte=thirty_days_ago).count()

# Authentication metrics
auth_events = AuditLog.objects.filter(
    timestamp__gte=thirty_days_ago,
    action__in=['LOGIN', 'LOGIN_FAILED', 'LOGOUT', 'MFA_ENABLED']
)

successful_logins = auth_events.filter(action='LOGIN').count()
failed_logins = auth_events.filter(action='LOGIN_FAILED').count()
mfa_enabled = auth_events.filter(action='MFA_ENABLED').count()

# Failure rate
if successful_logins + failed_logins > 0:
    failure_rate = (failed_logins / (successful_logins + failed_logins)) * 100
else:
    failure_rate = 0

# Sensitive data access
sensitive_access = AuditLog.objects.filter(
    timestamp__gte=thirty_days_ago,
    is_sensitive=True
).count()

# User management events
user_mgmt = AuditLog.objects.filter(
    timestamp__gte=thirty_days_ago,
    resource_type='user',
    action__in=['CREATE', 'UPDATE', 'DELETE']
).values('action').annotate(count=Count('id'))

# Print report
print("=== SECURITY METRICS (Last 30 Days) ===")
print(f"Total Audit Events: {total_events:,}")
print(f"\nAuthentication:")
print(f"  Successful Logins: {successful_logins:,}")
print(f"  Failed Logins: {failed_logins:,}")
print(f"  Failure Rate: {failure_rate:.1f}%")
print(f"  MFA Enabled: {mfa_enabled}")
print(f"\nSensitive Data Access: {sensitive_access:,}")
print(f"\nUser Management:")
for event in user_mgmt:
    print(f"  {event['action']}: {event['count']}")
```

#### Compliance Report

```python
import csv
from security.models import AuditLog
from datetime import datetime, timedelta
from django.utils import timezone

# Generate compliance report
def generate_compliance_report(days=365):
    """Generate annual compliance report for audit."""

    start_date = timezone.now() - timedelta(days=days)
    logs = AuditLog.objects.filter(timestamp__gte=start_date).order_by('timestamp')

    filename = f'compliance_report_{datetime.now().strftime("%Y%m%d")}.csv'

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Header
        writer.writerow([
            'Timestamp',
            'Action',
            'User',
            'User Email',
            'Resource Type',
            'Resource ID',
            'IP Address',
            'Severity',
            'Sensitive',
            'Changes',
            'Extra Data'
        ])

        # Data rows
        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.action,
                log.user.username if log.user else 'System',
                log.user.email if log.user else '',
                log.resource_type or '',
                log.resource_id or '',
                log.ip_address or '',
                log.severity,
                'Yes' if log.is_sensitive else 'No',
                str(log.changes) if log.changes else '',
                str(log.extra_data) if log.extra_data else ''
            ])

    print(f"Compliance report generated: {filename}")
    print(f"Total events: {logs.count():,}")

    return filename

# Usage
generate_compliance_report(days=365)  # Annual report
```

## Testing

### Running Tests

```bash
# Run all audit logging tests
python manage.py test core.tests.test_audit_logging_integration

# Run specific test class
python manage.py test core.tests.test_audit_logging_integration.EnhancedAuditLoggingTests

# Run specific test method
python manage.py test core.tests.test_audit_logging_integration.EnhancedAuditLoggingTests.test_login_creates_audit_log
```

### Test Coverage

The test suite covers:
- ✅ User creation logging
- ✅ Login success/failure logging
- ✅ Model change tracking via decorator
- ✅ Sensitive data access logging
- ✅ Configuration change logging
- ✅ Security event logging
- ✅ Sensitive field masking
- ✅ Audit log integrity verification
- ✅ `@audit_data_access` decorator
- ✅ Changes calculation and diff
- ✅ Audit log retention policies
- ✅ Report filtering (by action, date, user, sensitivity)

## Admin Interface

### Viewing Audit Logs

Django Admin:
1. Navigate to `/admin/security/auditlogentry/`
2. Use filters:
   - Action type
   - Date range
   - User
   - Tenant
   - Is Sensitive
   - Severity
3. Search by user email, resource type, or resource ID
4. Click on entry to see full details including JSON fields

### Bulk Operations

**Export Selected:**
1. Select audit log entries
2. Choose action: "Export selected logs"
3. Download CSV file

**Mark as Reviewed:**
1. Select entries
2. Choose action: "Mark as reviewed"
3. Updates metadata

## Best Practices

### When to Log

**DO Log:**
- ✅ Authentication events (login, logout, MFA changes)
- ✅ User management actions (create, update, delete, role changes)
- ✅ Sensitive data access (PII, financial data, documents)
- ✅ Configuration changes (settings, integrations, feature flags)
- ✅ Security events (failed attempts, suspicious activity)
- ✅ Data exports (especially sensitive data)
- ✅ Administrative actions (impersonation, bulk operations)

**DON'T Log:**
- ❌ Regular page views (non-sensitive data)
- ❌ Static file requests
- ❌ Health check endpoints
- ❌ High-frequency polling endpoints
- ❌ User passwords or tokens (sensitive field masking handles this)

### Performance Tips

1. **Use Async Logging:**
```python
from celery import shared_task
from core.security.audit import AuditLogger

@shared_task
def log_audit_event(action, user_id, resource_type, resource_id, **kwargs):
    """Async audit logging task."""
    from django.contrib.auth import get_user_model
    User = get_user_model()

    user = User.objects.get(id=user_id) if user_id else None

    AuditLogger.log(
        action=action,
        user=user,
        resource_type=resource_type,
        resource_id=resource_id,
        **kwargs
    )

# Usage
log_audit_event.delay(
    action='CREATE',
    user_id=request.user.id,
    resource_type='document',
    resource_id=str(document.id)
)
```

2. **Batch Logs for Bulk Operations:**
```python
# Instead of logging each individually
for user in users:
    AuditLogger.log(...)  # N queries

# Batch create
AuditLog.objects.bulk_create([
    AuditLog(
        action='UPDATE',
        user=request.user,
        resource_type='user',
        resource_id=str(user.id),
        # ... other fields ...
    )
    for user in users
])
```

3. **Archive Old Logs:**
```python
# Archive logs older than 7 years
from security.models import AuditLog
from datetime import timedelta
from django.utils import timezone

seven_years_ago = timezone.now() - timedelta(days=365*7)

# Export to cold storage before deleting
old_logs = AuditLog.objects.filter(timestamp__lt=seven_years_ago)
# ... export logic ...

# Then delete
old_logs.delete()
```

### Security Tips

1. **Protect Audit Logs:**
- Restrict admin access to audit logs
- Use database-level permissions
- Consider write-only tables (append-only)

2. **Sensitive Field Masking:**
```python
# Automatic masking of sensitive fields
AUDIT_SENSITIVE_FIELDS = [
    'password',
    'password_hash',
    'secret',
    'token',
    'api_key',
    'credit_card',
    'ssn',
]
```

3. **Integrity Verification:**
```python
# Audit logs include integrity hashes
log = AuditLog.objects.get(id=123)
is_valid = log.verify_integrity()

if not is_valid:
    # Log has been tampered with!
    alert_security_team()
```

## Troubleshooting

### Issue: Audit logs not being created

**Cause:** Middleware not installed or decorator not applied

**Solution:**
1. Check `MIDDLEWARE` in settings.py includes `AuditLogMiddleware`
2. Verify decorator is applied to model/view
3. Check log level settings
4. Test manually:
```python
from core.security.audit import AuditLogger, AuditAction
AuditLogger.log(
    action=AuditAction.READ,
    resource_type='test',
    resource_id='123'
)
# Check database
from security.models import AuditLog
print(AuditLog.objects.latest('timestamp'))
```

### Issue: Missing user in audit logs

**Cause:** Request not available or user not authenticated

**Solution:**
- Use `user=None` for system actions
- Pass `request` parameter to capture user from middleware
- For Celery tasks, pass `user_id` and look up user

### Issue: Performance degradation

**Cause:** Too many audit log writes

**Solution:**
- Use async logging (Celery)
- Batch bulk operations
- Archive old logs
- Add database indexes:
```python
class AuditLog(models.Model):
    # ... fields ...

    class Meta:
        indexes = [
            models.Index(fields=['timestamp', 'action']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
        ]
```

### Issue: Circular import errors

**Cause:** Importing AuditLogger in models.py

**Solution:**
- Import inside methods, not at module level:
```python
def save(self, *args, **kwargs):
    from core.security.audit import AuditLogger  # Import here
    # ... logging logic ...
```

## FAQ

**Q: How long should I retain audit logs?**

A: Depends on compliance requirements:
- GDPR: 6 months to 2 years
- SOC 2: 1 year minimum
- HIPAA: 6 years
- Financial: 7 years

**Q: Can I delete audit logs?**

A: Only if outside retention period and no legal hold. Use management command:
```bash
python manage.py cleanup_audit_logs --days 2555  # 7 years
```

**Q: How do I export logs for compliance audit?**

A: Use `generate_audit_report` command:
```bash
python manage.py generate_audit_report --start-date 2025-01-01 --end-date 2025-12-31
```

**Q: What's the performance impact?**

A: Minimal with proper optimization:
- Async logging: ~0ms impact
- Sync logging: ~5-10ms per log entry
- Use caching and batch operations

**Q: Can I customize what gets logged?**

A: Yes, configure in settings.py:
```python
AUDIT_LOG_ACTIONS = ['LOGIN', 'UPDATE', 'DELETE']  # Only log these
AUDIT_LOG_IGNORE_PATHS = ['/health/', '/metrics/']  # Ignore these paths
```

## Compliance Mapping

### GDPR Requirements

| Requirement | Implementation |
|------------|----------------|
| Right to Access | `generate_audit_report --user email@example.com` |
| Right to Erasure | User anonymization in audit logs |
| Data Breach Notification | Monitor `severity=CRITICAL` logs |
| Purpose Limitation | `resource_type` and `action` tracking |
| Accountability | Full audit trail with user attribution |

### SOC 2 Type II Controls

| Control | Implementation |
|---------|----------------|
| CC6.1 - Logical Access | Authentication event logging |
| CC6.2 - Authorization | Role change logging |
| CC6.3 - System Access Removal | User deletion logging |
| CC7.2 - System Monitoring | Real-time audit logging |
| CC7.3 - Change Management | Configuration change tracking |

## Support

For issues or questions:
- Review this documentation
- Check test files for examples
- Review Django logs
- Contact security team for access issues

## Changelog

### Version 2.0 (2026-01-24)
- Added 12 new audit action types
- Created `@audit_data_access` decorator
- Created `@audit_model_changes` decorator
- Enhanced reporting with advanced filters
- Added comprehensive integration tests
- Improved performance with batch operations
- Added compliance report generation

### Version 1.0 (Previous)
- Initial audit logging system
- Basic AuditLog model
- AuditLogger service
- Middleware integration
- Admin interface
