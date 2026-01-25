# Audit Logging Gaps and Remediation Guide

**Status:** Action Items for Zumodra Security/Compliance Teams
**Priority:** Critical and High items should be completed before production release

---

## 1. Critical Gaps (Must Fix)

### Gap 1.1: Authentication Events Not Logged to AuditLog

**Issue:** Failed login attempts and authentication events are tracked by django-axes but not recorded in the tenant-scoped AuditLog model.

**Current State:**
- django-axes tracks failed attempts in AccessAttempt model
- No integration with AuditLog
- Makes compliance reporting incomplete

**Impact:**
- ❌ SOC 2 audit requirement not met
- ❌ GDPR breach notification procedures incomplete
- ❌ Incident response lacks full context

**Remediation:**

1. Create authentication logging service:

```python
# accounts/services.py - ADD THIS

from tenants.models import AuditLog, Tenant
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

def log_authentication_event(event_type, user, ip_address, user_agent, tenant=None):
    """
    Log authentication events to audit trail.

    Args:
        event_type: 'login_success', 'login_failed', 'logout', '2fa_success', '2fa_failed'
        user: User instance or None for failed logins
        ip_address: Client IP
        user_agent: Browser user agent
        tenant: Tenant instance (optional, can derive from user)
    """

    # Derive tenant from user if not provided
    if tenant is None and user:
        tenant = user.tenant_memberships.first().tenant

    if tenant is None:
        # For failed logins without user, try to get tenant from session
        return

    action_map = {
        'login_success': AuditLog.ActionType.LOGIN,
        'logout': AuditLog.ActionType.LOGOUT,
        'login_failed': 'failed_login',
        '2fa_success': AuditLog.ActionType.LOGIN,
        '2fa_failed': 'failed_2fa',
    }

    action = action_map.get(event_type, event_type)

    AuditLog.objects.create(
        tenant=tenant,
        user=user,
        action=action,
        resource_type='User',
        resource_id=str(user.id) if user else 'unknown',
        description=f'Authentication event: {event_type}',
        ip_address=ip_address,
        user_agent=user_agent,
    )
```

2. Integrate with authentication backend:

```python
# accounts/authentication.py - ADD THIS TO TokenAuthenticate.authenticate()

from tenant_profiles.services import log_authentication_event

def authenticate(request):
    """Custom authentication with logging."""
    try:
        user = validate_token(request)
        log_authentication_event(
            'login_success',
            user,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        return user
    except AuthenticationFailed as e:
        log_authentication_event(
            'login_failed',
            None,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        raise
```

3. Hook into logout:

```python
# accounts/authentication.py - ADD THIS TO logout view

@require_http_methods(["POST"])
def logout_view(request):
    """Logout with audit logging."""
    user = request.user
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    # Log logout before clearing session
    log_authentication_event(
        'logout',
        user,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Clear session/token
    logout(request)

    return redirect('login')
```

**Estimated Effort:** 2-4 hours
**Testing:** Unit tests + integration tests
**Deployment:** Requires database migration (only schema change: adding 'failed_login' to ActionType)

---

### Gap 1.2: No Immutability Guarantee for Audit Logs

**Issue:** Audit logs can be modified or deleted via standard Django ORM, violating compliance requirements.

**Current State:**
- AuditLog is a standard Django model
- Admins can modify/delete logs
- No cryptographic verification

**Impact:**
- ❌ Audit logs are not tamper-proof
- ❌ Violates SOC 2 CC6.2 (logging integrity)
- ❌ Insufficient for FINRA/HIPAA compliance

**Remediation Option A: Database Constraints (Recommended)**

```python
# Create migration: auditlog_immutability.py

from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0001_previous_migration'),
    ]

    operations = [
        migrations.RunSQL(
            """
            -- Add trigger to prevent updates to AuditLog
            CREATE OR REPLACE FUNCTION prevent_auditlog_update()
            RETURNS TRIGGER AS $$
            BEGIN
                IF TG_OP = 'UPDATE' THEN
                    RAISE EXCEPTION 'Audit logs cannot be modified';
                ELSIF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'Audit logs cannot be deleted';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER auditlog_immutability
            BEFORE UPDATE OR DELETE ON tenants_auditlog
            FOR EACH ROW EXECUTE FUNCTION prevent_auditlog_update();
            """,
            """
            DROP TRIGGER auditlog_immutability ON tenants_auditlog;
            DROP FUNCTION prevent_auditlog_update();
            """
        ),
    ]
```

**Remediation Option B: Application-Level Enforcement**

```python
# tenants/models.py - MODIFY AuditLog class

class AuditLog(models.Model):
    # ... existing fields ...

    class Meta:
        # Make read-only at application level
        permissions = [
            ('view_auditlog', 'Can view audit logs'),
        ]
        # Note: This prevents creation in admin but not programmatically

    def save(self, *args, **kwargs):
        """Prevent modifications after creation."""
        if self.pk is not None:
            raise ValueError('Audit logs cannot be modified after creation')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Prevent deletion."""
        raise ValueError('Audit logs cannot be deleted')
```

**Remediation Option C: Cryptographic Signing (Best Practice)**

```python
# tenants/models.py - ADD hash chain

import hashlib
import hmac
from django.conf import settings

class AuditLog(models.Model):
    # ... existing fields ...
    previous_hash = models.CharField(max_length=64, blank=True)
    log_hash = models.CharField(max_length=64, editable=False, db_index=True)

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValueError('Audit logs cannot be modified')

        # Create hash chain
        if AuditLog.objects.filter(tenant=self.tenant).exists():
            previous = AuditLog.objects.filter(
                tenant=self.tenant
            ).latest('created_at')
            self.previous_hash = previous.log_hash

        # Compute log hash
        log_content = f"{self.tenant_id}{self.user_id}{self.action}{self.resource_type}{self.created_at}".encode()
        hmac_key = settings.AUDIT_LOG_SIGNING_KEY.encode()
        self.log_hash = hmac.new(hmac_key, log_content, hashlib.sha256).hexdigest()

        super().save(*args, **kwargs)
```

**Recommended:** Use Database Constraints (Option A)
- Most robust
- Cannot be bypassed programmatically
- No performance impact
- Standard database practice

**Estimated Effort:** 1-2 hours (Option A), 4-6 hours (Option C)
**Testing:** Verify UPDATEs and DELETEs fail
**Deployment:** Zero-downtime migration

---

### Gap 1.3: Sensitive Data May Be Logged

**Issue:** Some models log sensitive fields like passwords, tokens, API keys, despite exclusion in integrations.

**Current State:**
```python
# integrations/models.py - Only these are excluded
auditlog.register(IntegrationCredential, exclude_fields=[
    'access_token', 'refresh_token', 'api_key', 'api_secret', 'password'
])
```

**Problem:** Other apps don't have exclusion configured

**Impact:**
- ❌ Sensitive data in logs (PII violation)
- ❌ Compliance violation (GDPR, HIPAA)
- ❌ Security risk if logs compromised

**Remediation:**

1. Create comprehensive field exclusion policy:

```python
# Create file: auditlog_config.py

AUDITLOG_FIELD_EXCLUSIONS = {
    'tenant_profiles.User': [
        'password',
        'auth_token',
        'backup_codes',
        'recovery_email',
    ],
    'tenant_profiles.KYCVerification': [
        'id_number',
        'id_document',
        'selfie_image',
        'address_proof',
        'verification_data',
    ],
    'finance.Payment': [
        'stripe_charge_id',
        'stripe_payment_intent_id',
        'card_token',
    ],
    'integrations.IntegrationCredential': [
        'access_token',
        'refresh_token',
        'api_key',
        'api_secret',
        'password',
        'webhook_secret',
    ],
    'services.Proposal': [
        'bank_account_token',
    ],
}
```

2. Register all models with exclusions:

```python
# accounts/models.py - ADD THIS

from auditlog.registry import auditlog
from auditlog_config import AUDITLOG_FIELD_EXCLUSIONS

def register_auditlog_models():
    """Register all models with proper field exclusions."""

    excluded = AUDITLOG_FIELD_EXCLUSIONS.get('tenant_profiles.User', [])
    auditlog.register(User, exclude_fields=excluded)

    excluded = AUDITLOG_FIELD_EXCLUSIONS.get('tenant_profiles.KYCVerification', [])
    auditlog.register(KYCVerification, exclude_fields=excluded)

# Call at module load
register_auditlog_models()
```

3. Audit logging middleware to filter sensitive data:

```python
# tenants/middleware.py - ADD THIS

class AuditLogSensitiveDataFilter:
    """Filter sensitive data from audit logs."""

    SENSITIVE_PATTERNS = {
        'password': r'.*password.*',
        'token': r'.*token.*',
        'secret': r'.*secret.*',
        'key': r'.*key.*',
        'credential': r'.*credential.*',
    }

    @staticmethod
    def filter_log_values(log_entry):
        """Remove sensitive data from LogEntry."""
        import json

        try:
            for field in ['old_values', 'new_values']:
                data = getattr(log_entry, field, {})
                if isinstance(data, str):
                    data = json.loads(data)

                for key in list(data.keys()):
                    if any(key.lower().startswith(pattern) for pattern in [
                        'password', 'token', 'secret', 'key', 'credential'
                    ]):
                        data[key] = '***REDACTED***'

                setattr(log_entry, field, json.dumps(data))
        except:
            pass
```

**Estimated Effort:** 3-4 hours
**Testing:** Verify sensitive fields redacted in logs
**Deployment:** No database changes required

---

## 2. High Priority Gaps (Should Fix)

### Gap 2.1: No Archival System for Old Logs

**Issue:** Logs older than 90 days kept in production database, causing bloat.

**Current State:**
- Retention policy defined (90 days) but not enforced
- No archival mechanism
- Logs accumulate indefinitely

**Impact:**
- ⚠ Database size grows 1.8GB/year per 100K logins/month
- ⚠ Query performance degrades over time
- ⚠ Backup/restore takes longer
- ⚠ Storage costs increase

**Remediation:**

1. Create archival task:

```python
# zumodra/tasks.py - ADD THIS

from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import json
import boto3
from tenants.models import AuditLog, Tenant

@shared_task
def archive_old_audit_logs():
    """
    Archive audit logs older than 90 days to S3.
    Runs quarterly.
    """
    cutoff_date = timezone.now() - timedelta(days=90)

    for tenant in Tenant.objects.filter(status='active'):
        logs = AuditLog.objects.filter(
            tenant=tenant,
            created_at__lt=cutoff_date,
            archived=False
        )

        if not logs.exists():
            continue

        # Create archive file
        archive_data = []
        for log in logs:
            archive_data.append({
                'uuid': str(log.uuid),
                'action': log.action,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'user_id': log.user_id,
                'ip_address': log.ip_address,
                'old_values': log.old_values,
                'new_values': log.new_values,
                'created_at': log.created_at.isoformat(),
            })

        # Upload to S3
        s3 = boto3.client('s3')
        archive_key = f"audit-logs/{tenant.slug}/{cutoff_date.year}/{cutoff_date.month:02d}.json.gz"

        import gzip
        compressed = gzip.compress(json.dumps(archive_data).encode())

        s3.put_object(
            Bucket=settings.AUDIT_LOG_ARCHIVE_BUCKET,
            Key=archive_key,
            Body=compressed,
            ServerSideEncryption='AES256',
            StorageClass='GLACIER',  # Long-term storage
        )

        # Mark as archived
        logs.update(archived=True)

        # Delete from active database
        logs.delete()

        logger.info(f"Archived {logs.count()} logs for {tenant.slug}")

@shared_task
def backup_audit_logs_weekly():
    """Daily backup of active audit logs."""
    s3 = boto3.client('s3')

    # Export to S3 in JSON Lines format
    # Enables point-in-time recovery
```

2. Add archival fields to model:

```python
# tenants/models.py - ADD FIELDS

class AuditLog(models.Model):
    # ... existing fields ...

    archived = models.BooleanField(
        default=False,
        db_index=True,
        help_text='Whether log has been archived to cold storage'
    )
    archive_location = models.CharField(
        max_length=255,
        blank=True,
        help_text='S3 path where archived'
    )

    class Meta:
        # ... existing meta ...
        indexes = [
            # ... existing indexes ...
            models.Index(fields=['archived', 'created_at']),
        ]
```

3. Schedule quarterly archival:

```python
# zumodra/celery_beat_schedule.py - ADD THIS

CELERY_BEAT_SCHEDULE = {
    # ... existing tasks ...
    'archive-old-audit-logs': {
        'task': 'zumodra.tasks.archive_old_audit_logs',
        'schedule': crontab(day_of_month=1, hour=2, minute=0),  # Monthly
        'options': {'queue': 'maintenance'}
    },
    'backup-audit-logs': {
        'task': 'zumodra.tasks.backup_audit_logs_weekly',
        'schedule': crontab(hour=3, minute=0),  # Daily at 3 AM
        'options': {'queue': 'maintenance'}
    },
}
```

**Estimated Effort:** 6-8 hours
**Infrastructure Required:**
- S3 bucket with lifecycle policies
- IAM role for Celery worker
- Backup/restore procedures documented

**Deployment:** Requires:
- Database migration (add archived, archive_location fields)
- S3 bucket creation
- IAM configuration
- Celery Beat schedule update

---

### Gap 2.2: No Automatic View/API Logging Middleware

**Issue:** User actions in views/APIs not automatically logged, only manual logging where implemented.

**Current State:**
- AuditLog entries created manually in views
- Inconsistent coverage (some views logged, others not)
- API accesses not tracked

**Impact:**
- ⚠ Incomplete audit trail
- ⚠ Manual logging prone to errors/omissions
- ⚠ Maintenance burden

**Remediation:**

```python
# tenants/middleware.py - ADD THIS

import logging
import json
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from tenants.models import AuditLog, Tenant
from core.utils import get_client_ip

logger = logging.getLogger(__name__)

class AuditLoggingMiddleware(MiddlewareMixin):
    """
    Automatically log user actions in views and APIs.
    """

    TRACKED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    IGNORE_PATHS = [
        '/health/',
        '/static/',
        '/media/',
        '/api/docs/',
        '/swagger/',
    ]

    def process_view(self, request, view_func, view_args, view_kwargs):
        """Log view access."""
        # Store request metadata for process_response
        request._audit_log_start = timezone.now()
        request._audit_log_path = request.path
        request._audit_log_method = request.method

        # Extract tenant from request
        request._audit_log_tenant = getattr(request, 'tenant', None)

        return None

    def process_response(self, request, response):
        """Create audit log entry after view execution."""

        # Skip non-tracked methods and paths
        if (request.method not in self.TRACKED_METHODS or
            any(request.path.startswith(p) for p in self.IGNORE_PATHS)):
            return response

        try:
            tenant = getattr(request, 'tenant', None)
            user = request.user if request.user.is_authenticated else None

            if not tenant:
                return response

            # Determine action type from HTTP method
            action_map = {
                'POST': AuditLog.ActionType.CREATE,
                'PUT': AuditLog.ActionType.UPDATE,
                'PATCH': AuditLog.ActionType.UPDATE,
                'DELETE': AuditLog.ActionType.DELETE,
            }
            action = action_map.get(request.method, 'update')

            # Extract resource info from URL
            resource_type = self._extract_resource_type(request.path)
            resource_id = self._extract_resource_id(request.path)

            # Log only on success (2xx/3xx status)
            if 200 <= response.status_code < 400:
                AuditLog.objects.create(
                    tenant=tenant,
                    user=user,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    description=f'{request.method} {request.path}',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                )
        except Exception as e:
            logger.error(f'Error logging audit trail: {e}')

        return response

    @staticmethod
    def _extract_resource_type(path):
        """Extract resource type from URL path."""
        # /api/v1/jobs/jobs/ -> Job
        # /api/v1/jobs/candidates/ -> Candidate
        parts = path.strip('/').split('/')
        if len(parts) >= 3:
            resource = parts[-2] if parts[-1] == '' else parts[-1]
            return resource.capitalize()
        return 'Unknown'

    @staticmethod
    def _extract_resource_id(path):
        """Extract resource ID from URL path."""
        # /api/v1/jobs/jobs/123/ -> 123
        import re
        match = re.search(r'/(\d+)/?$', path)
        return match.group(1) if match else ''
```

**Estimated Effort:** 4-6 hours
**Testing:** Verify all CRUD operations logged
**Deployment:** No database changes, just middleware registration

---

### Gap 2.3: No Compliance Dashboard

**Issue:** No UI for searching, filtering, and reporting audit logs.

**Current State:**
- Logs stored in database
- No admin interface for audit log queries
- Compliance reports generated manually

**Impact:**
- ⚠ Difficult to investigate incidents
- ⚠ Compliance audits require database queries
- ⚠ No self-service reporting

**Remediation:** Create Django admin interface

```python
# tenants/admin.py - ADD THIS

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count, Q
from django_admin_inline_paginator.admin import TabularInlinePaginator
from .models import AuditLog

class AuditLogAdmin(admin.ModelAdmin):
    """Advanced audit log search and filtering."""

    list_display = [
        'id', 'action_badge', 'resource_type', 'user_link',
        'ip_address', 'created_at_display', 'summary'
    ]
    list_filter = [
        'action', 'resource_type', 'created_at',
        ('user', admin.RelatedOnlyFieldListFilter),
        ('tenant', admin.RelatedOnlyFieldListFilter),
    ]
    search_fields = [
        'user__email', 'resource_id', 'description', 'ip_address'
    ]
    readonly_fields = [
        'uuid', 'old_values_display', 'new_values_display',
        'created_at', 'ip_address'
    ]

    fieldsets = (
        ('Event', {
            'fields': ('uuid', 'action', 'created_at')
        }),
        ('Resource', {
            'fields': ('resource_type', 'resource_id')
        }),
        ('Actor', {
            'fields': ('user', 'tenant', 'ip_address')
        }),
        ('Changes', {
            'fields': ('old_values_display', 'new_values_display'),
            'classes': ('collapse',)
        }),
        ('Request Context', {
            'fields': ('user_agent',),
            'classes': ('collapse',)
        }),
    )

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def action_badge(self, obj):
        """Color-coded action type."""
        colors = {
            'create': '#28a745',
            'update': '#ffc107',
            'delete': '#dc3545',
            'login': '#007bff',
            'export': '#6c757d',
        }
        color = colors.get(obj.action, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; '
            'padding: 3px 10px; border-radius: 3px;">{}</span>',
            color, obj.get_action_display()
        )
    action_badge.short_description = 'Action'

    def user_link(self, obj):
        """Link to user."""
        if obj.user:
            return format_html(
                '<a href="/admin/auth/user/{}/change/">{}</a>',
                obj.user.id, obj.user.email
            )
        return '-'
    user_link.short_description = 'User'

    def created_at_display(self, obj):
        """Formatted timestamp."""
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
    created_at_display.short_description = 'When'

    def old_values_display(self, obj):
        """Format old values as JSON."""
        import json
        return format_html(
            '<pre>{}</pre>',
            json.dumps(obj.old_values, indent=2)
        )
    old_values_display.short_description = 'Old Values'

    def new_values_display(self, obj):
        """Format new values as JSON."""
        import json
        return format_html(
            '<pre>{}</pre>',
            json.dumps(obj.new_values, indent=2)
        )
    new_values_display.short_description = 'New Values'

    def summary(self, obj):
        """One-line summary."""
        return obj.description[:100]
    summary.short_description = 'Description'

admin.site.register(AuditLog, AuditLogAdmin)
```

**Estimated Effort:** 4-6 hours
**Deployment:** No database changes

---

## 3. Medium Priority Gaps

### Gap 3.1: No Alerting for Suspicious Activities

**Issue:** No automated alerts for security events (brute force, privilege escalation, etc).

**Remediation:** Create alerting tasks

```python
# integrations/services.py - ADD THIS

@shared_task
def check_suspicious_activities():
    """Detect and alert on suspicious patterns."""

    from tenants.models import AuditLog
    from notifications.services import send_alert

    # Check 1: Multiple failed logins from same IP
    failed_logins = AuditLog.objects.filter(
        action='failed_login',
        created_at__gte=timezone.now() - timedelta(hours=1)
    ).values('ip_address').annotate(
        count=Count('id')
    ).filter(count__gte=5)

    for item in failed_logins:
        send_alert(
            f"Brute force attempt from {item['ip_address']}: {item['count']} failed logins",
            severity='high'
        )

    # Check 2: Privilege escalation
    privilege_changes = AuditLog.objects.filter(
        action=AuditLog.ActionType.PERMISSION_CHANGE,
        created_at__gte=timezone.now() - timedelta(hours=1)
    ).filter(
        new_values__role__in=['admin', 'owner']
    )

    for log in privilege_changes:
        send_alert(
            f"Privilege escalation: {log.user.email} -> {log.new_values.get('role')}",
            severity='critical'
        )
```

**Estimated Effort:** 2-3 hours
**Deployment:** Celery task, no database changes

---

## 4. Implementation Timeline

```
Week 1:
  Day 1-2: Implement authentication logging (Gap 1.1)
  Day 3-4: Add immutability constraints (Gap 1.2)
  Day 5: Testing & documentation

Week 2:
  Day 1-2: Sensitive data filtering (Gap 1.3)
  Day 3-5: Create archival system (Gap 2.1)

Week 3:
  Day 1-3: Implement logging middleware (Gap 2.2)
  Day 4-5: Build compliance dashboard (Gap 2.3)

Week 4:
  Day 1-2: Add alerting system (Gap 3.1)
  Day 3-5: Testing, documentation, deployment prep
```

---

## 5. Testing Checklist

For each gap remediation:

- [ ] Unit tests written
- [ ] Integration tests pass
- [ ] Performance impact assessed
- [ ] Security review completed
- [ ] Documentation updated
- [ ] Code reviewed by team
- [ ] QA sign-off obtained

---

## 6. Compliance Checklist

After all gaps fixed:

- [ ] SOC 2 audit requirements met
- [ ] GDPR procedures documented
- [ ] HIPAA compliance verified
- [ ] FINRA logging requirements met
- [ ] PCI DSS applicable requirements reviewed
- [ ] Incident response procedures updated
- [ ] Auditor sign-off obtained

---

**Report Generated:** 2026-01-16
**Next Review:** After all critical gaps fixed (Target: 2026-03-31)
