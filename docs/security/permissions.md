# Zumodra Security Permissions Guide

This document describes the security permission system implemented in the Zumodra platform.

## Table of Contents

1. [Role Definitions](#role-definitions)
2. [Permission Classes](#permission-classes)
3. [Secure ViewSets](#secure-viewsets)
4. [View Decorators](#view-decorators)
5. [Celery Task Security](#celery-task-security)
6. [Sensitive Data Protection](#sensitive-data-protection)
7. [Input Validation](#input-validation)
8. [Audit Logging](#audit-logging)
9. [How to Add New Permissions](#how-to-add-new-permissions)

---

## Role Definitions

Zumodra uses a role-based access control (RBAC) system with the following roles:

| Role | Description | Access Level |
|------|-------------|--------------|
| `owner` | Tenant owner (PDG) | Full access to all tenant resources |
| `admin` | Tenant administrator | Full access except billing/ownership transfer |
| `hr_manager` | HR Manager | Employee records, time-off, onboarding |
| `recruiter` | Recruiter | Candidates, applications, job postings |
| `hiring_manager` | Hiring Manager | Assigned jobs, interview feedback |
| `employee` | Regular employee | Own profile, time-off requests |
| `viewer` | Read-only access | View-only access to non-sensitive data |

### Role Hierarchy

```
owner
  └── admin
       ├── hr_manager
       ├── recruiter
       │    └── hiring_manager
       └── employee
            └── viewer
```

---

## Permission Classes

Located in `core/permissions.py`, these classes enforce access control:

### Basic Permissions

```python
from core.permissions import (
    IsTenantUser,        # User belongs to current tenant
    IsTenantAdmin,       # User is admin or owner
    IsTenantOwner,       # User is tenant owner
    TenantObjectPermission,  # Object belongs to tenant
)
```

### Role-Based Permissions

```python
from core.permissions import (
    IsRecruiter,         # Recruiter or higher
    IsHRManager,         # HR Manager or higher
    IsHiringManager,     # Hiring Manager or higher
)
```

### Object-Level Permissions

```python
from core.permissions import (
    ObjectOwnerPermission,   # User owns the object
    IsParticipant,          # User is a participant (contracts, conversations)
)
```

### Audited Permissions

Wrap any permission class to log access attempts:

```python
from core.permissions import audited

# Log all permission checks
permission_classes = [audited(IsTenantAdmin)]
```

---

## Secure ViewSets

Located in `core/viewsets.py`, use these as base classes for your ViewSets:

### SecureTenantViewSet

Default secure ViewSet with tenant isolation:

```python
from core.viewsets import SecureTenantViewSet

class JobViewSet(SecureTenantViewSet):
    queryset = JobPosting.objects.all()
    serializer_class = JobSerializer
    # Automatically scoped to current tenant
    # Requires authentication and tenant membership
```

### RoleBasedViewSet

Per-action role requirements:

```python
from core.viewsets import RoleBasedViewSet

class EmployeeViewSet(RoleBasedViewSet):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer

    role_permissions = {
        'list': ['hr_manager', 'admin', 'owner'],
        'retrieve': ['hr_manager', 'admin', 'owner', 'employee'],
        'create': ['hr_manager', 'admin', 'owner'],
        'update': ['hr_manager', 'admin', 'owner'],
        'destroy': ['admin', 'owner'],
    }
```

### RecruiterViewSet

For recruiting-related views:

```python
from core.viewsets import RecruiterViewSet

class CandidateViewSet(RecruiterViewSet):
    queryset = Candidate.objects.all()
    # Requires recruiter, hiring_manager, hr_manager, admin, or owner role
```

### HRViewSet

For HR-related views:

```python
from core.viewsets import HRViewSet

class TimeOffViewSet(HRViewSet):
    queryset = TimeOffRequest.objects.all()
    # Requires hr_manager, admin, or owner role
```

### ParticipantViewSet

For resources with participant-based access:

```python
from core.viewsets import ParticipantViewSet

class ContractViewSet(ParticipantViewSet):
    queryset = Contract.objects.all()
    participant_fields = ['buyer', 'seller']
    # Only participants can access
```

---

## View Decorators

Located in `core/decorators.py`, for function-based views:

### @require_tenant

Requires tenant context:

```python
from core.decorators import require_tenant

@require_tenant
def my_view(request):
    # request.tenant is guaranteed
    return HttpResponse('OK')
```

### @require_tenant_user

Requires tenant membership:

```python
from core.decorators import require_tenant_user

@require_tenant_user
def my_view(request):
    # User is member of current tenant
    return HttpResponse('OK')
```

### @require_role

Requires specific roles:

```python
from core.decorators import require_role

@require_role(['admin', 'owner'])
def admin_view(request):
    return HttpResponse('Admin only')

@require_role(['hr_manager', 'admin', 'owner'])
def hr_view(request):
    return HttpResponse('HR access')
```

### @require_permission

Requires specific Django permission:

```python
from core.decorators import require_permission

@require_permission('ats.change_candidate')
def edit_candidate(request, pk):
    return HttpResponse('Edit form')
```

### @audit_access

Log access for audit:

```python
from core.decorators import audit_access

@audit_access('viewed_salary')
def view_salary(request, employee_id):
    # Access logged to security.audit logger
    return HttpResponse('Salary data')
```

### @rate_limit

Apply rate limiting:

```python
from core.decorators import rate_limit

@rate_limit(limit=10, period=60)  # 10 requests per minute
def api_endpoint(request):
    return HttpResponse('OK')
```

---

## Celery Task Security

Located in `core/tasks/secure_task.py`:

### SecureTenantTask

Base class for secure background tasks:

```python
from core.tasks.secure_task import SecureTenantTask

class BulkEmailTask(SecureTenantTask):
    required_permission = 'messaging.send_bulk_email'
    required_roles = ['hr_manager', 'admin', 'owner']

    def run_task(self, user_id, tenant_id, recipients, subject, body):
        # Permission validated before this runs
        send_emails(recipients, subject, body)
```

### Using Secure Tasks

```python
# The task validates permissions before execution
BulkEmailTask.delay(
    user_id=request.user.id,
    tenant_id=request.tenant.id,
    recipients=['user1@example.com', 'user2@example.com'],
    subject='Important Update',
    body='...'
)
```

---

## Sensitive Data Protection

Located in `core/serializers.py`:

### SensitiveFieldMixin

Automatically mask sensitive fields:

```python
from core.serializers import SensitiveFieldMixin

class EmployeeSerializer(SensitiveFieldMixin, serializers.ModelSerializer):
    sensitive_fields = ['ssn', 'bank_account', 'phone']
    sensitive_roles = {'owner', 'admin', 'hr_manager'}

    class Meta:
        model = Employee
        fields = '__all__'
```

### Masking Patterns

| Field Type | Masked Example |
|------------|----------------|
| Email | `j***@company.com` |
| Phone | `***-***-1234` |
| SSN | `***-**-6789` |
| Bank Account | `****1234` |

### SecureModelSerializer

Combines all security features:

```python
from core.serializers import SecureModelSerializer

class PayrollSerializer(SecureModelSerializer):
    sensitive_fields = ['bank_account', 'salary']
    owner_only_fields = ['performance_bonus']
    audit_all_access = True

    class Meta:
        model = Payroll
        fields = '__all__'
```

---

## Input Validation

Located in `core/validators.py`:

### SQL Injection Prevention

```python
from core.validators import NoSQLInjection

class MyForm(forms.Form):
    search = forms.CharField(validators=[NoSQLInjection()])
```

### XSS Prevention

```python
from core.validators import NoXSS

class MyForm(forms.Form):
    content = forms.CharField(validators=[NoXSS()])
```

### HTML Sanitization

```python
from core.validators import sanitize_html

def clean_description(self):
    return sanitize_html(self.cleaned_data['description'])
```

### File Upload Validation

```python
from core.validators import FileValidator

class DocumentForm(forms.Form):
    file = forms.FileField(validators=[FileValidator('document')])
    image = forms.ImageField(validators=[FileValidator('image')])
```

---

## Audit Logging

### Security Loggers

- `security.permissions` - Permission check logs
- `security.audit` - Sensitive data access
- `security.serializers` - Data serialization
- `security.cache` - Cache invalidation
- `security.kyc` - KYC verification

### Log Format

```
PERMISSION_DENIED: user=123 tenant=456 permission=IsTenantAdmin ip=192.168.1.1
SENSITIVE_DATA_ACCESS: user=123 model=Employee instance=789 fields=['ssn', 'bank_account']
CACHE_INVALIDATED: type=permissions user=123 tenant=456
```

### Viewing Logs

```bash
# View security logs
tail -f logs/security.log

# Filter by type
grep "PERMISSION_DENIED" logs/security.log
```

---

## How to Add New Permissions

### 1. Create Permission Class

```python
# In your app's permissions.py
from core.permissions import TenantPermissionMixin

class CanApproveExpenses(TenantPermissionMixin, permissions.BasePermission):
    message = "You don't have permission to approve expenses."

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        return self.has_role(request, ['finance_manager', 'admin', 'owner'])
```

### 2. Use in ViewSet

```python
class ExpenseViewSet(SecureTenantViewSet):
    permission_classes = [IsAuthenticated, IsTenantUser, CanApproveExpenses]
```

### 3. Use in Decorator

```python
@require_role(['finance_manager', 'admin', 'owner'])
def approve_expense(request, expense_id):
    ...
```

### 4. Add to Celery Task

```python
class ApproveExpenseTask(SecureTenantTask):
    required_roles = ['finance_manager', 'admin', 'owner']

    def run_task(self, expense_id):
        ...
```

---

## Security Checklist

When adding new views/endpoints:

- [ ] Inherit from `SecureTenantViewSet` or use decorators
- [ ] Add appropriate role requirements
- [ ] Filter querysets by tenant
- [ ] Use `SensitiveFieldMixin` for PII fields
- [ ] Add input validation to forms
- [ ] Log sensitive data access
- [ ] Write security tests

---

## Testing Security

Run security tests:

```bash
# All security tests
pytest -m security

# Specific test class
pytest tests/test_permissions_comprehensive.py::TestTenantIsolation -v

# With coverage
pytest -m security --cov=core.permissions --cov=core.viewsets
```

---

## Emergency Procedures

### Revoking User Access

```python
from core.cache import invalidate_permission_cache

# Immediately revoke all cached permissions
invalidate_all_user_permissions(user_id)

# Deactivate tenant membership
TenantUser.objects.filter(user_id=user_id).update(is_active=False)
```

### Investigating Security Incidents

1. Check security logs: `grep "PERMISSION" logs/security.log`
2. Review audit trail in admin
3. Check login history: `LoginHistory.objects.filter(user_id=...)`
4. Review cache invalidation events

---

*Last updated: 2024*
