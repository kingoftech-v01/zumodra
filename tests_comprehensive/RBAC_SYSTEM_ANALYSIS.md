# RBAC System Analysis & Architecture

**Date:** 2026-01-16
**Status:** Analysis Complete
**Document Type:** Technical Architecture & Implementation Review

---

## Table of Contents

1. [Overview](#overview)
2. [Current RBAC Implementation](#current-rbac-implementation)
3. [Role Definitions](#role-definitions)
4. [Permission Architecture](#permission-architecture)
5. [Multi-Tenant Integration](#multi-tenant-integration)
6. [Data Isolation Mechanisms](#data-isolation-mechanisms)
7. [API Security Implementation](#api-security-implementation)
8. [Identified Issues & Recommendations](#identified-issues--recommendations)

---

## Overview

### System Purpose

Zumodra implements a comprehensive Role-Based Access Control (RBAC) system for a multi-tenant SaaS platform supporting:

- **7 distinct user roles** with different permission levels
- **Multi-tenant isolation** - complete data separation between organizations
- **Department-based access control** - hierarchical permission within tenants
- **Object-level permissions** - ownership and collaboration controls
- **API and view-level enforcement** - secure frontend and backend

### Key Features

✓ Tenant-scoped role assignments
✓ Multi-tenant membership (same user in multiple orgs)
✓ Department-level hierarchy
✓ Custom permissions per role
✓ Permission caching for performance
✓ Audit logging of permission changes

---

## Current RBAC Implementation

### Core Models

#### 1. TenantUser Model
**Location:** `/accounts/models.py`

```python
class TenantUser(models.Model):
    class UserRole(models.TextChoices):
        OWNER = 'owner', _('Owner/PDG')
        ADMIN = 'admin', _('Administrator')
        HR_MANAGER = 'hr_manager', _('HR Manager')
        RECRUITER = 'recruiter', _('Recruiter')
        HIRING_MANAGER = 'hiring_manager', _('Hiring Manager')
        EMPLOYEE = 'employee', _('Employee')
        VIEWER = 'viewer', _('Viewer (Read-only)')

    user = ForeignKey(User, on_delete=CASCADE)
    tenant = ForeignKey(Tenant, on_delete=CASCADE)
    role = CharField(max_length=20, choices=UserRole.choices)
    department = ForeignKey(Department, null=True, blank=True)
    custom_permissions = ManyToManyField(Permission)
    is_active = BooleanField(default=True)
    reports_to = ForeignKey('self', null=True, blank=True)
```

**Key Characteristics:**
- Single join table between User and Tenant
- Unique constraint: (user, tenant) pair
- Role is tenant-scoped (not global)
- Department optional, for org structure
- Reporting relationships supported
- Custom permissions per user

#### 2. KYCVerification Model
**Location:** `/accounts/models.py`

Handles identity verification for users:
- Bidirectional KYC (candidates and recruiters)
- Verification status tracking
- Expiration handling

#### 3. ProgressiveConsent Model
**Location:** `/accounts/models.py`

Manages data access consent:
- User consent for data sharing
- Consent withdrawal
- Audit trail of consent changes

---

## Role Definitions

### 1. Owner/PDG (OWNER)
**Permission Level:** FULL SYSTEM ACCESS

**Capabilities:**
- Create/modify/delete tenant configuration
- Manage all users and roles
- Access billing and subscription settings
- Delete tenant
- Access all data across all departments
- Change other users' roles
- Enable/disable features

**Restrictions:**
- Cannot be created by admins (owner-only action)
- Only one owner per tenant (enforced by business logic)

**Use Cases:**
- C-level executives (CEO, President)
- Sole proprietors
- Business owners

---

### 2. Administrator (ADMIN)
**Permission Level:** ADMINISTRATIVE ACCESS

**Capabilities:**
- Create/edit/delete users (except owner)
- Modify user roles (except to owner)
- Change user departments
- View all tenant data
- Manage integrations
- Access audit logs
- Configure features (within plan limits)

**Restrictions:**
- Cannot delete owner account
- Cannot change own role (prevent privilege escalation)
- Cannot access billing
- Cannot delete tenant

**Use Cases:**
- IT administrators
- Office managers
- Team leads with admin access

---

### 3. HR Manager (HR_MANAGER)
**Permission Level:** DEPARTMENT/HR FUNCTION ACCESS

**Capabilities:**
- Manage employee records (in assigned departments or all if no dept restriction)
- Approve/reject time-off requests
- View payroll information
- Access HR analytics
- Manage onboarding workflows
- View employee performance reviews
- Access training/compliance records

**Restrictions:**
- Cannot manage system users
- Cannot change user roles
- Cannot access billing
- Limited by department (or all departments)
- Cannot delete users

**Use Cases:**
- HR specialists
- People operations managers
- Employee relations staff

---

### 4. Recruiter (RECRUITER)
**Permission Level:** RECRUITMENT FUNCTION ACCESS

**Capabilities:**
- Create/edit/delete job postings
- Manage candidates and applications
- Schedule interviews (pending hiring manager approval)
- Send candidate communications
- Generate recruitment reports
- Access candidate database
- Manage job boards

**Restrictions:**
- Cannot manage HR/employee data
- Cannot conduct interviews alone (need hiring manager)
- Cannot approve hiring decisions (need hiring manager)
- Cannot change job publishing status (admin/owner only)
- Cannot delete candidates (only archive)

**Use Cases:**
- Recruitment specialists
- Talent acquisition managers
- Sourcing coordinators

---

### 5. Hiring Manager (HIRING_MANAGER)
**Permission Level:** HIRING PROCESS ACCESS

**Capabilities:**
- View job postings and candidates
- Conduct interviews and provide feedback
- Make hiring recommendations/decisions
- Create offers
- Access candidate evaluations
- View interview feedback from others
- Approve/reject candidates

**Restrictions:**
- Cannot create job postings (recruiter role)
- Cannot manage HR functions
- Cannot delete candidates
- Cannot change salary ranges (admin/owner)
- Cannot approve final offers (owner/admin)

**Use Cases:**
- Department heads
- Team leads
- Hiring team members
- Department managers

---

### 6. Employee (EMPLOYEE)
**Permission Level:** PERSONAL/DEPARTMENT ACCESS

**Capabilities:**
- View own profile
- Update own profile/password
- Submit time-off requests
- View own time-off requests
- Submit expense reports
- View own salary information
- Access internal communications
- View team calendar
- Submit feedback/reviews (when prompted)
- Apply for internal jobs

**Restrictions:**
- Cannot view other employees' data (except manager/team)
- Cannot approve time-off
- Cannot access candidates/jobs
- Cannot change own role
- Cannot delete own account
- Cannot view salary info of others

**Use Cases:**
- Regular employees
- Contractors (if on payroll)
- Interns

---

### 7. Viewer (VIEWER)
**Permission Level:** READ-ONLY ACCESS

**Capabilities:**
- View dashboards (limited metrics)
- View publicly shared documents
- View own profile (read-only)
- View aggregated reports
- View team structure (org chart)

**Restrictions:**
- **CANNOT** create anything
- **CANNOT** modify anything
- **CANNOT** delete anything
- **CANNOT** change any settings
- Cannot view individual salary data
- Cannot view candidate details

**Use Cases:**
- Executives reviewing metrics
- Auditors (temporary read-only access)
- Board members
- Advisors
- External stakeholders (limited view)

---

## Permission Architecture

### Permission Classes
**Location:** `/accounts/permissions.py`

The system implements multiple permission classes for different scenarios:

#### 1. Tenant-Level Permissions

```python
class IsTenantUser(permissions.BasePermission):
    """User is member of current tenant"""
    # Checks TenantUser exists with is_active=True

class IsTenantAdmin(permissions.BasePermission):
    """User has admin or owner role"""
    # Checks role in (admin, owner)

class IsTenantOwner(permissions.BasePermission):
    """User has owner role only"""
    # Checks role == owner
```

#### 2. Data-Level Permissions

```python
class CanAccessUserData(permissions.BasePermission):
    """User has consent to access other user's data"""
    # Checks ProgressiveConsent

class HasKYCVerification(permissions.BasePermission):
    """User has verified KYC status"""
    # Checks KYCVerification.is_verified
```

#### 3. Object-Level Permissions

```python
class ObjectOwnerPermission(permissions.BasePermission):
    """Object owner or admin can modify"""
    # Checks obj.created_by == request.user OR is_admin

class TenantObjectPermission(permissions.BasePermission):
    """Object tenant matches request tenant"""
    # Checks obj.tenant == request.tenant
```

#### 4. Role-Based Permissions

```python
class HasTenantRole(permissions.BasePermission):
    """User has specific role"""
    # Checks role in request.user.tenant_memberships

class HasTenantPermission(permissions.BasePermission):
    """User has specific permission"""
    # Checks custom_permissions and role defaults
```

#### 5. Feature/Plan Permissions

```python
class HasFeatureAccess(permissions.BasePermission):
    """User's plan includes feature"""
    # Checks subscription.plan.features

class HasPlanPermission(permissions.BasePermission):
    """User's plan tier has access"""
    # Checks subscription.tier >= required_tier
```

### Permission Inheritance

**Role-to-Permission Mapping:**

```
OWNER (Full)
├── ADMIN
│   ├── HR_MANAGER
│   │   ├── EMPLOYEE
│   │   └── VIEWER
│   ├── RECRUITER
│   │   ├── HIRING_MANAGER
│   │   └── EMPLOYEE
│   └── HIRING_MANAGER
└── (plan limits don't apply)

VIEWER (Minimal)
├── Read-only access
└── No plan-based restrictions
```

**Permission Resolution:**
1. Check if user is tenant member (IsTenantUser)
2. Check role-specific permission class
3. Apply object-level filters (department, ownership)
4. Apply plan-based limits
5. Apply scope limits (tenant, department)

---

## Multi-Tenant Integration

### Tenant Routing

**How requests get tenant context:**

1. **Domain-based routing** (`tenants/middleware.py`):
   ```
   subdomain.localhost        → Tenant with slug='subdomain'
   company.zumodra.com        → Tenant with domain='company.zumodra.com'
   localhost:8002 (no tenant) → Public/frontend site
   ```

2. **Middleware attachment**:
   ```python
   # Sets request.tenant from domain/slug
   # Sets request.user.current_tenant
   # Validates user is member of tenant
   ```

3. **QuerySet filtering**:
   ```python
   # All models with tenant_id automatically filtered
   User.objects.all()  # Returns only users in request.tenant
   ```

### Tenant User Assignment

**Database structure:**

```
User (auth_user)
├── id
├── username
└── email
    ↓
TenantUser (linking table)
├── user_id (FK)
├── tenant_id (FK) ← Tenant association
├── role          ← Role per tenant
├── department_id ← Department assignment
└── custom_permissions (M2M)
    ↓
Tenant
├── id
├── name
└── schema_name (for database schema)
```

### Multi-Tenant Data Isolation

**Schema-based isolation:**

```
PostgreSQL Database: zumodra
├── public (shared schema)
│   ├── tenants_tenant (tenant list)
│   ├── auth_user (users table)
│   └── accounts_tenantuser (user-tenant mapping)
├── techcorp (company A schema)
│   ├── ats_job
│   ├── ats_candidate
│   ├── hr_core_employee
│   └── ... (all other tables)
└── financeinc (company B schema)
    ├── ats_job
    ├── ats_candidate
    ├── hr_core_employee
    └── ... (same tables, different data)
```

**Benefits:**
- Complete data isolation at database level
- No cross-tenant data leakage possible
- Easy tenant backup/restore
- Scalability (can move tenants to different databases)
- Compliance (data residency requirements)

---

## Data Isolation Mechanisms

### 1. Middleware Enforcement

**TenantMiddleware** (`tenants/middleware.py`):
```python
def __call__(self, request):
    # 1. Extract tenant from domain/subdomain
    # 2. Load Tenant object
    # 3. Switch database schema
    # 4. Verify user belongs to tenant
    # 5. Set request.tenant
    # 6. Attach to user
```

### 2. QuerySet Filtering

**All models inherit filtering:**
```python
# Automatic in multi-tenant mode:
User.objects.all()  # Only users in request.tenant

# Explicit filtering:
Job.objects.filter(tenant=request.tenant)

# No explicit filter needed (manager handles it):
Job.objects.all()  # Still filtered by middleware
```

### 3. View-Level Protection

**Views require tenant context:**
```python
def job_list(request):
    # request.tenant is set by middleware
    # request.user must be in request.tenant
    # Results automatically filtered by tenant
```

### 4. API-Level Protection

**API ViewSets:**
```python
class JobViewSet(viewsets.ModelViewSet):
    permission_classes = [IsTenantUser]  # Must be in tenant

    def get_queryset(self):
        return Job.objects.filter(tenant=self.request.tenant)
```

### 5. Database Schema Isolation

**Each tenant has separate schema:**
```bash
# Company A data in 'techcorp' schema
psql -h localhost -U postgres zumodra -c "SET search_path TO techcorp; SELECT * FROM ats_job;"

# Company B data in 'financeinc' schema
psql -h localhost -U postgres zumodra -c "SET search_path TO financeinc; SELECT * FROM ats_job;"
```

---

## API Security Implementation

### Authentication Methods

#### 1. Token Authentication (REST API)
**Endpoint:** `/api/token/`

```bash
curl -X POST http://localhost:8084/api/token/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john@company.com",
    "password": "securepass123"
  }'

Response:
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

#### 2. JWT Authentication
**Package:** `djangorestframework-simplejwt`

**Configuration:**
```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ]
}
```

#### 3. Session Authentication (Browser)
**Method:** Django session cookies
- Set on login
- Validated on each request
- Cleared on logout

### Authorization Checks

**Flow for API request:**

```
HTTP Request
    ↓
Authentication (validate token/session)
    ↓
Tenant Middleware (set request.tenant)
    ↓
View Permission Classes (IsTenantUser, HasRole)
    ↓
QuerySet Filtering (filter by tenant)
    ↓
Object-Level Permissions (ownership check)
    ↓
Response
```

### Rate Limiting

**Configuration:** `api/throttling.py`

```python
# Per-role rate limiting:
OWNER:          10,000 requests/hour (unlimited)
ADMIN:          5,000 requests/hour
HR_MANAGER:     2,000 requests/hour
RECRUITER:      2,000 requests/hour
EMPLOYEE:       500 requests/hour
VIEWER:         100 requests/hour
```

---

## Identified Issues & Recommendations

### ✓ STRENGTHS

1. **Comprehensive Role System**
   - 7 well-defined roles covering all use cases
   - Clear responsibility boundaries
   - Hierarchical permission structure

2. **Strong Multi-Tenant Isolation**
   - Schema-based database isolation
   - Middleware enforcement
   - No cross-tenant access possible

3. **Flexible Permission System**
   - Custom permissions per user
   - Department-based restrictions
   - Plan-based feature access

4. **Security Features**
   - KYC verification support
   - Consent management
   - Audit logging
   - Rate limiting by role

### ⚠ POTENTIAL ISSUES

#### Issue 1: Role Change Validation
**Severity:** MEDIUM

**Description:** When changing a user's role, ensure all cascading changes are handled:
- Department reassignment (if needed)
- Permission cleanup (revoke no-longer-applicable permissions)
- Resource access updates
- Audit logging

**Recommendation:**
```python
def change_user_role(user, tenant, new_role):
    """Safely change user role with validation"""
    old_role = TenantUser.objects.get(user=user, tenant=tenant).role

    # 1. Verify permission to change role
    # 2. Validate new role transition (some roles may not be compatible)
    # 3. Revoke previous role permissions
    # 4. Grant new role permissions
    # 5. Log change with audit trail
    # 6. Notify user and admins
```

#### Issue 2: Department Boundary Enforcement
**Severity:** MEDIUM

**Description:** Department-based access control needs consistent enforcement:
- Some views may not filter by department
- API endpoints may return cross-department data
- Reporting doesn't respect department boundaries

**Recommendation:**
```python
class DepartmentScopedQuerySet(QuerySet):
    """Auto-filter by user's department(s)"""
    def for_request(self, request):
        user = request.user
        tenant_user = TenantUser.objects.get(user=user, tenant=request.tenant)

        if user.is_superuser or tenant_user.role in ('owner', 'admin'):
            return self  # No filtering for admins

        if tenant_user.department:
            return self.filter(department=tenant_user.department)

        return self  # HR managers without department see all
```

#### Issue 3: Object Ownership Verification
**Severity:** MEDIUM

**Description:** Some objects (Jobs, Candidates, etc.) need ownership checks:
- Recruiter A creates Job but Recruiter B modifies it
- Lack of explicit ownership tracking
- No clear "author/creator" field

**Recommendation:**
```python
class OwnedModel(models.Model):
    """Mixin for owned objects"""
    created_by = ForeignKey(User, on_delete=PROTECT)
    modified_by = ForeignKey(User, on_delete=SET_NULL, null=True)
    created_at = DateTimeField(auto_now_add=True)
    modified_at = DateTimeField(auto_now=True)

    class Meta:
        abstract = True
```

#### Issue 4: Permission Cache Invalidation
**Severity:** LOW

**Description:** Permission changes need cache invalidation:
- User role changed but permission cache not cleared
- Custom permissions added but cached
- Stale permissions after role change

**Recommendation:**
```python
from django.core.cache import cache

def change_user_role(user, tenant, new_role):
    # ... change role ...

    # Invalidate permission cache
    cache.delete(f"user_permissions_{user.id}_{tenant.id}")

    # Force re-evaluation on next request
```

#### Issue 5: Viewer Role Write Protection
**Severity:** MEDIUM

**Description:** Viewer role should be truly read-only:
- Need comprehensive test of all write endpoints
- DELETE operations should be explicitly blocked
- Even view-level updates need protection

**Recommendation:**
```python
class ViewerProtectedMixin:
    """Ensure viewer users cannot write"""
    def dispatch(self, request, *args, **kwargs):
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            tenant_user = TenantUser.objects.get(
                user=request.user,
                tenant=request.tenant
            )
            if tenant_user.role == 'viewer':
                raise PermissionDenied("Viewer users are read-only")

        return super().dispatch(request, *args, **kwargs)
```

### 📋 RECOMMENDATIONS

#### 1. Add Role Transition Validation
```python
# Define valid role transitions
VALID_ROLE_TRANSITIONS = {
    'employee': ['viewer', 'hiring_manager'],
    'viewer': ['employee'],
    'recruiter': ['hiring_manager', 'hr_manager'],
    # ... etc
}

def validate_role_transition(old_role, new_role):
    return new_role in VALID_ROLE_TRANSITIONS.get(old_role, [])
```

#### 2. Comprehensive Department Access Tests
```python
# Test that all endpoints respect department boundaries
# Test cross-department data visibility
# Test department-level reporting
```

#### 3. API Endpoint Audit
```bash
# Generate list of all API endpoints
python manage.py generate_endpoint_report

# Check each endpoint for:
# 1. Authentication requirement
# 2. Role permission check
# 3. Tenant filtering
# 4. Department filtering (if applicable)
# 5. Object-level permission check
```

#### 4. Add Permission Override Logs
```python
# Log when permissions are overridden
# Log when admin accesses user data
# Log when user role is changed
# Log when permissions are revoked
```

#### 5. Implement Permission Preview
```python
# Before applying role change, preview what access changes
def preview_role_change(user, tenant, new_role):
    current_permissions = get_user_permissions(user, tenant)
    new_permissions = get_role_permissions(new_role)

    return {
        'added': new_permissions - current_permissions,
        'removed': current_permissions - new_permissions,
        'unchanged': current_permissions & new_permissions,
    }
```

---

## Testing Summary

### Test Coverage Recommendations

| Component | Priority | Coverage Goal |
|-----------|----------|---|
| Role Assignment | CRITICAL | 100% |
| Permission Checks | CRITICAL | 100% |
| Tenant Isolation | CRITICAL | 100% |
| Department Access | HIGH | 95% |
| API Authorization | CRITICAL | 100% |
| View Authorization | CRITICAL | 100% |
| Object Ownership | HIGH | 95% |
| Role Transitions | MEDIUM | 90% |
| Permission Cache | MEDIUM | 85% |
| Audit Logging | MEDIUM | 80% |

### Critical Tests (Must Pass)

✓ User cannot access data from different tenant
✓ Viewer cannot create/modify/delete
✓ Employee cannot manage users
✓ Admin cannot become owner
✓ Permission checks working on all endpoints
✓ Department boundaries enforced
✓ Deactivated users denied access

---

## Conclusion

The Zumodra RBAC system is **well-architected** with:
- Clear role definitions
- Strong multi-tenant isolation
- Flexible permission system
- Good security foundations

**Recommended actions:**
1. Execute comprehensive RBAC tests (provided in test suite)
2. Address medium-severity issues identified
3. Implement recommended enhancements
4. Maintain regular permission audits

---

