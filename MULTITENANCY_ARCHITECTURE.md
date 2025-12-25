# Multi-Tenancy Architecture for Zumodra

This document explains the multi-tenancy architecture for Zumodra, covering both the technical implementation and the business logic for handling two distinct user types.

## Table of Contents

1. [Overview](#overview)
2. [User Types in Zumodra](#user-types-in-zumodra)
3. [Multi-Tenancy Architecture](#multi-tenancy-architecture)
4. [Implementation Strategy](#implementation-strategy)
5. [Database Schema Design](#database-schema-design)
6. [Middleware and Request Flow](#middleware-and-request-flow)
7. [Code Examples](#code-examples)
8. [Migration Path](#migration-path)
9. [Security Considerations](#security-considerations)
10. [Testing Strategy](#testing-strategy)

---

## Overview

Zumodra requires a sophisticated multi-tenancy system to handle two distinct user populations:

1. **Public Users** - Individuals using the platform independently
2. **Company Employees** - Users belonging to organizations (tenants)

The system must support:
- Public users transitioning to company employees when hired
- Company employees accessing both company-wide and personal data
- Complete data isolation between different companies
- Shared platform features (services, events, job postings) accessible to all

---

## User Types in Zumodra

### Type 1: Public Users (Non-Tenant)

**Characteristics:**
- Not associated with any company/tenant
- Access platform as individuals
- Can be job seekers, service clients, or event attendees

**User Journey:**
```
Registration → Browse Services → Request Service → Hire Provider
             → Look for Jobs → Get Hired → Become Company Employee
             → Attend Events → Subscribe to Newsletter
```

**Dashboard Access:**
- Personal service requests and contracts
- Job applications
- Event registrations
- Personal appointments
- Provider profile (if they offer services)

**Example Scenarios:**
- John is looking for a web designer (service client)
- Sarah is a freelance photographer offering services (provider)
- Mike is looking for a job (job seeker)
- Lisa wants to attend tech events (attendee)

### Type 2: Company Employees (Tenant Members)

**Characteristics:**
- Associated with a specific company/tenant
- Were previously public users who got hired
- Access both company and personal features

**User Journey:**
```
Public User → Apply for Job → Get Hired → Join Company Tenant
           → Access Company Dashboard
           → Manage Company Services
           → View Company-Wide Analytics
           → Still can use personal features
```

**Dashboard Access:**
- Company-wide service statistics
- Team member directory
- Company marketing campaigns
- Company revenue and contracts
- HR features (if admin)
- **PLUS** all personal features from public dashboard

**Example Scenarios:**
- Mike got hired by TechCorp → Now sees TechCorp's company dashboard
- As employee, Mike can still use personal services
- Mike's personal data remains separate from company data
- Mike sees company-wide stats if he has permission

---

## Multi-Tenancy Architecture

### Recommended Approach: Schema-Based Multi-Tenancy

**Why Schema-Based?**
- Complete data isolation between tenants
- Better security (tenant data in separate schemas)
- Easier compliance with data regulations
- Simpler backup/restore per tenant
- Better performance at scale

**How It Works:**
```
Database: zumodra_db
│
├── Schema: public (shared data)
│   ├── DServiceCategory (shared)
│   ├── Skills (shared)
│   ├── Events (shared, visible to all)
│   └── Job Postings (shared, visible to all)
│
├── Schema: tenant_techcorp
│   ├── Users (TechCorp employees only)
│   ├── DServiceProviderProfile (TechCorp providers)
│   ├── DServiceContracts (TechCorp contracts)
│   ├── Companies (TechCorp info)
│   └── Newsletter Campaigns (TechCorp marketing)
│
├── Schema: tenant_designco
│   ├── Users (DesignCo employees only)
│   ├── DServiceProviderProfile (DesignCo providers)
│   └── ... (DesignCo data)
│
└── Schema: public_users (non-tenant users)
    ├── Users (public users not in companies)
    ├── DServiceRequest (public user requests)
    └── DServiceProviderProfile (freelance providers)
```

### Alternative Approach: Row-Level Multi-Tenancy

Simpler but less isolated:

```python
class DServiceContract(models.Model):
    tenant = models.ForeignKey(Tenant, null=True, blank=True)  # NULL for public users
    client = models.ForeignKey(User, on_delete=models.CASCADE)
    provider = models.ForeignKey(DServiceProviderProfile, on_delete=models.CASCADE)
    # ... other fields

    class Meta:
        # Automatically filter by tenant in all queries
        default_permissions = []
```

**When to use Row-Level:**
- Smaller scale (< 50 companies)
- Simpler deployment requirements
- Less strict data isolation needs

**When to use Schema-Based:**
- Large scale (100+ companies)
- Strict data isolation required
- Regulatory compliance needed
- Multi-region deployment

---

## Implementation Strategy

### Phase 1: Preparation (Week 1)

**Goal:** Set up infrastructure without breaking existing functionality

**Tasks:**
1. Install django-tenants:
   ```bash
   pip install django-tenants
   ```

2. Update settings.py:
   ```python
   INSTALLED_APPS = [
       'django_tenants',  # Must be first
       'django.contrib.contenttypes',
       # ... other apps
   ]

   DATABASE_ROUTERS = ['django_tenants.routers.TenantSyncRouter']

   TENANT_MODEL = "companies.Company"
   TENANT_DOMAIN_MODEL = "companies.Domain"
   ```

3. Create Domain model:
   ```python
   # companies/models.py
   from django_tenants.models import TenantMixin, DomainMixin

   class Company(TenantMixin):
       name = models.CharField(max_length=100)
       created_at = models.DateTimeField(auto_now_add=True)
       # ... existing fields

       auto_create_schema = True  # Automatically create schema

   class Domain(DomainMixin):
       pass
   ```

4. Run migrations:
   ```bash
   python manage.py makemigrations
   python manage.py migrate_schemas --shared
   ```

### Phase 2: User Association (Week 2)

**Goal:** Link users to tenants when they join companies

**Tasks:**
1. Add tenant field to User model:
   ```python
   # accounts/models.py or custom user model
   class User(AbstractUser):
       company = models.ForeignKey(
           'companies.Company',
           null=True,
           blank=True,
           on_delete=models.SET_NULL,
           related_name='employees'
       )
       is_company_admin = models.BooleanField(default=False)
   ```

2. Create migration script for existing users:
   ```python
   # Migration: Associate existing users with companies
   def associate_users_with_companies(apps, schema_editor):
       User = apps.get_model('accounts', 'User')
       Company = apps.get_model('companies', 'Company')

       # Example: Associate users based on email domain
       for company in Company.objects.all():
           domain = company.domain_url
           users = User.objects.filter(email__endswith=f'@{domain}')
           users.update(company=company)
   ```

3. Update registration/hiring flow:
   ```python
   # When a user gets hired
   def hire_user(user, company):
       user.company = company
       user.save()

       # Move user's data to company schema
       with schema_context(company.schema_name):
           # Create company-specific records
           pass
   ```

### Phase 3: Middleware Setup (Week 3)

**Goal:** Automatically detect and switch to correct tenant schema

**Tasks:**
1. Configure tenant middleware:
   ```python
   # settings.py
   MIDDLEWARE = [
       'django_tenants.middleware.main.TenantMainMiddleware',
       'django.middleware.security.SecurityMiddleware',
       # ... other middleware
   ]
   ```

2. Create custom tenant detection:
   ```python
   # middleware.py
   from django_tenants.utils import schema_context

   class TenantDetectionMiddleware:
       def __init__(self, get_response):
           self.get_response = get_response

       def __call__(self, request):
           # Detect tenant from subdomain
           hostname = request.get_host().split(':')[0]
           tenant_name = hostname.split('.')[0]

           if tenant_name == 'www' or tenant_name == request.tenant.schema_name:
               # Public schema
               schema = 'public'
           else:
               # Company schema
               try:
                   company = Company.objects.get(schema_name=tenant_name)
                   schema = company.schema_name
               except Company.DoesNotExist:
                   schema = 'public'

           with schema_context(schema):
               response = self.get_response(request)

           return response
   ```

### Phase 4: Query Updates (Week 4)

**Goal:** Update all queries to be tenant-aware

**Tasks:**
1. Create tenant-aware managers:
   ```python
   # utils/managers.py
   from django.db import models
   from django_tenants.utils import get_tenant_model, schema_context

   class TenantAwareManager(models.Manager):
       def get_queryset(self):
           qs = super().get_queryset()
           # Automatically filter by current tenant
           tenant = self.model._get_current_tenant()
           if tenant and hasattr(self.model, 'tenant'):
               qs = qs.filter(tenant=tenant)
           return qs
   ```

2. Update model queries:
   ```python
   # Before
   contracts = DServiceContract.objects.filter(client=user)

   # After (automatic with TenantAwareManager)
   contracts = DServiceContract.objects.filter(client=user)  # Already filtered by tenant
   ```

### Phase 5: Testing & Deployment (Week 5)

**Goal:** Comprehensive testing and production deployment

**Tasks:**
1. Create test tenants
2. Test data isolation
3. Test user transitions (public → employee)
4. Load testing
5. Security audit
6. Production deployment

---

## Database Schema Design

### Shared Tables (Public Schema)

These tables are shared across all tenants:

```sql
-- public.DServiceCategory
-- public.Skills
-- public.Events (visible to all, but may be tenant-specific)
-- public.JobPostings (visible to all, posted by companies)
-- public.django_migrations
-- public.django_session
```

### Tenant-Specific Tables (Per-Schema)

Each company gets its own schema with these tables:

```sql
-- tenant_techcorp.users
-- tenant_techcorp.DServiceProviderProfile
-- tenant_techcorp.DServiceContract
-- tenant_techcorp.companies
-- tenant_techcorp.newsletter_campaigns
-- tenant_techcorp.payments
```

### Public Users Schema

Non-tenant users get their own schema:

```sql
-- public_users.users
-- public_users.DServiceRequest
-- public_users.DServiceProviderProfile
```

---

## Middleware and Request Flow

### Request Flow Diagram

```
User Request
    ↓
[TenantMainMiddleware]
    ↓
Detect subdomain: company1.zumodra.com
    ↓
Lookup Company by subdomain
    ↓
Set schema_name = "tenant_company1"
    ↓
[TenantDetectionMiddleware]
    ↓
Check if user belongs to tenant
    ↓
YES: Use tenant schema
NO: Use public_users schema
    ↓
[Django View Processing]
    ↓
All queries automatically use correct schema
    ↓
Response
```

### Middleware Implementation

```python
# zumodra/middleware.py
from django_tenants.utils import schema_context, get_tenant_model
from django.shortcuts import redirect

class ZumodraTenantMiddleware:
    """
    Custom tenant middleware for Zumodra.
    Handles tenant detection and user validation.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get current tenant (set by TenantMainMiddleware)
        tenant = request.tenant

        # If user is authenticated, validate tenant access
        if request.user.is_authenticated:
            user_company = getattr(request.user, 'company', None)

            # User belongs to a company
            if user_company:
                # Check if user is accessing their company's subdomain
                if tenant.schema_name != user_company.schema_name:
                    # Redirect to user's company subdomain
                    return redirect(f'https://{user_company.domain_url}{request.path}')

            # Public user accessing a company subdomain
            elif tenant.schema_name != 'public':
                # Allow read-only access to public services
                # But prevent access to company-internal pages
                if request.path.startswith('/company/'):
                    return redirect('/')

        # Process request with correct schema
        response = self.get_response(request)
        return response
```

---

## Code Examples

### Example 1: User Hiring Workflow

```python
# recruitment/views.py
from django_tenants.utils import schema_context
from companies.models import Company

@login_required
def accept_job_offer(request, offer_id):
    """
    When a public user accepts a job offer, they become a company employee.
    """
    offer = JobOffer.objects.get(id=offer_id, candidate=request.user)
    company = offer.company

    # Update user's company association
    request.user.company = company
    request.user.save()

    # Move user to company schema
    with schema_context(company.schema_name):
        # Create employee record in company schema
        Employee.objects.create(
            user=request.user,
            position=offer.position,
            start_date=timezone.now(),
        )

    # Send notification
    Notification.objects.create(
        recipient=request.user,
        notification_type='success',
        title='Welcome to the team!',
        message=f'You are now part of {company.name}',
    )

    # Redirect to company dashboard
    return redirect(f'https://{company.domain_url}/dashboard/')
```

### Example 2: Tenant-Aware Service Requests

```python
# DServices/views.py
from django_tenants.utils import get_tenant_model, schema_context

def create_service_request(request, service_uuid):
    """
    Create a service request.
    If user is in a company, request is created in company schema.
    Otherwise, created in public schema.
    """
    service = DService.objects.get(uuid=service_uuid)

    # Determine schema
    if hasattr(request.user, 'company') and request.user.company:
        schema = request.user.company.schema_name
    else:
        schema = 'public_users'

    # Create request in appropriate schema
    with schema_context(schema):
        service_request = DServiceRequest.objects.create(
            DService=service,
            client=request.user,
            description=request.POST.get('description'),
            is_open=True,
        )

    return redirect('request_detail', uuid=service_request.uuid)
```

### Example 3: Cross-Schema Queries

```python
# analytics/views.py
from django_tenants.utils import get_tenant_model, schema_context

@staff_member_required
def platform_analytics_view(request):
    """
    Admin view showing statistics across ALL tenants.
    """
    Company = get_tenant_model()
    all_companies = Company.objects.exclude(schema_name='public')

    stats = []

    for company in all_companies:
        with schema_context(company.schema_name):
            company_stats = {
                'company_name': company.name,
                'total_employees': User.objects.filter(company=company).count(),
                'total_contracts': DServiceContract.objects.count(),
                'total_revenue': DServiceContract.objects.filter(
                    status='completed'
                ).aggregate(total=Sum('agreed_rate'))['total'] or 0,
            }
            stats.append(company_stats)

    # Public users stats
    with schema_context('public_users'):
        public_stats = {
            'total_public_users': User.objects.filter(company__isnull=True).count(),
            'total_requests': DServiceRequest.objects.count(),
        }

    context = {
        'company_stats': stats,
        'public_stats': public_stats,
    }

    return render(request, 'analytics/platform_analytics.html', context)
```

### Example 4: Shared Data Access

```python
# DServices/models.py
from django_tenants.models import TenantMixin

class DServiceCategory(models.Model):
    """
    Shared across all tenants (in public schema).
    All users can see all categories.
    """
    name = models.CharField(max_length=100)
    description = models.TextField()

    class Meta:
        # This model is in the public schema
        db_table = 'public_DService_category'


class DService(models.Model):
    """
    Tenant-specific services.
    Each company has their own services.
    """
    DServiceCategory = models.ForeignKey(DServiceCategory, on_delete=models.CASCADE)
    provider = models.ForeignKey(DServiceProviderProfile, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    # ... other fields

    # Automatically filtered by tenant
    objects = TenantAwareManager()
```

---

## Migration Path

### Option A: Big Bang Migration (1 week downtime)

**When to use:** Small user base (< 1000 users), can afford downtime

**Steps:**
1. Announce maintenance window
2. Backup entire database
3. Run migration scripts
4. Create tenant schemas
5. Move user data to appropriate schemas
6. Test thoroughly
7. Go live

**Pros:** Clean, complete
**Cons:** Requires downtime

### Option B: Gradual Migration (No downtime)

**When to use:** Production system with active users

**Steps:**

**Week 1:** Deploy tenant infrastructure (middleware disabled)
```python
# settings.py
TENANT_MULTITENANCY_ENABLED = False  # Feature flag
```

**Week 2:** Create tenant schemas for companies
```bash
python manage.py create_tenant_schemas
```

**Week 3:** Dual-write to both old and new schemas
```python
# Every write operation writes to both locations
with schema_context('public'):
    DServiceContract.objects.create(...)

with schema_context(user.company.schema_name):
    DServiceContract.objects.create(...)
```

**Week 4:** Enable tenant middleware for subset of users (beta)
```python
TENANT_MULTITENANCY_ENABLED = True
TENANT_BETA_USERS = [user1.id, user2.id, ...]
```

**Week 5:** Full rollout
```python
TENANT_MULTITENANCY_ENABLED = True
# Remove dual-write logic
# Remove old schema
```

---

## Security Considerations

### 1. Data Isolation

**Risk:** User from Company A accessing Company B's data

**Mitigation:**
```python
# Middleware validation
if request.user.company != request.tenant:
    raise PermissionDenied("Access to this tenant denied")
```

### 2. Cross-Tenant Queries

**Risk:** Queries accidentally spanning multiple tenants

**Mitigation:**
```python
# Always use schema_context explicitly
with schema_context(user.company.schema_name):
    # Safe - queries only this schema
    contracts = DServiceContract.objects.all()
```

### 3. Shared Resource Access

**Risk:** Public users accessing company-only resources

**Mitigation:**
```python
class DServiceContract(models.Model):
    # Add visibility field
    is_public = models.BooleanField(default=False)

    def can_view(self, user):
        if self.is_public:
            return True
        return user.company == self.tenant
```

### 4. Subdomain Spoofing

**Risk:** Malicious subdomain creation

**Mitigation:**
```python
# Validate subdomain before creating tenant
RESERVED_SUBDOMAINS = ['www', 'admin', 'api', 'mail', 'ftp']

def create_company(name, subdomain):
    if subdomain in RESERVED_SUBDOMAINS:
        raise ValidationError("Subdomain reserved")

    if not re.match(r'^[a-z0-9-]+$', subdomain):
        raise ValidationError("Invalid subdomain format")
```

---

## Testing Strategy

### Unit Tests

```python
# tests/test_multitenancy.py
from django_tenants.test.cases import TenantTestCase
from django_tenants.utils import schema_context

class MultiTenancyTestCase(TenantTestCase):

    def test_data_isolation(self):
        """Test that Company A cannot access Company B's data"""

        # Create two companies
        company_a = Company.objects.create(name='Company A', schema_name='tenant_a')
        company_b = Company.objects.create(name='Company B', schema_name='tenant_b')

        # Create data in Company A schema
        with schema_context('tenant_a'):
            contract_a = DServiceContract.objects.create(...)

        # Try to access from Company B schema
        with schema_context('tenant_b'):
            contracts = DServiceContract.objects.all()
            self.assertEqual(contracts.count(), 0)  # Should not see Company A's data

    def test_user_transition(self):
        """Test public user becoming company employee"""

        # Create public user
        user = User.objects.create(username='john', company=None)

        # User creates request as public
        with schema_context('public_users'):
            request = DServiceRequest.objects.create(client=user, ...)

        # User gets hired
        company = Company.objects.create(name='TechCorp', schema_name='tenant_techcorp')
        user.company = company
        user.save()

        # User can now access company schema
        with schema_context('tenant_techcorp'):
            # User's company dashboard should work
            contracts = DServiceContract.objects.filter(provider__user=user)
```

### Integration Tests

```python
from django.test import Client

class TenantIntegrationTest(TenantTestCase):

    def test_subdomain_routing(self):
        """Test that subdomains route to correct tenant"""

        client = Client()

        # Access company subdomain
        response = client.get('/', HTTP_HOST='company1.zumodra.local')
        self.assertEqual(response.tenant.schema_name, 'tenant_company1')

        # Access public domain
        response = client.get('/', HTTP_HOST='www.zumodra.local')
        self.assertEqual(response.tenant.schema_name, 'public')
```

---

## Performance Optimization

### 1. Schema Connection Pooling

```python
# settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.postgresql_backend',
        'OPTIONS': {
            'MAX_CONNS': 20,  # Connection pool per schema
        }
    }
}
```

### 2. Caching Per Tenant

```python
# Cache keys include tenant schema
def get_cache_key(key, tenant):
    return f"{tenant.schema_name}:{key}"

cache.set(get_cache_key('stats', request.tenant), stats, 300)
```

### 3. Query Optimization

```python
# Use select_related for cross-schema foreign keys
contracts = DServiceContract.objects.select_related(
    'provider__user'  # Avoid N+1 queries
).all()
```

---

## Recommended Implementation Timeline

| Week | Tasks | Deliverables |
|------|-------|--------------|
| 1 | Install django-tenants, create Domain model, run migrations | Tenant infrastructure ready |
| 2 | Add company field to User, create association migration | User-tenant relationship working |
| 3 | Configure middleware, test subdomain routing | Automatic tenant detection working |
| 4 | Update queries to be tenant-aware, add managers | All queries tenant-scoped |
| 5 | Testing, security audit, deployment | Production-ready multi-tenancy |

---

## Conclusion

Multi-tenancy in Zumodra enables:
- ✅ Complete data isolation between companies
- ✅ Seamless user transition from public to employee
- ✅ Company-wide analytics and management
- ✅ Scalable architecture for growth
- ✅ Secure, compliant data handling

**Recommendation:** Start with **simple dashboard implementation** first (from DASHBOARD_IMPLEMENTATION_EXAMPLES.md), then add multi-tenancy in a second phase when the platform scales to 10+ companies.

---

**Document created**: 2025-12-25
**For**: Zumodra Multi-Tenancy Implementation
**Status**: Architecture design complete, ready for implementation
