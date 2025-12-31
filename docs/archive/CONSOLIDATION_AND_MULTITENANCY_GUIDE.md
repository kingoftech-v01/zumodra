# Consolidation & Multi-Tenancy Implementation Guide

**Date:** December 25, 2025
**Status:** Implementation Guide

---

## Executive Summary

This guide addresses the remaining architectural issues in your Zumodra platform:

1. ✅ **Newsletter Consolidation** - NO DUPLICATES FOUND
   - Only `newsletter/` app exists (django-newsletter package)
   - `leads/` and `marketing/` apps DO NOT exist in codebase
   - **Action:** None needed

2. ✅ **Empty Apps Removal** - ALREADY COMPLETED
   - `jobs/` app - Already deleted
   - `projects/` app - Already deleted
   - **Action:** None needed

3. ⚠️ **Dashboard with Real Data** - NEEDS IMPLEMENTATION
   - Current: 50+ views with no QuerySets (static templates)
   - Required: Dynamic data from existing features
   - **Action:** Implement QuerySets (detailed below)

4. ⚠️ **Multi-Tenancy** - NEEDS ARCHITECTURE DECISION
   - Current: django_tenants infrastructure exists but disabled
   - Required: Two user types (public users vs company employees)
   - **Action:** Enable & configure properly (detailed below)

---

## Part 1: Dashboard Implementation with QuerySets

### Current State
[dashboard/views.py](dashboard/views.py) has 50+ views like:
```python
def dashboard_view(request):
    return render(request, 'dashboard.html')  # NO DATA!
```

### Architecture Decision

Based on CLAUDE.md and your requirements:
- **Public Users**: Job seekers, service clients (no tenant)
- **Company Employees**: Part of a tenant/company, access company dashboard
- **Service Providers**: Can be public or part of company

### Recommended Implementation

Create **TWO** dashboard systems:

#### 1. Public User Dashboard
**File:** `dashboard/views.py` → `public_dashboard_view()`

```python
from django.contrib.auth.decorators import login_required
from services.models import DService, DServiceRequest, DServiceContract
from appointment.models import Appointment
from finance.models import Payment, Subscription
from notifications.models import Notification

@login_required
def public_dashboard_view(request):
    """Dashboard for public users (non-company)"""

    # User's service requests
    my_requests = DServiceRequest.objects.filter(client=request.user)
    open_requests = my_requests.filter(is_open=True).count()

    # User's contracts (as client)
    my_contracts = DServiceContract.objects.filter(client=request.user)
    active_contracts = my_contracts.filter(status='active').count()
    completed_contracts = my_contracts.filter(status='completed').count()

    # If user is also a provider
    provider_stats = None
    if hasattr(request.user, 'DService_provider_profile'):
        provider = request.user.DService_provider_profile
        provider_stats = {
            'total_services': provider.DServices_offered_by_provider.count(),
            'rating': provider.rating_avg,
            'completed_jobs': provider.completed_jobs_count,
        }

    # Appointments
    upcoming_appointments = Appointment.objects.filter(
        user=request.user,
        start_time__gte=timezone.now()
    ).order_by('start_time')[:5]

    # Recent notifications
    recent_notifications = Notification.objects.filter(
        recipient=request.user,
        is_read=False
    )[:10]

    # Finance (if applicable)
    payments = Payment.objects.filter(user=request.user).order_by('-created_at')[:5]

    context = {
        'user_type': 'public',
        'my_requests': my_requests[:5],
        'open_requests': open_requests,
        'active_contracts': active_contracts,
        'completed_contracts': completed_contracts,
        'provider_stats': provider_stats,
        'upcoming_appointments': upcoming_appointments,
        'recent_notifications': recent_notifications,
        'recent_payments': payments,
    }

    return render(request, 'dashboard/public_dashboard.html', context)
```

#### 2. Company/Tenant Dashboard
**File:** `dashboard/views.py` → `company_dashboard_view()`

```python
from django_tenants.utils import get_tenant_model, tenant_context

@login_required
def company_dashboard_view(request):
    """Dashboard for company employees (tenant users)"""

    # Get current tenant
    tenant = request.tenant if hasattr(request, 'tenant') else None

    if not tenant:
        # User is not in a company
        return redirect('public_dashboard')

    # Company-wide stats
    # All employees in this company
    company_employees = User.objects.filter(company=tenant.company).count()

    # Company services (if company offers services)
    company_services = DService.objects.filter(provider__company=tenant.company)

    # Company contracts
    company_contracts = DServiceContract.objects.filter(
        Q(provider__company=tenant.company) | Q(client__company=tenant.company)
    )

    # Company appointments
    company_appointments = Appointment.objects.filter(
        user__company=tenant.company
    )

    # Company revenue (from finance app)
    company_revenue = company_contracts.filter(
        status='completed'
    ).aggregate(total=Sum('agreed_rate'))['total'] or 0

    # Recent activity (company-wide)
    recent_actions = UserAction.objects.filter(
        user__company=tenant.company
    ).order_by('-timestamp')[:20]

    context = {
        'user_type': 'company',
        'tenant': tenant,
        'company': tenant.company,
        'company_employees': company_employees,
        'company_services': company_services.count(),
        'company_contracts': company_contracts.count(),
        'active_contracts': company_contracts.filter(status='active').count(),
        'company_revenue': company_revenue,
        'recent_appointments': company_appointments.order_by('-start_time')[:10],
        'recent_actions': recent_actions,
    }

    return render(request, 'dashboard/company_dashboard.html', context)
```

#### 3. Smart Dashboard Router
**File:** `dashboard/views.py` → `dashboard_view()`

```python
@login_required
def dashboard_view(request):
    """
    Smart router: directs to public or company dashboard based on user context
    """
    # Check if user belongs to a company/tenant
    if hasattr(request, 'tenant') and request.tenant:
        return company_dashboard_view(request)
    elif hasattr(request.user, 'company') and request.user.company:
        # User has company but not in tenant context
        return company_dashboard_view(request)
    else:
        # Public user
        return public_dashboard_view(request)
```

---

## Part 2: Multi-Tenancy Architecture

### Understanding Your Requirements

From CLAUDE.md and your description:

**Two Types of Users:**

1. **Public Users** (No Tenant)
   - Job seekers
   - Service clients
   - Individual service providers
   - Can browse, book, hire
   - Once hired by company → becomes employee (gets tenant)

2. **Company Users** (Tenant Members)
   - Company employees
   - Access company dashboard
   - Part of "circular" (company workspace)
   - Company-specific data isolation

### django-tenants Architecture

```
Database Structure:
├── public schema (shared)
│   ├── Tenant model (companies)
│   ├── Domain model (subdomains)
│   └── Shared tables
└── tenant schemas (one per company)
    ├── Company-specific users
    ├── Company-specific services
    ├── Company-specific contracts
    └── Company-specific data
```

### Implementation Steps

#### Step 1: Enable django-tenants in Settings

**File:** [zumodra/settings.py](zumodra/settings.py)

Find the commented django_tenants middleware and uncomment it:

```python
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',  # UNCOMMENT THIS
    'django.middleware.security.SecurityMiddleware',
    # ... rest of middleware
]
```

Add database router:

```python
DATABASE_ROUTERS = [
    'django_tenants.routers.TenantSyncRouter',
]
```

#### Step 2: Define Shared vs Tenant Apps

```python
SHARED_APPS = [
    'django_tenants',  # Must be first
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    # ... admin, etc.

    # Your shared apps (accessible by all)
    'main',  # Tenant model
    'custom_account_u',  # User model
    'newsletter',  # Shared newsletters
    'api',  # API (shared)
]

TENANT_APPS = [
    # Apps that should be tenant-specific
    'services',  # Company services
    'configurations',  # Company-specific configs
    'finance',  # Company finances
    'appointment',  # Company appointments
    'dashboard',  # Company dashboards
    'analytics',  # Company analytics
    'notifications',  # Tenant notifications
]

INSTALLED_APPS = list(SHARED_APPS) + [
    app for app in TENANT_APPS if app not in SHARED_APPS
]
```

#### Step 3: Tenant Model Configuration

**File:** [main/models.py](main/models.py)

Your Tenant model should look like:

```python
from django_tenants.models import TenantMixin, DomainMixin

class Tenant(TenantMixin):
    name = models.CharField(max_length=100)
    company = models.OneToOneField(
        'configurations.Company',
        on_delete=models.CASCADE,
        related_name='tenant',
        help_text="Associated company for this tenant"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    # Auto-create schema on save
    auto_create_schema = True

    def __str__(self):
        return self.name


class Domain(DomainMixin):
    pass
```

#### Step 4: User-Tenant Association

**File:** [custom_account_u/models.py](custom_account_u/models.py)

Add to your User model:

```python
class User(AbstractBaseUser, PermissionsMixin):
    # ... existing fields ...

    # Tenant association (optional, for employees)
    company = models.ForeignKey(
        'configurations.Company',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='employees',
        help_text="Company/Tenant this user belongs to (if employee)"
    )

    is_public_user = models.BooleanField(
        default=True,
        help_text="True = public user, False = company employee"
    )

    def get_tenant(self):
        """Get user's tenant if they're a company employee"""
        if self.company and hasattr(self.company, 'tenant'):
            return self.company.tenant
        return None
```

#### Step 5: Middleware for User Tenant Detection

**Create:** `zumodra/middleware/tenant_middleware.py`

```python
from django_tenants.utils import get_tenant_model

class UserTenantMiddleware:
    """
    Attach tenant to request based on user's company
    Fallback to domain-based tenant if available
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # If user is authenticated and has company
        if request.user.is_authenticated:
            if hasattr(request.user, 'company') and request.user.company:
                tenant = request.user.company.tenant if hasattr(request.user.company, 'tenant') else None
                if tenant:
                    request.tenant = tenant

        response = self.get_response(request)
        return response
```

Add to MIDDLEWARE after TenantMainMiddleware:

```python
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',
    'zumodra.middleware.tenant_middleware.UserTenantMiddleware',
    # ... rest
]
```

#### Step 6: URL Configuration for Tenants

**File:** [zumodra/urls_tenant.py](zumodra/urls_tenant.py)

Create separate URLs for tenant-specific views:

```python
# Tenant-specific URLs (accessed via subdomain or company context)

urlpatterns = [
    path('company/dashboard/', company_dashboard_view, name='company_dashboard'),
    path('company/services/', include('services.urls')),  # Company services
    path('company/appointments/', include('appointment.urls')),
    path('company/analytics/', include('analytics.urls')),
    # ... other company-specific URLs
]
```

**File:** [zumodra/urls.py](zumodra/urls.py) (keep existing for public)

```python
# Public URLs (main domain, no tenant)

urlpatterns = [
    path('', home_view, name='home'),
    path('services/', include('services.urls')),  # Public services
    path('api/', include('api.urls')),
    # ... existing public URLs
]
```

#### Step 7: Domain Setup Examples

```python
# In Django shell or management command

from main.models import Tenant, Domain
from configurations.models import Company

# Create a company
company = Company.objects.create(
    name="Acme Corp",
    email="info@acmecorp.com"
)

# Create tenant for company
tenant = Tenant.objects.create(
    schema_name="acme",  # Database schema name
    name="Acme Corp Tenant",
    company=company
)

# Create domain
domain = Domain.objects.create(
    domain="acme.zumodra.com",  # Subdomain
    tenant=tenant,
    is_primary=True
)

# Or for development: localhost with port
domain_dev = Domain.objects.create(
    domain="localhost",
    tenant=tenant,
    is_primary=False
)
```

---

## Part 3: User Flow Examples

### Scenario 1: Public User (Job Seeker)

1. User signs up at `zumodra.com`
2. `is_public_user = True`, `company = None`
3. Accesses public dashboard at `/app/dashboard/`
4. Can browse services, create requests, hire providers
5. Applies for a job at Acme Corp
6. Gets hired!

### Scenario 2: User Becomes Employee

```python
# When user is hired
user.company = acme_company
user.is_public_user = False
user.save()

# Now user can access:
# - Public services (still available)
# - Company dashboard at acme.zumodra.com or /company/dashboard/
# - Company-specific services
```

### Scenario 3: Company Employee Login

1. Employee visits `acme.zumodra.com`
2. Tenant middleware detects subdomain → loads Acme tenant
3. User logs in
4. Dashboard router detects tenant → shows company dashboard
5. All data is tenant-isolated

---

## Part 4: Migration Strategy

### Phase 1: Prepare (Week 1)
- [ ] Backup database
- [ ] Review all models - decide which are SHARED vs TENANT
- [ ] Update settings.py with SHARED_APPS and TENANT_APPS
- [ ] Test in development

### Phase 2: Enable Tenants (Week 2)
- [ ] Uncomment django_tenants middleware
- [ ] Run migrations: `python manage.py migrate_schemas --shared`
- [ ] Create first tenant for testing
- [ ] Test tenant creation

### Phase 3: Migrate Data (Week 3)
- [ ] For each company in configurations.Company:
  - Create Tenant
  - Create Domain
  - Migrate company-specific data to tenant schema
- [ ] Associate users with companies
- [ ] Test data isolation

### Phase 4: Update Views (Week 4)
- [ ] Implement public_dashboard_view with QuerySets
- [ ] Implement company_dashboard_view with QuerySets
- [ ] Update all 50+ dashboard views with real data
- [ ] Create company-specific templates

### Phase 5: Testing & Deployment (Week 5)
- [ ] Test public user flow
- [ ] Test company employee flow
- [ ] Test tenant isolation
- [ ] Deploy to production

---

## Part 5: Dashboard Views with Real Data

### Update All Dashboard Views

Here's a template for each view type:

#### Services Dashboard
```python
@login_required
def candidates_applied(request):
    """Show services/jobs user has applied to"""

    # Get user's proposals
    proposals = DServiceProposal.objects.filter(
        provider__user=request.user
    ).select_related('request', 'request__client')

    pending_proposals = proposals.filter(is_accepted=False)
    accepted_proposals = proposals.filter(is_accepted=True)

    context = {
        'proposals': proposals,
        'pending_count': pending_proposals.count(),
        'accepted_count': accepted_proposals.count(),
    }
    return render(request, 'candidates-applied.html', context)
```

#### Earnings Dashboard
```python
@login_required
def candidates_earnings(request):
    """Show provider earnings"""

    # Check if user is provider
    if not hasattr(request.user, 'DService_provider_profile'):
        messages.error(request, 'You need a provider profile')
        return redirect('create_provider_profile')

    provider = request.user.DService_provider_profile

    # Get completed contracts
    contracts = DServiceContract.objects.filter(
        provider=provider,
        status='completed'
    )

    # Calculate earnings
    total_earnings = contracts.aggregate(
        total=Sum('agreed_rate')
    )['total'] or 0

    # Monthly breakdown
    monthly_earnings = contracts.annotate(
        month=TruncMonth('completed_at')
    ).values('month').annotate(
        amount=Sum('agreed_rate')
    ).order_by('-month')

    context = {
        'provider': provider,
        'total_earnings': total_earnings,
        'completed_contracts': contracts.count(),
        'monthly_earnings': monthly_earnings,
    }
    return render(request, 'candidates-earnings.html', context)
```

---

## Part 6: Quick Start Implementation

### Fastest Path to Working Dashboard

1. **Update main dashboard view** (30 minutes):
```bash
# Edit dashboard/views.py
# Replace dashboard_view() with the smart router version above
```

2. **Create public dashboard** (2 hours):
```bash
# Implement public_dashboard_view()
# Create template with real data
```

3. **Test without tenants first** (1 hour):
```bash
python manage.py runserver
# Visit /app/dashboard/
# Verify all data shows correctly
```

4. **Then enable multi-tenancy** (when ready):
```bash
# Follow Phase 1-5 above
```

---

## Summary

### What's Actually Needed

1. ✅ **Newsletter consolidation** - NOT NEEDED (no duplicates)
2. ✅ **Remove empty apps** - ALREADY DONE
3. ⚠️ **Dashboard with real data** - IMPLEMENT (use templates above)
4. ⚠️ **Multi-tenancy** - ARCHITECTURAL DECISION REQUIRED

### Recommended Approach

**Option A: Quick Win (1 week)**
- Skip multi-tenancy for now
- Implement public dashboard with QuerySets
- All users see their own data (no company isolation)
- Single database, simpler architecture

**Option B: Full Implementation (5 weeks)**
- Enable multi-tenancy
- Implement both public and company dashboards
- Full tenant isolation
- Subdomain-based or path-based routing

### My Recommendation

Start with **Option A** to get a working dashboard quickly, then migrate to **Option B** when you have:
- More companies using the platform
- Need for data isolation
- Budget for 5-week implementation

---

**All code examples and architecture patterns are provided above. You can implement any piece step by step.**
