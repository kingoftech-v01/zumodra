# Zumodra Multi-Tenant Architecture - CORRECTED

**Last Updated**: 2026-01-10
**Architecture Version**: 2.0 (Hybrid B2B/B2B2C Marketplace)

---

## Executive Summary

Zumodra is a **multi-tenant B2B/B2B2C platform** combining HRIS, ATS, freelance marketplace, and messaging with **schema-based tenant isolation**. The platform supports two distinct tenant types:

1. **COMPANY tenants**: Organizations that can hire employees, create job postings, and offer services
2. **FREELANCER tenants**: Solo service providers (single-user) who cannot create jobs or hire employees

**Key Architectural Principle**: Identity, reputation, and billing are **global** in the public schema, while all operational data (HR, ATS, marketplace activity) is **isolated per tenant** in separate PostgreSQL schemas.

---

## Core Concepts

### Tenant Types

Zumodra supports **two tenant types** with distinct capabilities:

| Feature | COMPANY | FREELANCER |
|---------|---------|------------|
| **Create job postings (ATS)** | ✅ Yes | ❌ No |
| **Create services** | ✅ Yes | ✅ Yes |
| **Have multiple employees** | ✅ Yes | ❌ No (single-user only) |
| **Publish to marketplace** | ✅ Yes | ✅ Yes |
| **Send employee invitations** | ✅ Yes | ❌ No |
| **Public career page** | ✅ Yes | ❌ No |
| **Dedicated services page** | ✅ Yes | ✅ Yes |
| **Switch tenant type** | ✅ Can become FREELANCER (if ≤1 member) | ✅ Can become COMPANY |

### Tenant-Specific Public Pages

Each tenant type has different public-facing pages:

**COMPANY Tenants**:
- ✅ Public career page: `careers.{tenant-slug}.zumodra.com` or `{tenant-slug}.zumodra.com/careers/`
- ✅ Public services page: `{tenant-slug}.zumodra.com/services/`
- ✅ Service detail pages: `{tenant-slug}.zumodra.com/services/{service-slug}/`

**FREELANCER Tenants**:
- ❌ NO career page (freelancers cannot create jobs)
- ✅ Public services page: `{tenant-slug}.zumodra.com/services/`
- ✅ Service detail pages: `{tenant-slug}.zumodra.com/services/{service-slug}/`

### User Lifecycle (CORRECTED)

**Standalone User** (No Tenant):
- Has global profile with `cv_verified`, `kyc_verified` status
- Can browse public marketplace
- Can hire services personally (creates user's primary tenant on first hire)

**User Creates Freelancer Tenant**:
- Single-user organization (solo freelancer)
- Can create and publish services
- Cannot create jobs or hire employees
- Has dedicated services page (no career page)

**User Joins Company Tenant**:
- Receives invitation with assigned role (owner, admin, hr_manager, recruiter, employee, viewer)
- Can access company's ATS, HR, and services features (based on role)
- Company has both career page and services page

**Tenant Type Switching**:
- **Company → Freelancer**: Only if ≤1 active member (must remove all employees first)
- **Freelancer → Company**: Can switch anytime (becomes multi-user organization)

---

## Data Placement & Schema Architecture

### PUBLIC Schema (Cross-Tenant Data)

**Global Identity & Reputation**:
- `CustomUser` - User accounts with authentication
- `UserProfile` - Personal information
- `KYCVerification` - Identity verification (global, not tenant-specific)
- `TrustScore` - Reputation system (follows user across tenants)

**User Verification (Global)**:
- `cv_verified` - CV/professional credentials verified
- `kyc_verified` - Identity (KYC) verified
- Verification is **user-level**, not tenant-level

**Tenant Management**:
- `Tenant` - Tenant definitions with `tenant_type` (COMPANY or FREELANCER)
- `Domain` - Tenant domain mappings
- `TenantUser` - User↔Tenant membership with roles
- `TenantInvitation` - Invitations to join tenants (COMPANY only)
- `Plan` - Subscription plans
- `TenantUsage` - Resource usage tracking

**Tenant Verification (Organization-Level)**:
- `ein_number` - EIN/business registration number
- `ein_verified` - Business number verified via API
- Verification is **tenant-level**, not user-level

**Public Marketplace Catalog**:
- `PublicServiceCatalog` - Denormalized read model of all public services
- Synced via Django signals from tenant schemas
- Enables public homepage and marketplace browsing without cross-schema queries

**Billing & Payments**:
- `Subscription` - Active subscriptions
- `Invoice` - Billing records
- `PaymentMethod` - Stored payment methods (Stripe)

### TENANT Schemas (Per-Organization Data)

**COMPANY Tenants** (Full Feature Set):

**HR Core** (COMPANY only):
- `Employee` - Employee records
- `TimeOffType` - PTO types
- `TimeOffRequest` - Time-off requests
- `OnboardingTemplate` - Employee onboarding

**ATS (Applicant Tracking)** (COMPANY only):
- `JobPosting` - Job listings
- `JobCategory` - Job categories
- `Pipeline` - Hiring pipeline
- `PipelineStage` - Pipeline stages
- `Candidate` - Job applicants
- `Application` - Job applications
- `Interview` - Interview schedules
- `Offer` - Job offers

**Services Marketplace** (Both COMPANY and FREELANCER):
- `ServiceProvider` - Service providers
- `ServiceCategory` - Service categories
- `Service` - Service listings
- `ServiceRequest` - Internal service requests
- `ServiceProposal` - Proposals
- `ServiceContract` - Active contracts
- `ContractMilestone` - Contract milestones

**Cross-Tenant Requests** (Both):
- `CrossTenantServiceRequest` - Requests from other tenants
- Includes `hiring_context` field (ORGANIZATIONAL or PERSONAL)

**Finance** (Both):
- `EscrowTransaction` - Escrowed payments
- `Payout` - Provider payouts

**Messaging** (Both):
- `Conversation` - Message threads
- `Message` - Individual messages

**FREELANCER Tenants** (Limited Feature Set):
- ❌ NO HR Core models (no employees)
- ❌ NO ATS models (no job postings)
- ✅ Services Marketplace (can create and sell services)
- ✅ Cross-Tenant Requests (can receive service requests)
- ✅ Finance (escrow, payouts)
- ✅ Messaging

---

## Tenant Type Enforcement

### Model-Level Validation

**File**: `tenants/validators.py`

```python
def validate_company_can_create_jobs(tenant):
    """Only COMPANY tenants can create job postings."""
    if tenant.tenant_type == 'freelancer':
        raise ValidationError(
            'Freelancer tenants cannot create job postings. Switch to Company type first.'
        )

def validate_company_can_receive_invitations(tenant):
    """Only COMPANY tenants can receive employee invitations."""
    if tenant.tenant_type == 'freelancer':
        raise ValidationError(
            'Freelancer tenants cannot receive employee invitations. Only companies can have employees.'
        )

def validate_freelancer_members(tenant):
    """Freelancer tenants must have exactly 1 member."""
    if tenant.tenant_type == 'freelancer':
        active_members = tenant.members.filter(is_active=True).count()
        if active_members > 1:
            raise ValidationError(
                'Freelancer tenants cannot have more than one member.'
            )
```

### API-Level Enforcement

**File**: `ats/views.py` (JobPostingViewSet)

```python
def perform_create(self, serializer):
    # TENANT TYPE VALIDATION: Only COMPANY tenants can create jobs
    from tenants.validators import validate_company_can_create_jobs
    from django.core.exceptions import ValidationError

    try:
        validate_company_can_create_jobs(self.request.tenant)
    except ValidationError as e:
        from rest_framework.exceptions import PermissionDenied
        raise PermissionDenied(str(e))

    instance = serializer.save(created_by=self.request.user)
```

### UI-Level Enforcement

**File**: `templates/components/sidebar.html`

```django
<!-- ATS Section (COMPANY TENANTS ONLY) -->
{% if request.tenant.tenant_type == 'company' %}
<div x-data="{ open: expandedMenus.ats || activeSection.startsWith('ats') }">
    <!-- ATS menu items -->
</div>
{% endif %}

<!-- HR Section (COMPANY TENANTS ONLY) -->
{% if request.tenant.tenant_type == 'company' %}
<div x-data="{ open: expandedMenus.hr || activeSection.startsWith('hr') }">
    <!-- HR menu items -->
</div>
{% endif %}
```

---

## Hiring Contexts

### Personal vs Organizational Hiring

Users can hire services in **two contexts**:

**ORGANIZATIONAL Hiring** (Default):
- User hiring on behalf of their tenant/organization
- Request lives in requesting tenant's schema
- Contract created in requesting tenant's schema
- Invoice/billing goes to tenant
- Example: Company A hires Freelancer B for a project

**PERSONAL Hiring**:
- User hiring for themselves (personal use)
- Request lives in user's primary tenant schema (or creates one)
- Contract created in user's primary tenant schema
- Invoice/billing goes to user
- Example: Individual user hires Freelancer B for personal project

**Model Field**: `CrossTenantServiceRequest.hiring_context`

```python
class CrossTenantServiceRequest(TenantAwareModel):
    class HiringContext(models.TextChoices):
        ORGANIZATIONAL = 'organizational', 'On behalf of tenant/organization'
        PERSONAL = 'personal', 'Personal user hiring'

    hiring_context = models.CharField(
        max_length=20,
        choices=HiringContext.choices,
        default=HiringContext.ORGANIZATIONAL,
        db_index=True
    )
```

---

## Verification System

### Two-Level Verification

**User-Level Verification (Global)**:
- `cv_verified`: CV/professional credentials verified
- `kyc_verified`: Identity (KYC) verified
- Stored on `CustomUser` model in PUBLIC schema
- Follows user across all tenants
- Displayed as badges on user profile

**Tenant-Level Verification (Organization)**:
- `ein_number`: EIN/business registration number
- `ein_verified`: Business verified via external API
- Stored on `Tenant` model in PUBLIC schema
- Specific to each organization
- Displayed on tenant/company profile

### Trust Score System

**Global Trust Score**:
- Lives in PUBLIC schema
- Follows user across tenants
- Includes: identity_score, career_score, activity_score
- Visible to all organizations considering hiring this user

---

## Public Marketplace Architecture

### PublicServiceCatalog (Read Model)

**Problem**: Services live in TENANT schemas, but public homepage runs in PUBLIC schema.

**Solution**: Denormalized catalog synced via Django signals.

**Sync Flow**:
```
TENANT SCHEMA                    PUBLIC SCHEMA
┌──────────────┐                ┌─────────────────────┐
│ Service      │  post_save     │ PublicServiceCatalog│
│ is_public=T  │  ────────────> │ (denormalized)      │
│ provider     │  signal        │ - service_uuid      │
└──────────────┘                │ - tenant_schema     │
                                 │ - price (denorm)    │
                                 │ - rating (denorm)   │
                                 └─────────────────────┘
```

**Signal Handler** (`services/signals.py`):
- Triggered on `Service.save()` when `is_public=True`
- Creates/updates `PublicServiceCatalog` entry
- Deletes catalog entry when service becomes private or inactive
- Validates `provider.marketplace_enabled=True`

**Benefits**:
- ✅ No cross-schema JOINs (performance)
- ✅ Django ORM works naturally (no raw SQL)
- ✅ Aggressive caching possible (read model)
- ✅ Clear security separation

---

## Tenant Routing & Domain Strategy

### Domain Patterns

**PUBLIC Domain** (No Tenant Context):
- `zumodra.com` - Public homepage, marketplace browse
- `www.zumodra.com` - Marketing site
- `api.zumodra.com/api` - REST API
- `admin.zumodra.com` - Platform admin

**COMPANY Tenant Domains**:
- `{slug}.zumodra.com` - Main tenant dashboard
- `{slug}.zumodra.com/careers/` - Public career page (job board)
- `{slug}.zumodra.com/services/` - Public services page
- `{slug}.zumodra.com/services/{service-slug}/` - Service detail
- `careers.{slug}.zumodra.com` - Dedicated career subdomain (optional)

**FREELANCER Tenant Domains**:
- `{slug}.zumodra.com` - Main tenant dashboard
- `{slug}.zumodra.com/services/` - Public services page
- `{slug}.zumodra.com/services/{service-slug}/` - Service detail
- ❌ NO career page/subdomain

### Routing Middleware

`django-tenants` middleware:
1. Extracts subdomain from request (`{slug}.zumodra.com`)
2. Looks up `Tenant` by domain
3. Sets `connection.schema_name` to tenant's schema
4. All subsequent ORM queries scoped to that schema

---

## Security & IAM

### Schema Isolation

**Primary Security Mechanism**:
- Each tenant has isolated PostgreSQL schema
- Schema-level RLS (Row-Level Security)
- Once schema is set, all queries automatically scoped
- No cross-tenant data leakage possible

### Role-Based Access Control (RBAC)

**Tenant Roles** (via `TenantUser.role`):
- `OWNER` (PDG): Full access, billing, tenant settings
- `ADMIN`: All features except billing
- `HR_MANAGER`: HR + employee management
- `RECRUITER`: ATS + recruiting
- `HIRING_MANAGER`: View jobs, review candidates
- `EMPLOYEE`: Limited access to own data
- `VIEWER`: Read-only access

**Freelancer Tenant Roles**:
- Only `OWNER` role (single-user)
- Cannot assign other roles (no invitations)

### Invitation System

**TenantInvitation Model**:
```python
class TenantInvitation(models.Model):
    tenant = models.ForeignKey(Tenant)
    email = models.EmailField()
    assigned_role = models.CharField(
        max_length=20,
        choices=TenantUser.UserRole.choices,
        default=TenantUser.UserRole.EMPLOYEE
    )

    def clean(self):
        # Freelancers cannot send invitations
        if self.tenant.tenant_type == 'freelancer':
            raise ValidationError(
                'Freelancer tenants cannot invite employees.'
            )
```

**Invitation Flow**:
1. COMPANY sends invitation with assigned role
2. User receives email with unique token
3. User accepts invitation
4. `TenantUser` created with specified role
5. User can now access company tenant

---

## Marketplace Flows

### Cross-Tenant Service Request

**Scenario**: Company A wants to hire Freelancer B's service

**Flow**:
1. User from Company A browses `PublicServiceCatalog` (public schema)
2. Finds Freelancer B's service
3. Creates `CrossTenantServiceRequest` in Company A's schema
4. Async Celery task notifies Freelancer B (in their schema)
5. Freelancer B reviews request in their dashboard
6. If accepted, creates `ServiceContract` in Company A's schema
7. Work proceeds, escrow released, payout to Freelancer B

**Key Point**: Request lives in REQUESTING tenant's schema (Company A), not provider's schema.

### Personal Hiring Flow

**Scenario**: Individual user wants to hire Freelancer B

**Flow**:
1. User (not in any tenant) browses public marketplace
2. Finds Freelancer B's service
3. Selects "Hire for myself" (hiring_context=PERSONAL)
4. System creates user's primary tenant (if doesn't exist)
5. Creates `CrossTenantServiceRequest` in user's tenant schema
6. Rest of flow same as organizational hiring

---

## Tenant Type Switching

### Company → Freelancer

**Requirements**:
- Must have ≤1 active member (remove all employees first)
- All job postings will be closed/archived
- HR data (employees, time-off) will be inaccessible
- ATS data will be archived (not deleted)

**Code**:
```python
def switch_to_freelancer(self):
    if self.members.filter(is_active=True).count() > 1:
        raise ValidationError(
            "Cannot switch to freelancer with multiple members."
        )
    self.tenant_type = self.TenantType.FREELANCER
    self.save(update_fields=['tenant_type'])
```

### Freelancer → Company

**Requirements**:
- No restrictions (can switch anytime)
- Can now create jobs, hire employees
- Career page becomes available

**Code**:
```python
def switch_to_company(self):
    self.tenant_type = self.TenantType.COMPANY
    self.save(update_fields=['tenant_type'])
```

---

## API Integration

### Tenant Type in API Responses

**Tenant Serializer**:
```python
class TenantSerializer(serializers.ModelSerializer):
    can_create_jobs = serializers.SerializerMethodField()
    can_have_employees = serializers.SerializerMethodField()

    class Meta:
        model = Tenant
        fields = [
            'uuid', 'name', 'slug', 'tenant_type',
            'ein_number', 'ein_verified', 'ein_verified_at',
            'can_create_jobs', 'can_have_employees'
        ]
        read_only_fields = ['ein_verified', 'ein_verified_at']

    def get_can_create_jobs(self, obj):
        return obj.can_create_jobs()

    def get_can_have_employees(self, obj):
        return obj.can_have_employees()
```

### Webhook Payloads

**Tenant Events**:
```json
{
  "event": "tenant.updated",
  "tenant": {
    "uuid": "...",
    "name": "Acme Corp",
    "tenant_type": "company",
    "ein_verified": true,
    "can_create_jobs": true
  }
}
```

---

## Migration Path

### For Existing Tenants

**Default Behavior**:
- All existing tenants default to `tenant_type='company'`
- No data loss
- All features remain available

**Manual Migration** (if tenant should be freelancer):
1. Remove all members except owner
2. Call `tenant.switch_to_freelancer()`
3. Career page disabled automatically
4. ATS features hidden in UI

### For New Signups

**Signup Flow**:
1. User chooses: "I'm a freelancer" or "I'm a company"
2. Creates tenant with appropriate `tenant_type`
3. Freelancer: Single-user setup, services only
4. Company: Multi-user setup, full features

---

## Key Differences from Previous Architecture

### ❌ WRONG (Previous Implementation)

**Freelancers as User State**:
- `CustomUser.is_available_for_hire` (WRONG)
- `CustomUser.freelancer_profile_complete` (WRONG)
- Homepage counted: `User.objects.filter(is_available_for_hire=True)` (WRONG)
- Freelancers "joined" companies as employees (WRONG)

### ✅ CORRECT (Current Architecture)

**Freelancers as Tenant Type**:
- `Tenant.tenant_type = 'freelancer'` (CORRECT)
- Homepage counts: `Tenant.objects.filter(tenant_type='freelancer')` (CORRECT)
- Freelancers are organizations (single-user) (CORRECT)
- Users can belong to both freelancer and company tenants (CORRECT)

---

## Summary

**Zumodra's hybrid multi-tenant architecture** supports two distinct organization types:

1. **COMPANY tenants**: Full-featured organizations with ATS, HR, services, and dedicated career pages
2. **FREELANCER tenants**: Solo service providers with marketplace features only (no ATS, no career page)

**Key architectural principles**:
- ✅ Schema-based isolation for data security
- ✅ Global identity and reputation (user-level)
- ✅ Tenant-level verification (organization-level)
- ✅ Denormalized public catalog for performance
- ✅ Signal-based synchronization
- ✅ Support for personal and organizational hiring
- ✅ RBAC with role assignment on invitations
- ✅ Bidirectional tenant type switching

**Critical insight**: Freelancers are NOT users available for hire - they are **single-user organizations** that provide services in the marketplace, with limited features compared to companies.
