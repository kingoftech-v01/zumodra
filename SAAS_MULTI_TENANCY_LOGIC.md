# Multi-Tenant SaaS Architecture Logic

## Overview
Zumodra uses **schema-based multi-tenancy** via `django-tenants`. This document explains which models belong in the **public schema** (shared across all tenants) versus **tenant schemas** (isolated per tenant).

## Core Principle
**Public Schema**: Data that belongs to the USER globally, regardless of which company/tenant they work for
**Tenant Schema**: Data that belongs to a specific COMPANY/ORGANIZATION

---

## Model Classification

### 🌐 PUBLIC SCHEMA (models.Model)
These models are shared across ALL tenants and stored in the public schema:

#### **User & Identity Models**
- ✅ `CustomUser` (accounts) - A person can work for multiple companies
- ✅ `UserProfile` (accounts) - User's personal profile is global
- ✅ `KYCVerification` (accounts) - Identity verification is GLOBAL
  - **Why**: If a user is identity-verified, that verification applies everywhere
  - A user verified once doesn't need to re-verify for each company
- ✅ `TrustScore` (accounts) - Trust reputation is GLOBAL
  - **Why**: A user's trust score follows them across all platforms/tenants
  - Prevents malicious users from getting a "clean slate" in each tenant
- ✅ `TenantUser` (accounts) - Maps users to tenants with roles
- ✅ `Tenant` (tenants) - The tenant/organization itself

#### **Subscription & Billing** (Public Schema)
- ✅ `SubscriptionPlan` (finance) - Plans are the same for all tenants
- ✅ `TenantSubscription` (finance) - Which plan each tenant has

---

### 🏢 TENANT SCHEMA (TenantAwareModel)
These models are isolated PER TENANT and stored in each tenant's schema:

#### **HR & Employee Management**
- ❌ ~~Employee (models.Model)~~ → ✅ **Should inherit from TenantAwareModel**
  - **Why**: Employee records are specific to EACH COMPANY
  - Same person can be employee at multiple companies (different Employee records)

- ❌ ~~TimeOffType (models.Model)~~ → ✅ **Should inherit from TenantAwareModel**
  - **Why**: Each company has its own PTO policies
  - Company A: 15 days PTO, Company B: unlimited PTO

- ❌ ~~TimeOffRequest (models.Model)~~ → ✅ **Should inherit from TenantAwareModel**
  - **Why**: Time-off requests are for a specific company's employee

#### **ATS (Applicant Tracking System)**
- ✅ `JobPosting` - Jobs belong to a specific company
- ✅ `JobCategory` - Each company can have its own job categories
- ✅ `Pipeline` - Hiring pipeline is company-specific
- ✅ `PipelineStage` - Custom stages per company
- ✅ `Candidate` - Candidates apply to specific companies
- ✅ `Application` - Applications are per job/company
- ✅ `Interview` - Interviews are company-specific
- ✅ `Offer` - Job offers from specific companies

#### **Freelance Marketplace**
- ✅ `ServiceProvider` - Providers can offer services to specific tenants
- ✅ `ServiceCategory` - Each tenant can have custom service categories
- ✅ `Service` - Services are listed per tenant
- ✅ `ServiceRequest` - Requests within a tenant
- ✅ `Proposal` - Proposals for tenant-specific requests
- ✅ `Contract` - Contracts between parties in a tenant

#### **Messaging**
- ✅ `Conversation` - Conversations within a tenant
- ✅ `Message` - Messages within tenant conversations

---

## Real-World Example

### Scenario: John Doe works for 2 companies

**Public Schema (Shared)**:
```
CustomUser: john.doe@email.com
UserProfile: Phone: +1234567890, Bio: "Software Engineer"
KYCVerification: Status=VERIFIED, Level=ENHANCED
TrustScore: Score=95/100, Level=HIGH
```

**Tenant: "Acme Corp" (tenant_id=1)**:
```
Employee:
  - employee_id: "EMP-001"
  - user: john.doe@email.com
  - job_title: "Senior Developer"
  - hire_date: 2020-01-15
  - base_salary: $120,000
  - pto_balance: 15 days

TimeOffType (Acme's policies):
  - PTO: 15 days/year
  - Sick: 10 days/year

TimeOffRequest:
  - employee: EMP-001
  - type: PTO
  - dates: Dec 20-31
  - status: APPROVED
```

**Tenant: "TechStart Inc" (tenant_id=2)**:
```
Employee:
  - employee_id: "TS-042"
  - user: john.doe@email.com
  - job_title: "Consultant"
  - hire_date: 2023-06-01
  - hourly_rate: $75/hour
  - pto_balance: 0 (contract worker)

TimeOffType (TechStart's policies):
  - Unlimited PTO
  - No sick leave tracking

TimeOffRequest:
  - (none - unlimited policy)
```

**Key Points**:
- John's KYC and TrustScore are the SAME in both tenants (public schema)
- John has DIFFERENT employee records in each tenant (tenant schema)
- Each company has its OWN time-off policies (tenant schema)

---

## Why This Matters

### ✅ Benefits of Proper Separation

1. **Data Isolation**: Company A cannot see Company B's HR data
2. **Custom Policies**: Each tenant can have different PTO policies, categories, etc.
3. **Global Identity**: Users don't re-verify identity for each tenant
4. **Trust Continuity**: Bad actors can't escape their reputation
5. **Scalability**: Add new tenants without affecting existing ones

### ❌ Problems if Wrong Classification

**If Employee was Public Schema**:
- ❌ All companies would see all employees
- ❌ Couldn't have same user as employee in 2 companies
- ❌ Security breach: data leakage between tenants

**If KYCVerification was Tenant Schema**:
- ❌ User would need to verify identity for EACH company
- ❌ Annoying UX: "verify your ID again for this company"
- ❌ Bad actors could bypass verification by joining new tenants

---

## Database Structure

### Public Schema (1 database)
```sql
-- Shared by ALL tenants
public.custom_account_u_customuser
public.accounts_userprofile
public.accounts_kycverification
public.accounts_trustscore
public.tenants_tenant
public.accounts_tenantuser
```

### Tenant Schemas (1 per tenant)
```sql
-- Isolated per tenant (e.g., "acme" tenant)
acme.hr_core_employee
acme.hr_core_timeofftype
acme.hr_core_timeoffrequest
acme.ats_jobposting
acme.ats_candidate
acme.services_serviceprovider
```

---

## Migration Impact

### Current State (WRONG ❌)
```python
class Employee(models.Model):  # ❌ Not tenant-aware
    user = models.ForeignKey(User)
    employee_id = models.CharField()
    # Missing: tenant field
```

### Fixed State (CORRECT ✅)
```python
class Employee(TenantAwareModel):  # ✅ Tenant-aware
    user = models.ForeignKey(User)
    tenant = models.ForeignKey(Tenant)  # Auto-added by TenantAwareModel
    employee_id = models.CharField()

    class Meta:
        unique_together = [('tenant', 'user'), ('tenant', 'employee_id')]
```

---

## Implementation Checklist

### HR Models to Fix
- [x] Change `Employee(models.Model)` → `Employee(TenantAwareModel)` ✅ COMPLETED
- [x] Change `TimeOffType(models.Model)` → `TimeOffType(TenantAwareModel)` ✅ COMPLETED
- [x] Change `TimeOffRequest(models.Model)` → `TimeOffRequest(TenantAwareModel)` ✅ COMPLETED
- [x] Remove duplicate `uuid` field from Employee (TenantAwareModel provides `id` as UUID) ✅ COMPLETED
- [ ] Clean rebuild: Delete all containers, images, and volumes
- [ ] Run makemigrations for hr_core app (auto via entrypoint.sh)
- [ ] Run migrate_schemas --shared and --tenant (auto via entrypoint.sh)

**Note:** This is a breaking change requiring a clean database rebuild. The primary key changes from integer to UUID.

### Keep in Public Schema
- [x] `CustomUser` - Already public
- [x] `UserProfile` - Already public
- [x] `KYCVerification` - Stays public (correct)
- [x] `TrustScore` - Stays public (correct)

---

## Django Settings Configuration

### SHARED_APPS (Public Schema)
```python
SHARED_APPS = [
    'django_tenants',
    'tenants',
    'custom_account_u',  # CustomUser
    'accounts',          # KYCVerification, TrustScore, TenantUser
    'finance',           # Subscription plans
    # ... admin, auth, etc.
]
```

### TENANT_APPS (Tenant Schema)
```python
TENANT_APPS = [
    'ats',           # Jobs, Candidates, Applications
    'hr_core',       # Employee, TimeOffType, TimeOffRequest
    'services',      # Marketplace
    'messages_sys',  # Conversations
    # ... all tenant-specific apps
]
```

---

## Security Implications

### Row-Level Security (Automatic)
- Django-tenants automatically filters queries by tenant schema
- Query in "acme" schema CANNOT access "techstart" data
- PostgreSQL schema isolation enforces this at DB level

### User Access Control
1. User logs in → Check TenantUser mapping
2. User accesses tenant → Switch to tenant schema
3. All queries automatically scoped to that tenant
4. No way to query another tenant's data

### Trust Score Protection
- Stored in public schema = cannot be manipulated per-tenant
- If user is flagged as malicious, flag follows them
- Prevents "tenant hopping" to escape bad reputation

---

## References

- **Django Tenants Docs**: https://django-tenants.readthedocs.io/
- **TenantAwareModel**: `core/models.py`
- **Settings**: `zumodra/settings_tenants.py`
- **Bootstrap Logic**: `tenants/management/commands/bootstrap_demo_tenant.py`

---

## Decision Tree

**When creating a new model, ask:**

### Is this data specific to a COMPANY/ORGANIZATION?
- ✅ YES → Use `TenantAwareModel` (tenant schema)
- ❌ NO → Use `models.Model` (public schema)

### Is this data about a USER's global identity/reputation?
- ✅ YES → Use `models.Model` (public schema)
- ❌ NO → Use `TenantAwareModel` (tenant schema)

### Examples:
- "Employee salary at Company X" → **Tenant schema** (company-specific)
- "User's government ID verification" → **Public schema** (global identity)
- "Job posting by Company Y" → **Tenant schema** (company-specific)
- "User's overall platform trust score" → **Public schema** (global reputation)

---

**Last Updated**: 2026-01-10
**Status**: ⚠️ HR models need migration to TenantAwareModel
