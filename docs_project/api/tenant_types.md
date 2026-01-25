# Tenant Type System API Reference

## Overview

Zumodra supports two tenant types with distinct capabilities:
- **COMPANY**: Can create jobs, services, hire employees, have career pages
- **FREELANCER**: Can create services only, single-user, no employees, no career pages

## Tenant Type Fields in API Responses

All tenant-related API endpoints include these fields:

```json
{
  "tenant_type": "company",  // or "freelancer"
  "can_create_jobs": true,
  "can_have_employees": true,
  "ein_verified": false
}
```

## Core API Endpoints

### Get Tenant Details
`GET /api/tenants/tenant/`

**Response:**
```json
{
  "id": 1,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Corp",
  "slug": "acme-corp",
  "tenant_type": "company",
  "can_create_jobs": true,
  "can_have_employees": true,
  "ein_number": "12-3456789",
  "ein_verified": true,
  "ein_verified_at": "2026-01-09T15:30:00Z"
}
```

### Switch Tenant Type
`POST /api/tenants/tenant/switch_type/`

**Request:**
```json
{
  "type": "freelancer"  // or "company"
}
```

**Response:**
```json
{
  "tenant_type": "freelancer",
  "can_create_jobs": false,
  "can_have_employees": false,
  "message": "Successfully switched to freelancer tenant"
}
```

**Validation Rules:**
- Company → Freelancer: Requires ≤1 active member
- Freelancer → Company: Always allowed

**HTTP Status Codes:**
- `200 OK`: Successfully switched
- `400 Bad Request`: Cannot switch (e.g., company has multiple members)
- `403 Forbidden`: User not authorized (must be owner/admin)

## Tenant Type Capabilities

### COMPANY Tenant

**Can Do:**
- ✅ Create job postings (ATS)
- ✅ Create services (marketplace)
- ✅ Have multiple employees (HR)
- ✅ Have career page (careers module)
- ✅ Publish services to marketplace
- ✅ Receive invitations
- ✅ Switch to freelancer (if ≤1 member)

**API Access:**
- `/api/jobs/*` - Full access
- `/api/hr/*` - Full access
- `/api/careers/*` - Full access
- `/api/services/*` - Full access

### FREELANCER Tenant

**Can Do:**
- ✅ Create services (marketplace)
- ✅ Publish services to marketplace
- ✅ Switch to company

**Cannot Do:**
- ❌ Create job postings
- ❌ Have employees
- ❌ Have career page
- ❌ Receive invitations (single-user only)

**API Access:**
- `/api/jobs/*` - **403 Forbidden**
- `/api/hr/*` - **403 Forbidden**
- `/api/careers/*` - **403 Forbidden** (career pages)
- `/api/services/*` - Full access

## Serializer Fields

### ATS Serializers

All ATS Detail serializers include:
```json
{
  "tenant_type": "company",
  "can_create_jobs": true
}
```

**Example (JobPostingDetailSerializer):**
```json
{
  "id": 123,
  "title": "Senior Developer",
  "tenant_type": "company",
  "can_create_jobs": true,
  "status": "published",
  ...
}
```

### Services Serializers

Service-related serializers include provider tenant type:
```json
{
  "id": 456,
  "name": "Web Development",
  "tenant_type": "freelancer",
  "provider_tenant_type": "freelancer",
  ...
}
```

### HR Serializers

Employee-related serializers include:
```json
{
  "id": 789,
  "user": {...},
  "tenant_type": "company",
  "can_have_employees": true,
  ...
}
```

## Error Responses

### Freelancer Attempting to Create Job
```json
{
  "error": "This feature is only available for company tenants.",
  "status": 403
}
```

### Attempting to Switch with Multiple Members
```json
{
  "error": "Cannot switch to freelancer with multiple members. Remove all but 1 member first.",
  "status": 400
}
```

## Webhook Payloads

All tenant webhooks include tenant type information:

```json
{
  "event": "tenant.updated",
  "tenant": {
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Acme Corp",
    "tenant_type": "company",
    "can_create_jobs": true,
    "can_have_employees": true,
    "ein_verified": true,
    "timestamp": "2026-01-10T12:00:00Z"
  }
}
```

## Best Practices

### Frontend Implementation

1. **Check tenant type before rendering features:**
```javascript
if (tenant.can_create_jobs) {
  // Show "Create Job" button
}
```

2. **Display appropriate UI based on type:**
```javascript
const profileCard = tenant.tenant_type === 'company'
  ? <CompanyProfileCard tenant={tenant} />
  : <FreelancerProfileCard tenant={tenant} />;
```

3. **Handle API errors gracefully:**
```javascript
try {
  await createJob(jobData);
} catch (error) {
  if (error.status === 403) {
    // Show message: "Only companies can create jobs"
  }
}
```

### Backend Implementation

1. **Always use decorators for view protection:**
```python
from tenants.decorators import require_tenant_type

@require_tenant_type('company')
class JobCreateView(CreateView):
    """Only companies can create jobs."""
    ...
```

2. **Include tenant_type in serializer responses:**
```python
class JobSerializer(serializers.ModelSerializer):
    tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)
    can_create_jobs = serializers.SerializerMethodField()
```

3. **Validate in model methods:**
```python
def create_job(self):
    if self.tenant.tenant_type != 'company':
        raise ValidationError("Only companies can create jobs.")
```

## Migration Guide

### Upgrading Existing Tenants

All existing tenants default to `COMPANY` type. To convert specific tenants to freelancers:

```python
from tenants.models import Tenant

tenant = Tenant.objects.get(slug='john-doe')
if tenant.members.filter(is_active=True).count() <= 1:
    tenant.switch_to_freelancer()
```

### Database Constraints

The system enforces:
- Freelancer tenants cannot have career pages
- Freelancer tenants cannot have >1 active member
- All ATS/HR operations require company tenant

## See Also

- [Verification System](../verification.md) - User and tenant verification
- [UI Components](../components.md) - Frontend components for tenant types
- [Multi-Tenancy Logic](../../SAAS_MULTI_TENANCY_LOGIC.md) - Complete architecture guide
