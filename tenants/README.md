# Tenants App

## Overview

Multi-tenant management with schema-based isolation using django-tenants.

**Schema**: PUBLIC (tenant metadata) + TENANT (tenant-specific data)

## Models

- **Tenant**: Core tenant model (company information)
- **TenantDomain**: Custom domains for tenants
- **TenantInvitation**: User invitation system
- **TenantSettings**: Tenant-specific configuration

## Key Features

- Schema-based multi-tenancy
- Subdomain routing (company.zumodra.com)
- Custom domain support
- Tenant invitation workflow
- Role-based access (PDG, Supervisor, HR Manager, Recruiter, Employee, Viewer)
- Tenant isolation and security

## API Endpoints

### Tenants
- **GET** `/api/v1/tenants/` - Current tenant info
- **PUT/PATCH** `/api/v1/tenants/` - Update tenant settings

### Domains
- **GET/POST** `/api/v1/tenants/domains/`
- **DELETE** `/api/v1/tenants/domains/<id>/`

### Invitations
- **GET/POST** `/api/v1/tenants/invitations/`
- **POST** `/api/v1/tenants/invitations/<id>/resend/`
- **POST** `/api/v1/tenants/invitations/<token>/accept/`

### Memberships
- **GET** `/api/v1/tenants/members/`
- **POST** `/api/v1/tenants/members/<id>/update-role/`
- **DELETE** `/api/v1/tenants/members/<id>/` - Remove member

## Tenant Context

All requests must have tenant context set via domain/subdomain:

```python
from tenants.context import tenant_context

with tenant_context(tenant):
    # Operations are tenant-scoped
    pass
```

## Permissions

- `IsTenantAdmin`: PDG, Supervisor, HR Manager
- `CanManageTenant`: Tenant settings management
- `CanInviteUsers`: User invitation permissions

## Tasks (Celery)

- `sync_tenant_data`: Sync tenant metadata
- `daily_tenants_cleanup`: Clean expired invitations

## Signals

- `tenant_saved`: Update tenant metadata
- `invitation_created`: Send invitation email

## Testing

```bash
pytest tenants/tests/
```

## Tenant Types

All tenants are **COMPANY** type only.

**DEPRECATED**: FREELANCER tenant type removed (Phase 2) - individual freelancers are now `FreelancerProfile` user profiles.

## Management Commands

```bash
# Create demo tenant
python manage.py bootstrap_demo_tenant

# Setup beta tenant
python manage.py setup_beta_tenant "Company Name" "admin@company.com"
```
