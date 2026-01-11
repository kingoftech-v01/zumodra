# Tenants App

## Overview

Manages multi-tenancy infrastructure using django-tenants with schema-based isolation. Each tenant represents an enterprise with its own database schema, users, and configuration.

## Key Features

- **Schema-Based Isolation**: PostgreSQL schemas per tenant
- **Domain Routing**: Subdomain to tenant mapping
- **Tenant Provisioning**: Automated tenant creation and setup
- **Subscription Management**: Tenant plan and billing tracking
- **White-Label Branding**: Per-tenant customization
- **Tenant Settings**: Configurable per-tenant settings

## Models

| Model | Description |
|-------|-------------|
| **Tenant** | Enterprise accounts with schema |
| **Domain** | Domain mappings (slug.zumodra.com) |
| **TenantSettings** | Per-tenant configuration |
| **Subscription** | Tenant subscription plan |
| **Plan** | Available subscription tiers |

## Architecture

### Schema Structure

```
public (shared):
  - Tenant, Domain, Plan models
  - Global configuration
  - Shared reference data

tenant_schema_<slug>:
  - All tenant-specific data
  - Jobs, candidates, employees
  - Applications, contracts
  - Tenant users and permissions
```

### Tenant Routing

```python
# Middleware resolves tenant from domain
acme.zumodra.com → Tenant(slug='acme')
demo.localhost   → Tenant(slug='demo')  # Development
```

## Views

- `TenantCreateView` - Create new tenant
- `TenantSettingsView` - Manage settings
- `SubscriptionView` - Subscription management
- `BrandingView` - White-label customization

## Integration Points

- **All Apps**: Every app scopes queries to `request.tenant`
- **Accounts**: TenantUser model links users to tenants
- **Finance**: Subscription billing
- **Dashboard**: Tenant-specific dashboards

## Future Improvements

### High Priority

1. **Tenant Groups**: Multi-tenant holdings/conglomerates
2. **Data Migration**: Tenant-to-tenant data transfer
3. **Backup per Tenant**: Individual tenant backups
4. **Tenant Analytics**: Usage metrics per tenant
5. **Custom Domains**: Custom domain support (acme.com)

### Medium Priority

6. **Tenant Templates**: Pre-configured tenant setups
7. **Multi-Region**: Geographic tenant distribution
8. **Tenant API**: Programmatic tenant management
9. **Usage Quotas**: Resource limits per plan
10. **White-Label Portal**: Self-service tenant portal

## Security

- **Schema Isolation**: No cross-tenant data leakage
- **Query Scoping**: All queries must include tenant filter
- **Middleware Enforcement**: Automatic tenant context
- **Audit Logging**: Per-tenant audit trails

## Testing

```python
# Test with tenant context
from django_tenants.test.cases import TenantTestCase

class MyTest(TenantTestCase):
    def test_with_tenant(self):
        # Automatically in tenant schema
        pass
```

## Migration Notes

```bash
# Shared schema migrations
python manage.py migrate_schemas --shared

# Apply to all tenants
python manage.py migrate_schemas --tenant

# Apply to specific tenant
python manage.py migrate_schemas --tenant --schema=acme
```

## Contributing

**CRITICAL RULES:**
1. Never query without tenant scope
2. Always test cross-tenant isolation
3. Use `TenantTestCase` for tests
4. Document schema changes
5. Verify migration rollback safety

---

**Status:** Production
**Critical Component:** Core infrastructure
