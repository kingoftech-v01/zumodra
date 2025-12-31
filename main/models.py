"""
Main App Models - Zumodra Multi-tenant Platform

IMPORTANT: Tenant and Domain models have been consolidated into the `tenants` app.
This file re-exports them for backwards compatibility with django-tenants settings.

The canonical models are in:
- tenants.models.Tenant
- tenants.models.Domain

All new code should import directly from `tenants.models`.
"""

# Re-export from tenants for backwards compatibility with TENANT_MODEL setting
from tenants.models import Tenant, Domain

# Note: The original basic models have been replaced with the comprehensive
# versions from tenants app which include:
# - Tenant: Full enterprise tenant with Plan, status, Stripe integration
# - Domain: Custom domain mapping with SSL support
# - TenantSettings: Tenant-specific configuration
# - TenantInvitation: User invitations
# - TenantUsage: Resource usage tracking
# - AuditLog: Tenant-scoped audit logging
# - Circusale: Business units/divisions
# - CircusaleUser: User-to-circusale assignments

__all__ = ['Tenant', 'Domain']