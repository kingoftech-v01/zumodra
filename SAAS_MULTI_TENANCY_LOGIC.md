Zumodra’s core logic is a **multi-tenant B2B platform** where identity, reputation, and billing are global in the public schema, and all operational HR/ATS/marketplace activity is isolated per company in tenant schemas.

## Product vision

- Zumodra combines **HRIS + ATS + freelance marketplace + messaging** for organizations, with strong emphasis on KYC and a **global trust score** that follows users across tenants.
- Each **tenant = organization** with its own employees, jobs, pipelines, service marketplace, and policies, while the same person can participate in multiple tenants under one global account.

## Tenancy & identity model

- The platform uses **schema-based multi-tenancy with django-tenants**, where `Tenant` and routing live in the public schema and each tenant has its own PostgreSQL schema selected by hostname/subdomain.
- **Global identity** lives in public: `CustomUser`, `UserProfile`, `KYCVerification`, `TrustScore`, and `TenantUser` (user↔tenant membership + roles) so that authentication and reputation are shared across all organizations.

## Data placement rules

- **Public schema**: anything about a **person as a platform user** or cross-tenant configuration (users, profiles, KYC, trust, subscription plans, tenant definitions, TenantUser mappings, global feature flags, payment/billing records).
- **Tenant schemas**: anything about a **company’s internal operations** (employees, time off, pipelines, jobs, candidates, services, contracts, conversations), modeled via `TenantAwareModel` and always scoped by the active tenant.

## HR & ATS domain logic

- HR domain: each tenant has its own `Employee`, `TimeOffType`, `TimeOffRequest` so a single user can have multiple employee records and PTO policies across companies while keeping data fully isolated per tenant.
- ATS domain: `JobPosting`, `JobCategory`, `Pipeline`, `PipelineStage`, `Candidate`, `Application`, `Interview`, and `Offer` are all tenant-scoped, representing the hiring lifecycle per organization.

## Marketplace & messaging logic

- Marketplace: `ServiceProvider`, `ServiceCategory`, `Service`, `ServiceRequest`, `Proposal`, and `Contract` are defined per tenant, letting each company run its own internal or semi-public marketplace while still leveraging users’ global trust scores.
- Messaging: `Conversation` and `Message` live in the tenant schema, tying all discussions (HR, ATS, marketplace, support) to the tenant, while participant identity uses global user records.

## Security, IAM, and reputation

- Security relies on **schema isolation + tenant-aware ORM queries** so that once a tenant schema is selected, all domain queries are automatically limited to that organization’s data.
- IAM model: global login authenticates the user, then `TenantUser` and tenant roles determine which tenant(s) they can access and what they can do inside each tenant, enabling per-tenant RBAC and future SSO/SCIM integration for enterprises.