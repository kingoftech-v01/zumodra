# Changelog

All notable changes to Zumodra will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- **Multi-tenancy architecture (COMPLETE REMOVAL)** - Removed `django-tenants` dependency and all schema-per-tenant isolation logic. The platform now runs on a single database schema. All features (ATS, HR, Services, etc.) are preserved; only the multi-tenancy state is removed.
- `django-tenants>=3.5.0` from requirements (commented out)
- `django_tenants.middleware.main.TenantMainMiddleware` from middleware stack
- `tenants.middleware.TenantURLConfMiddleware` from middleware stack
- `DATABASE_ROUTERS` configuration (`django_tenants.routers.TenantSyncRouter`)
- `SHARED_APPS` / `TENANT_APPS` split - replaced with flat `INSTALLED_APPS`
- `TENANT_MODEL`, `TENANT_DOMAIN_MODEL`, `PUBLIC_SCHEMA_URLCONF` settings
- `settings_tenants.py` (replaced with deprecation stub)
- `TenantMixin` / `DomainMixin` inheritance from Tenant and Domain models
- Schema switching context managers from `tenants.context` (deleted)
- Thread-local tenant context auto-assignment from `tenants.mixins`
- All `from django_tenants` imports across the entire codebase (replaced with `tenants.utils` shims)

### Added
- **GitHub Actions CI/CD pipeline** (`.github/workflows/ci.yml`) with lint, test, security scan, and Docker build stages
- **CHANGELOG.md** (this file) following Keep a Changelog format
- **CODE_OF_CONDUCT.md** based on Contributor Covenant v2.1
- No-op compatibility shims in `tenants.utils`: `schema_context()`, `get_tenant_model()`, `get_public_schema_name()`
- `deprecated` pytest marker for tests pending migration away from multi-tenancy
- `flake8`, `isort`, `mypy` configuration in `setup.cfg`

### Changed
- `tenants/` app renamed from "Multi-Tenant Management" to "Organization Management"
- `tenants/models.py` - Tenant model is now a plain Django model (no schema isolation)
- `tenants/mixins.py` - Removed thread-local context auto-assignment, explicit tenant passing required
- `settings.py` - Flattened `INSTALLED_APPS`, standard PostGIS engine, removed tenant middleware
- `settings_test.py` - Removed tenant-specific test overrides
- `requirements.txt` - Removed `django-tenants>=3.5.0`
- `pytest.ini` - Removed `tenants/tests` from test paths, added `deprecated` marker
- `setup.cfg` - Added flake8/isort/mypy configuration, coverage target at 80%
- `conftest.py` - Simplified tenant factories, removed schema context utilities

## [2.2.0] - 2026-01-18

### Added
- Phase 11: Finance app split into 10 specialized apps (payments, escrow, payroll, expenses, subscriptions, stripe_connect, tax, accounting, billing, finance_webhooks)
- Phase 12: Deprecation cleanup across settings and URL configurations

### Changed
- `accounts` app renamed to `tenant_profiles` (Phase 10)
- `appointment` app renamed to `interviews` (Phase 9)
- `ats` app renamed to `jobs` (Phase 7)
- `ats_public` app renamed to `jobs_public` (Phase 7)
- `marketing` + `newsletter` merged into `marketing_campaigns` (Phase 8)

### Removed
- `FREELANCER` tenant type - replaced by `FreelancerProfile` user profile
- Monolithic `finance/` app - split into specialized modules
- `dashboard_service/` app - merged into `dashboard/`

## [2.1.0] - 2026-01-17

### Changed
- Phase 10: accounts app renamed to tenant_profiles
- Comprehensive test infrastructure with 4,666+ test functions

## [2.0.0] - 2025-12-15

### Added
- Initial multi-tenant SaaS platform
- Full ATS (Applicant Tracking System)
- HR Core module (employees, time-off, onboarding, performance reviews)
- Freelance services marketplace with escrow
- Real-time messaging via WebSockets
- Stripe Connect payment infrastructure
- AI-powered candidate matching
- MFA with TOTP and WebAuthn support
- Comprehensive API with OpenAPI/Swagger documentation
