# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Zumodra is a multi-tenant SaaS platform combining:
- **Applicant Tracking System (ATS)** for recruitment
- **Freelance Marketplace** with escrow payments
- **HR Core** for employee management
- **Real-time Messaging** via WebSockets

Tech stack: Django 5.2.7, PostgreSQL 16 + PostGIS, Redis, RabbitMQ, Celery, Django Channels, HTMX + Alpine.js.

## Development Commands

```bash
# Start development environment
docker compose up -d

# Run all tests
pytest

# Run with coverage (60% minimum dev, 80% prod)
pytest --cov

# Run by marker
pytest -m workflow      # End-to-end workflows
pytest -m security      # Security tests
pytest -m integration   # Integration tests

# Run single test file
pytest tests/test_ats_flows.py

# Database migrations (multi-tenant)
python manage.py migrate_schemas --shared   # Public schema
python manage.py migrate_schemas --tenant   # Tenant schemas

# Health check
python manage.py health_check --full

# Tenant management
python manage.py bootstrap_demo_tenant
python manage.py setup_beta_tenant "Company" "email@company.com"
python manage.py setup_demo_data --num-jobs 20 --num-candidates 100
```

## Docker Services

| Service | Port | Purpose |
|---------|------|---------|
| web | 8002 | Django application |
| channels | 8003 | WebSocket server (Daphne) |
| nginx | 8084 | Reverse proxy |
| db | 5434 | PostgreSQL + PostGIS |
| redis | 6380 | Cache & sessions |
| rabbitmq | 5673 | Message broker |
| mailhog | 8026 | Email testing UI |

## Architecture

### Multi-Tenancy
- Schema-based isolation via `django-tenants`
- Tenant routing by domain/subdomain
- Roles: PDG, Supervisor, HR Manager, Recruiter, Employee, Viewer
- Settings split: `settings.py` (main), `settings_tenants.py` (multi-tenancy), `settings_security.py` (security)

### Core Apps
- `accounts/` - Users, KYC, trust scores, authentication
- `ats/` - Jobs, pipelines, interviews, offers
- `services/` - Marketplace listings, proposals, contracts, escrow
- `hr_core/` - Employees, time-off, onboarding
- `finance/` - Payments, subscriptions (Stripe)
- `messages_sys/` - WebSocket real-time chat
- `tenants/` - Tenant management and isolation

### REST API
- DRF ViewSets in each app's `api/` subdirectory
- JWT authentication via `djangorestframework-simplejwt`
- OpenAPI docs at `/api/docs/` (Swagger) and `/api/redoc/`
- Per-tier rate limiting in `api/throttling.py`

### Caching
- Tenant-aware caching via `core/cache/` module
- Permission caching for performance
- View-level caching with ETag support
- Cache invalidation signals connected automatically

### Webhooks
- Outbound webhooks in `integrations/outbound_webhooks.py`
- Signal-based triggers in `integrations/webhook_signals.py`
- HMAC-SHA256 signature verification
- Automatic retry with exponential backoff

### Async Tasks
- Celery workers with RabbitMQ broker
- Celery Beat for scheduled tasks
- Configuration in `zumodra/celery.py` and `zumodra/celery_beat_schedule.py`

### Real-Time
- Django Channels with Redis channel layer
- WebSocket consumers in `messages_sys/consumers.py`

## Code Conventions

### No External CDNs
All assets must be served locally from `staticfiles/`:
- Alpine.js, HTMX, Chart.js in `staticfiles/assets/js/vendor/`
- Tailwind CSS pre-compiled in `staticfiles/dist/`
- Fonts in `staticfiles/assets/fonts/`

This is a strict Content Security Policy (CSP) requirement.

### Templates
- Base templates in `templates/base/` (`unified_base.html`, `dashboard_base.html`)
- Auth templates in `templates_auth/`
- Reusable components in `templates/components/`

### Testing
- Factories in `conftest.py` (UserFactory, TenantFactory, etc.)
- Test files in `tests/` directory and app-specific `tests/` subdirectories
- Always use pytest markers: `@pytest.mark.integration`, `@pytest.mark.security`, etc.

### Code Style
- Black formatter (120 char line length)
- isort for imports
- flake8 and pylint for linting
- CI enforces all style checks

## Security Requirements

- 2FA enabled via django-two-factor-auth
- django-axes for brute force protection (5 failures = 1-hour lockout)
- Input sanitization with bleach/nh3
- Admin honeypot protection at fake admin URL
- Audit logging via django-auditlog and django-simple-history

## Environment Configuration

All environment variables are in `.env.example`:
```bash
cp .env.example .env
# Edit .env with your settings
```

Key startup options:
- `CREATE_DEMO_TENANT=true` - Auto-create demo tenant on startup
- `RUN_TESTS=true` - Run pytest suite on startup
- `TEST_COVERAGE=true` - Include test coverage report

### Domain Configuration

All domain references are centralized and environment-driven. Never hard-code domain names.

**Environment Variables:**
```bash
# Primary domain for the platform
PRIMARY_DOMAIN=zumodra.com       # Production
PRIMARY_DOMAIN=localhost         # Development (default when DEBUG=True)

# Full site URL (includes protocol and port)
SITE_URL=https://zumodra.com     # Production
SITE_URL=http://localhost:8002   # Development (auto-detected from WEB_PORT)

# Tenant subdomain base
TENANT_BASE_DOMAIN=zumodra.com   # Production: tenants are {slug}.zumodra.com
TENANT_BASE_DOMAIN=localhost     # Development: tenants are {slug}.localhost

# Optional specialized domains
API_BASE_URL=https://api.zumodra.com/api
CAREERS_BASE_DOMAIN=careers.zumodra.com
EMAIL_DOMAIN=zumodra.com
ANONYMIZED_EMAIL_DOMAIN=anonymized.zumodra.com
```

**Centralized Utilities (core/domain.py):**
```python
from core.domain import (
    get_primary_domain,      # Get PRIMARY_DOMAIN
    get_site_url,            # Get SITE_URL with protocol
    get_tenant_url,          # Build tenant-specific URL
    build_absolute_url,      # Build full URL for a path
    get_noreply_email,       # Get noreply@{domain}
    is_development_domain,   # Check if running locally
)
```

**Development Notes:**
- `localhost` is only used when `DEBUG=True` and no domain is configured
- The Django Site framework is auto-synced on server startup via `core/apps.py`
- Run `python manage.py sync_site_domain` to manually sync the Site object
- Test fixtures in `conftest.py` use `TENANT_BASE_DOMAIN` for domain generation

**Security Considerations:**
- SSRF protection validators intentionally block `localhost` and private IP ranges
- These localhost references in security code are intentional and should NOT be changed
- See `core/validators.py` for the SSRF protection implementation
