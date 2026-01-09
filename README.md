# Zumodra - Multi-Tenant HR & Freelance Services Platform

**Enterprise-grade SaaS platform combining Applicant Tracking System (ATS), Freelance Marketplace with Escrow, HR Management, and CRM functionality.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.2-green.svg)](https://djangoproject.com)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()

---

## Overview

Zumodra is a comprehensive multi-tenant platform that combines:

- **Applicant Tracking System (ATS)** - Full hiring pipeline from job posting to offer
- **Freelance Marketplace** - Service listings with proposals and escrow payments
- **HR Core** - Employee management, time-off, onboarding, performance reviews
- **Trust & Verification** - KYC verification and trust scoring
- **Real-time Messaging** - WebSocket-powered chat system
- **Co-op/Internship Management** - Student, employer, and coordinator dashboards

---

## Quick Start

### Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/rhematek/zumodra.git
cd zumodra

# Configure environment
cp .env.example .env
# Edit .env with your credentials (see "Database Configuration" below)

# Start all services
docker compose up -d

# The entrypoint automatically handles:
# - Waiting for database/redis/rabbitmq
# - Running migrations
# - Collecting static files

# Create superuser
docker compose exec web python manage.py createsuperuser

# (Optional) Create demo tenant with sample data
docker compose exec web python manage.py bootstrap_demo_tenant

# Access application
# Web: http://localhost:8002 (or http://localhost:8084 via nginx)
# API Docs: http://localhost:8002/api/docs/
# Admin: http://localhost:8002/admin-panel/
```

### Production Deployment

```bash
# Configure for production
cp .env.example .env
# Edit .env with REAL production secrets (DEBUG=False, secure passwords, etc.)

# For production, use the production compose file if available
docker compose -f docker-compose.prod.yml up -d
# Or use the standard compose with production env vars
docker compose up -d
```

---

## Database Configuration

The entrypoint script and Django both use the same environment variables. Set these correctly and everything works.

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL hostname | `db` (dev) / `postgres-primary` (prod) |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `zumodra` |
| `DB_USER` | Database username | `postgres` |
| `DB_PASSWORD` | Database password | `your-strong-password` |

### How It Works

1. **Docker Compose** passes these env vars to the `web` container
2. **Entrypoint script** logs them on startup for diagnosis:
   ```
   [INFO] Database Configuration (from env):
   [INFO]   DB_HOST     = db
   [INFO]   DB_PORT     = 5432
   [INFO]   DB_NAME     = zumodra
   [INFO]   DB_USER     = postgres
   [INFO]   DB_PASSWORD = [SET]
   ```
3. **Django** reads the same vars in `settings.py`

### Troubleshooting "password authentication failed"

If you see this error:
1. Check that `DB_PASSWORD` in your `.env` matches `POSTGRES_PASSWORD` in the Postgres container
2. Check that `DB_USER` matches `POSTGRES_USER`
3. Check the entrypoint logs to see what values are actually being used

### Files

| File | Purpose |
|------|---------|
| `.env.example` | Environment template (copy to .env) |
| `docker/Dockerfile` | Docker build file |
| `docker/entrypoint.sh` | Container entrypoint script |
| `docker-compose.yml` | Main compose file |
| `docker-compose.prod.yml` | Production compose (optional) |

---

### Demo Tenant

For testing and exploration, create a demo tenant with rich sample data:

```bash
# Manual creation
python manage.py bootstrap_demo_tenant

# Or enable auto-creation on Docker startup
CREATE_DEMO_TENANT=1 docker compose up -d
```

**Demo Login Credentials:**
| Role | Email | Password |
|------|-------|----------|
| Admin | admin@demo.zumodra.local | Demo@2024! |
| HR Manager | hr@demo.zumodra.local | Demo@2024! |
| Recruiter | recruiter@demo.zumodra.local | Demo@2024! |

See [TENANT_ONBOARDING.md](docs/TENANT_ONBOARDING.md) for full demo tenant details.

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env

# Run migrations
python manage.py migrate

# Start development server
python manage.py runserver

# Start Celery (separate terminals)
celery -A zumodra worker --loglevel=info
celery -A zumodra beat --loglevel=info
```

---

## Features

### Core Modules

| Module | Status | Description |
|--------|--------|-------------|
| **ATS** | Production | Job postings, pipelines, interviews, offers |
| **Marketplace** | Production | Services, proposals, contracts, escrow |
| **HR Core** | Production | Employees, time-off, onboarding |
| **Finance** | Production | Stripe payments, escrow, subscriptions |
| **Messaging** | Production | Real-time WebSocket chat |
| **Notifications** | Production | Multi-channel notifications |
| **KYC/Verification** | Production | Identity and career verification |
| **Trust Scores** | Production | Multi-dimensional trust scoring |
| **Co-op Management** | Production | Student/employer/coordinator UIs |
| **Multi-CV** | Production | CV management with AI scoring |

### Security Features

- Two-Factor Authentication (mandatory)
- JWT API authentication with token rotation
- Brute force protection (django-axes)
- **Strict Content Security Policy** - No external CDN dependencies
- **Local-only assets** - All CSS/JS/fonts/icons served from staticfiles
- Admin honeypot protection
- Comprehensive audit logging
- Rate limiting per user tier
- Input sanitization and XSS prevention

> See [docs/SECURITY.md](docs/SECURITY.md) for the complete security policy including CSP configuration.

---

## Technology Stack

### Backend
- Python 3.11+
- Django 5.2 with GeoDjango
- Django REST Framework
- PostgreSQL 16 + PostGIS
- Redis 7 (cache, sessions, Celery)
- RabbitMQ (message broker)
- Celery 5.x (async tasks)
- Django Channels (WebSockets)

### Frontend
- Django Templates with HTMX
- Alpine.js for interactivity (local, no CDN)
- Tailwind CSS (pre-compiled, local)
- Phosphor Icons / Icomoon (local icon fonts)
- Wagtail CMS

### Infrastructure
- Docker + Docker Compose
- Nginx reverse proxy
- Gunicorn + Uvicorn (ASGI)
- Prometheus + Grafana (monitoring)

---

## Project Structure

```
zumodra/
├── accounts/           # User accounts, KYC, trust scores
├── ats/                # Applicant Tracking System
├── hr_core/            # HR management, onboarding
├── services/           # Freelance marketplace
├── finance/            # Payments, escrow, subscriptions
├── messages_sys/       # Real-time messaging
├── notifications/      # Notification system
├── careers/            # Public career pages
├── ai_matching/        # AI-powered matching
├── integrations/       # Third-party integrations
├── tenants/            # Multi-tenant management
├── api/                # REST API infrastructure
├── core/               # Shared utilities & security middleware
├── templates/          # Django templates
├── templates_auth/     # Allauth & MFA templates
├── staticfiles/        # Static assets (CSS, JS, fonts, icons)
├── tests/              # Test suite
├── docker/             # Docker configurations
├── docs/               # Documentation
└── zumodra/            # Django project settings
```

### Template Structure

```
templates/
├── base/
│   ├── unified_base.html    # Root base template (no CDN)
│   ├── base_auth.html       # Auth pages base
│   ├── dashboard_base.html  # Dashboard base
│   └── public_base.html     # Public pages base
├── components/              # Reusable UI components
├── emails/                  # HTML email templates
│   ├── base/base_email.html # Email base template
│   ├── auth/                # Auth emails
│   ├── ats/                 # ATS notifications
│   └── marketplace/         # Marketplace emails
└── errors/                  # Error pages (500, 503)

templates_auth/
├── account/                 # Allauth templates
├── mfa/                     # MFA/2FA templates
└── socialaccount/           # Social auth templates
```

### Static Assets (Local Only)

```
staticfiles/
├── assets/
│   ├── js/vendor/           # Alpine.js, HTMX, Chart.js, SortableJS
│   ├── css/                 # Icomoon icons, Leaflet styles
│   └── fonts/               # Local web fonts
└── dist/
    └── output-tailwind.css  # Pre-compiled Tailwind CSS
```

---

## API Documentation

### Interactive Docs

- **Swagger UI:** http://localhost:8002/api/docs/
- **ReDoc:** http://localhost:8002/api/redoc/
- **OpenAPI Schema:** http://localhost:8002/api/schema/

### Authentication

```bash
# Get JWT token
curl -X POST http://localhost:8002/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Use token
curl http://localhost:8002/api/v1/ats/jobs/ \
  -H "Authorization: Bearer <access_token>"
```

See [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) for complete API reference.

---

## Management Commands

Zumodra includes several custom management commands for common operations:

### Tenant Management

```bash
# Bootstrap a demo tenant with comprehensive sample data
python manage.py bootstrap_demo_tenant
python manage.py bootstrap_demo_tenant --reset      # Delete and recreate
python manage.py bootstrap_demo_tenant --dry-run    # Preview changes

# Create a beta tenant for early adopters
python manage.py setup_beta_tenant "Company Name" "owner@email.com"
python manage.py setup_beta_tenant "Acme Corp" "admin@acme.com" --plan beta_enterprise --trial-days 90

# Create a basic demo tenant with sample data
python manage.py setup_demo_data
python manage.py setup_demo_data --num-jobs 20 --num-candidates 100 --reset

# Create a standard tenant
python manage.py create_tenant

# Set up subscription plans
python manage.py setup_plans

# Clean up inactive tenants
python manage.py cleanup_inactive_tenants --days 90 --dry-run

# Migrate data between tenant schemas
python manage.py migrate_tenant_data
```

### Infrastructure & Utilities

```bash
# Check health of all services (database, cache, email, etc.)
python manage.py health_check
python manage.py health_check --full    # Include external services
python manage.py health_check --json    # Output as JSON

# Generate API documentation
python manage.py generate_api_docs
python manage.py generate_api_docs --format markdown
python manage.py generate_api_docs --format html --output docs/api
```

### Django-Tenants Migrations

```bash
# Run migrations on all schemas
python manage.py migrate_schemas

# Run migrations only on shared (public) schema
python manage.py migrate_schemas --shared

# Run migrations only on tenant schemas
python manage.py migrate_schemas --tenant
```

---

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov

# Run specific test file
pytest tests/test_ats_flows.py

# Run by marker
pytest -m workflow     # End-to-end workflows
pytest -m security     # Security tests
pytest -m integration  # Integration tests

# Check deployment readiness
python manage.py check --deploy
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [FEATURES.md](docs/FEATURES.md) | Complete platform features and specifications |
| [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) | Complete API reference |
| [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | Production deployment guide |
| [SECURITY.md](docs/SECURITY.md) | Security policy and practices |
| [QA_SCENARIOS.md](docs/QA_SCENARIOS.md) | End-to-end test scenarios |
| [TENANT_ONBOARDING.md](docs/TENANT_ONBOARDING.md) | New tenant setup guide |
| [domain_model.md](docs/domain_model.md) | Domain model documentation |

---

## Docker Services

| Service | Internal Port | External Port | Description |
|---------|---------------|---------------|-------------|
| web | 8000 | 8002 | Django application |
| channels | 8001 | 8003 | WebSocket server (Daphne) |
| nginx | 80 | 8084 | Reverse proxy |
| db | 5432 | 5434 | PostgreSQL + PostGIS |
| redis | 6379 | 6380 | Cache and sessions |
| rabbitmq | 5672 | 5673 | Message broker |
| celery-worker | - | - | Background tasks |
| celery-beat | - | - | Scheduled tasks |
| mailhog | 8025 | 8026 | Email testing (dev) |
| prometheus | 9090 | 9090 | Metrics (optional, --profile monitoring) |
| grafana | 3000 | 3001 | Dashboards (optional, --profile monitoring) |

---

## Environment Variables

Key configuration options (see `.env.example` for complete list):

```env
# Django
SECRET_KEY=your-secret-key
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_DEFAULT_NAME=zumodra
DB_USER=postgres
DB_PASSWORD=your-password
DB_HOST=db

# Redis
REDIS_URL=redis://redis:6379/0

# Stripe
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLIC_KEY=pk_test_...

# Feature Flags
FEATURE_ENABLE_2FA=True
FEATURE_ENABLE_ESCROW=True
FEATURE_ENABLE_AI_MATCHING=False
```

---

## Multi-Tenancy

Zumodra supports full multi-tenant architecture:

- **Tenant Isolation** - Each tenant has isolated data
- **Custom Domains** - Per-tenant domain support
- **Role-Based Access** - PDG, Supervisor, HR, Recruiter, Employee, Viewer
- **Plan-Based Features** - Feature flags per subscription tier

```python
# Tenant roles
TENANT_ROLES = [
    'pdg',          # Full tenant access
    'supervisor',   # Circusale + subordinates
    'hr_manager',   # HR operations
    'recruiter',    # ATS access
    'employee',     # Self-service
    'viewer',       # Read-only
]
```

---

## Supported Languages

- English (en)
- Spanish (es)
- French (fr)
- German (de)
- Italian (it)
- Portuguese (pt)
- Russian (ru)
- Simplified Chinese (zh-hans)
- Traditional Chinese (zh-hant)

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit (`git commit -m 'Add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## Support

- **Documentation:** https://docs.zumodra.com
- **API Status:** https://status.zumodra.com
- **Support Email:** support@zumodra.com

---

## License

Proprietary - All Rights Reserved

---

**Version:** 1.0.0
**Last Updated:** January 2026
