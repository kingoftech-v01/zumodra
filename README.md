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
# Edit .env with your credentials

# Start all services
docker compose up -d

# Run migrations
docker compose exec web python manage.py migrate

# Create superuser
docker compose exec web python manage.py createsuperuser

# Access application
# Web: http://localhost:8000
# API Docs: http://localhost:8000/api/docs/
# Admin: http://localhost:8000/admin-panel/
```

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

> See [SECURITY.md](SECURITY.md) for the complete security policy including CSP configuration.

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

- **Swagger UI:** http://localhost:8000/api/docs/
- **ReDoc:** http://localhost:8000/api/redoc/
- **OpenAPI Schema:** http://localhost:8000/api/schema/

### Authentication

```bash
# Get JWT token
curl -X POST http://localhost:8000/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Use token
curl http://localhost:8000/api/v1/ats/jobs/ \
  -H "Authorization: Bearer <access_token>"
```

See [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) for complete API reference.

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
| [FEATURES.md](docs/FEATURES.md) | Complete platform features and specifications |
| [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) | Complete API reference |
| [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | Production deployment guide |
| [SECURITY.md](docs/SECURITY.md) | Security policy and practices |
| [QA_SCENARIOS.md](docs/QA_SCENARIOS.md) | End-to-end test scenarios |
| [TENANT_ONBOARDING.md](docs/TENANT_ONBOARDING.md) | New tenant setup guide |
| [domain_model.md](docs/domain_model.md) | Domain model documentation |

---

## Docker Services

| Service | Port | Description |
|---------|------|-------------|
| web | 8000 | Django application |
| channels | 8001 | WebSocket server |
| nginx | 80/443 | Reverse proxy |
| db | 5433 | PostgreSQL + PostGIS |
| redis | 6379 | Cache and sessions |
| rabbitmq | 5672 | Message broker |
| celery_worker | - | Background tasks |
| celery_beat | - | Scheduled tasks |
| mailhog | 8025 | Email testing (dev) |
| prometheus | 9090 | Metrics (optional) |
| grafana | 3000 | Dashboards (optional) |

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
**Last Updated:** December 2025
