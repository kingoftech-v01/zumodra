# Zumodra Platform Architecture

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Technology Stack](#technology-stack)
3. [Multi-Tenant Architecture](#multi-tenant-architecture)
4. [Core Components](#core-components)
5. [App Organization](#app-organization)
6. [Data Flow](#data-flow)
7. [Security Architecture](#security-architecture)
8. [Deployment Architecture](#deployment-architecture)
9. [API Architecture](#api-architecture)
10. [Real-Time Architecture](#real-time-architecture)
11. [Background Tasks](#background-tasks)
12. [Caching Strategy](#caching-strategy)

---

## High-Level Architecture

Zumodra is a comprehensive multi-tenant SaaS platform that combines:
- **Applicant Tracking System (ATS)** for recruitment workflows
- **HR Core** for employee management, time-off, and onboarding
- **Freelance Marketplace** with escrow payments
- **Real-time Messaging** via WebSockets
- **AI-Powered Matching** for candidates and jobs

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NGINX (Reverse Proxy)                        │
│                         Port 8084 (HTTP/HTTPS)                       │
└────────────┬──────────────────────────────────────────┬──────────────┘
             │                                           │
             ▼                                           ▼
┌────────────────────────┐                   ┌────────────────────────┐
│   Django Web Server    │                   │   Django Channels      │
│   (Gunicorn + Uvicorn) │                   │   (Daphne/WebSocket)   │
│        Port 8000       │                   │        Port 8001       │
└───────────┬────────────┘                   └───────────┬────────────┘
            │                                            │
            └──────────────────┬─────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            │                                     │
            ▼                                     ▼
┌────────────────────────┐         ┌────────────────────────┐
│   PostgreSQL 16        │         │   Redis Cache          │
│   + PostGIS 3.4        │         │   + Channel Layer      │
│   (Multi-Schema)       │         │   + Session Store      │
│     Port 5432          │         │     Port 6379          │
└────────────────────────┘         └────────────────────────┘
            ▲                                     ▲
            │                                     │
            ├─────────────────────────────────────┤
            │                                     │
┌────────────────────────┐         ┌────────────────────────┐
│   Celery Workers       │         │   RabbitMQ Broker      │
│   (Background Tasks)   │────────▶│   (Message Queue)      │
│   4 Concurrent Tasks   │         │     Port 5672          │
└────────────────────────┘         └────────────────────────┘
            │
            ▼
┌────────────────────────┐
│   Celery Beat          │
│   (Scheduled Tasks)    │
│   (DatabaseScheduler)  │
└────────────────────────┘
```

---

## Technology Stack

### Backend Framework
- **Django 5.2.7** - Core web framework
- **Django REST Framework** - API layer with JWT authentication
- **django-tenants** - Schema-per-tenant multi-tenancy
- **Django Channels** - WebSocket/ASGI support

### Database
- **PostgreSQL 16** - Primary relational database
- **PostGIS 3.4** - Geospatial extensions for location-based features
- **pgvector** - Vector storage for AI embeddings (planned)

### Caching & Sessions
- **Redis 7** - In-memory cache and session store
- **Django Cache Framework** - Tenant-aware caching
- **django-redis** - Redis backend for Django caching

### Message Queue & Background Tasks
- **RabbitMQ 3.12** - Message broker (AMQP)
- **Celery** - Distributed task queue
- **Celery Beat** - Scheduled task scheduler
- **django-celery-beat** - Database-backed schedule storage

### Real-Time Communication
- **Django Channels** - ASGI server (WebSocket)
- **Daphne** - ASGI HTTP/WebSocket server
- **channels-redis** - Redis channel layer backend

### Frontend Technologies
- **HTMX** - Progressive enhancement with minimal JavaScript
- **Alpine.js** - Lightweight reactive framework
- **Tailwind CSS** - Utility-first CSS framework
- **Chart.js** - Data visualization

### Authentication & Security
- **django-allauth** - Authentication with social login
- **django-otp** - Two-factor authentication (TOTP)
- **django-axes** - Brute force protection
- **djangorestframework-simplejwt** - JWT authentication for API
- **django-csp** - Content Security Policy middleware
- **admin_honeypot** - Admin URL honeypot

### Third-Party Integrations
- **Stripe** - Payment processing and subscriptions
- **OpenAI** - AI matching and embeddings
- **Twilio** - SMS notifications (optional)
- **AWS S3** - Media storage (production)

### Development & Testing
- **pytest** - Testing framework
- **pytest-django** - Django integration for pytest
- **pytest-cov** - Code coverage reporting
- **factory_boy** - Test data factories
- **Faker** - Fake data generation
- **Black** - Code formatter
- **flake8** - Linting
- **isort** - Import sorting

### Monitoring & Deployment
- **Docker** - Containerization
- **Docker Compose** - Multi-container orchestration
- **Gunicorn** - WSGI HTTP server
- **Uvicorn** - ASGI server (for WebSocket support)
- **Nginx** - Reverse proxy and static file serving
- **MailHog** - Email testing (development)

---

## Multi-Tenant Architecture

### Schema-Per-Tenant Isolation

Zumodra implements **schema-per-tenant** isolation using `django-tenants`:

```
┌─────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐                                       │
│  │  PUBLIC Schema   │  (Shared across all tenants)          │
│  ├──────────────────┤                                       │
│  │ - Tenants        │  Tenant metadata                      │
│  │ - Domains        │  Domain mappings                      │
│  │ - Plans          │  Subscription plans                   │
│  │ - CustomUser     │  User accounts (cross-tenant)         │
│  │ - Integrations   │  Shared integrations                  │
│  │ - CeleryBeat     │  Scheduled tasks                      │
│  └──────────────────┘                                       │
│                                                              │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │  acme_corp       │  │  techstartup     │  Tenant Schemas│
│  ├──────────────────┤  ├──────────────────┤                │
│  │ - Jobs           │  │ - Jobs           │                │
│  │ - Candidates     │  │ - Candidates     │                │
│  │ - Interviews     │  │ - Interviews     │                │
│  │ - Employees      │  │ - Employees      │                │
│  │ - Services       │  │ - Services       │                │
│  │ - Messages       │  │ - Messages       │                │
│  │ - TenantUser     │  │ - TenantUser     │                │
│  └──────────────────┘  └──────────────────┘                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Shared vs Tenant Apps

#### Shared Apps (Public Schema)
Located in `settings.SHARED_APPS` - migrated to PUBLIC schema only:

- `django_tenants` - Multi-tenancy framework
- `custom_account_u` - User accounts (shared across tenants)
- `tenants` - Tenant management
- `main` - Public landing pages
- `integrations` - Webhook configurations
- `django_celery_beat` - Scheduled task definitions

#### Tenant Apps (Tenant Schemas)
Located in `settings.TENANT_APPS` - migrated to each tenant schema:

- `accounts` - KYC, RBAC, tenant-specific user data
- `ats` - Applicant Tracking System (jobs, candidates, interviews)
- `hr_core` - HR operations (employees, time-off, onboarding)
- `careers` - Public career pages
- `services` - Marketplace services
- `finance` - Payments, invoices, subscriptions
- `messages_sys` - Real-time messaging
- `notifications` - Multi-channel notifications
- `dashboard` - User dashboards
- `analytics` - Reporting and metrics

### Tenant Routing

**Request Flow:**

1. **Domain Resolution**: Nginx receives request (e.g., `acme.zumodra.com`)
2. **Tenant Middleware**: `TenantMainMiddleware` extracts tenant from domain
3. **Schema Switching**: Database connection switches to tenant's schema
4. **Request Processing**: Django views operate within tenant context
5. **Response**: Response sent with tenant-specific data

**Middleware Stack:**
```python
MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',  # MUST BE FIRST
    'tenants.middleware.TenantURLConfMiddleware',
    'tenants.middleware.TenantContextMiddleware',
    'tenants.middleware.TenantMigrationCheckMiddleware',
    # ... standard Django middleware ...
]
```

### Tenant Context Management

Throughout the application, the current tenant is accessible via:

```python
from django.db import connection

# Current tenant schema name
schema_name = connection.schema_name  # e.g., 'acme_corp'

# Current tenant object (from middleware)
from django_tenants.utils import get_tenant_model
tenant = connection.tenant  # Tenant instance
```

---

## Core Components

### 1. Tenant Management (`tenants/`)

**Models:**
- `Plan` - Subscription plans with feature flags
- `Tenant` - Organization/company with schema isolation
- `Domain` - Custom domain mappings (e.g., `careers.acme.com`)
- `TenantSettings` - Tenant-specific configurations
- `TenantUsage` - Resource usage tracking for billing
- `Circusale` - Business units/locations within tenant

**Key Features:**
- Trial period management
- Subscription lifecycle (trial → active → suspended → cancelled)
- Feature flag enforcement
- Usage limits and quota tracking
- Multi-location support (Circusales)

### 2. Authentication & Authorization (`accounts/`, `custom_account_u/`)

**User Model:** `CustomUser` (shared across tenants)
```python
AUTH_USER_MODEL = 'custom_account_u.CustomUser'
```

**Role-Based Access Control (RBAC):**
- `TenantUser` - Links users to tenants with roles
- Roles: Owner, Admin, HR Manager, Recruiter, Hiring Manager, Employee, Viewer
- Per-tenant permission system
- Custom permissions via Django's Permission framework

**Security Features:**
- **2FA/MFA**: TOTP via `django-allauth.mfa` and `django-otp`
- **Brute Force Protection**: django-axes (5 failures → 1-hour lockout)
- **KYC Verification**: Identity verification for candidates and recruiters
- **Progressive Data Revelation**: Consent-based data sharing

### 3. ATS (Applicant Tracking System) (`ats/`)

**Models:**
- `JobPosting` - Job listings with salary ranges, remote policy
- `Candidate` - Applicant profiles with CVs and skills
- `Application` - Job applications with status pipeline
- `Interview` - Interview scheduling with calendar sync
- `Offer` - Job offers with e-signature integration
- `Pipeline` - Customizable recruitment stages
- `ApplicationNote` - Internal notes and feedback

**Workflows:**
1. Job creation → Publication → Applications
2. Candidate screening → Interview scheduling → Offers
3. Offer acceptance → Onboarding handoff to HR

### 4. HR Core (`hr_core/`)

**Models:**
- `Employee` - Employee records with contracts
- `TimeOffRequest` - PTO/vacation requests with approval workflow
- `Onboarding` - New hire onboarding checklists
- `Department` - Organizational structure
- `Contract` - Employment contracts
- `PerformanceReview` - Performance evaluations

**Features:**
- Approval workflows (multi-stage)
- Time-off accrual tracking
- Onboarding task automation
- Org chart visualization

### 5. Services Marketplace (`services/`)

**Models:**
- `ServiceProvider` - Freelancer/agency profiles
- `Service` - Service listings with pricing
- `ServiceRequest` - Client requests for services
- `Contract` - Service agreements
- `Escrow` - Payment escrow for milestone-based work

**Payment Flow:**
1. Client requests service → Provider accepts
2. Contract created → Funds held in escrow
3. Milestones completed → Funds released incrementally

### 6. Real-Time Messaging (`messages_sys/`)

**Architecture:**
- **WebSocket Server**: Django Channels (Daphne)
- **Channel Layer**: Redis backend
- **Consumers**: `ChatConsumer` for 1-on-1 and group messaging

**Features:**
- Direct messages (1-on-1)
- Group conversations
- Typing indicators
- Read receipts
- Message attachments
- Tenant-scoped message isolation

### 7. Notifications (`notifications/`)

**Multi-Channel Delivery:**
- In-app notifications (WebSocket push)
- Email notifications (via Celery)
- SMS notifications (Twilio integration, optional)
- Push notifications (APNS/FCM, planned)

**Notification Types:**
- Application status updates
- Interview reminders
- Offer notifications
- Time-off approvals
- System alerts

### 8. Finance (`finance/`)

**Models:**
- `Invoice` - Tenant invoices
- `Payment` - Payment records (Stripe integration)
- `Subscription` - Stripe subscription management
- `Transaction` - Financial transaction log

**Stripe Integration:**
- Subscription creation and management
- Webhook handling for payment events
- Automated billing
- Usage-based billing support

### 9. AI Matching (`ai_matching/`)

**Features:**
- Candidate-to-job matching using embeddings
- Resume parsing and skill extraction
- Match score calculation
- OpenAI integration with fallback to local models

**Architecture:**
```python
# Embedding generation
job_embedding = generate_embedding(job.description)
candidate_embedding = generate_embedding(candidate.resume)

# Similarity calculation
match_score = cosine_similarity(job_embedding, candidate_embedding)
```

### 10. Integrations (`integrations/`)

**Outbound Webhooks:**
- Event-driven webhook triggers
- HMAC-SHA256 signature verification
- Automatic retry with exponential backoff
- Configurable per-tenant

**Supported Events:**
- `application.created`
- `interview.scheduled`
- `offer.accepted`
- `employee.created`

---

## App Organization

### Directory Structure

```
zumodra/
├── zumodra/                    # Project configuration
│   ├── settings.py             # Main settings
│   ├── settings_tenants.py     # Multi-tenancy config
│   ├── settings_security.py    # Security configuration
│   ├── urls.py                 # Root URL configuration
│   ├── celery.py               # Celery configuration
│   └── asgi.py                 # ASGI application
│
├── accounts/                   # KYC, RBAC, user profiles
├── ats/                        # Applicant Tracking System
├── hr_core/                    # HR operations
├── careers/                    # Public career pages
├── services/                   # Marketplace
├── finance/                    # Payments & subscriptions
├── messages_sys/               # Real-time messaging
├── notifications/              # Multi-channel notifications
├── dashboard/                  # User dashboards
├── analytics/                  # Reporting
├── ai_matching/                # AI candidate matching
├── integrations/               # Webhooks & integrations
├── tenants/                    # Tenant management
├── custom_account_u/           # Custom user model
├── core/                       # Shared utilities
│   ├── domain.py               # Domain configuration
│   ├── cache/                  # Caching utilities
│   └── validators.py           # Input validators
├── security/                   # Security monitoring
├── configurations/             # Configuration UI
├── marketing/                  # Marketing tools
│
├── templates/                  # Shared templates
│   ├── base/                   # Base templates
│   ├── components/             # Reusable components
│   └── emails/                 # Email templates
│
├── staticfiles/                # Static assets (local CDN)
│   ├── assets/
│   │   ├── js/vendor/          # Alpine.js, HTMX, Chart.js
│   │   ├── css/                # Tailwind CSS
│   │   └── fonts/              # Web fonts
│   └── dist/                   # Compiled assets
│
├── tests/                      # Integration tests
├── conftest.py                 # Pytest fixtures
├── docker/                     # Docker configuration
├── docs/                       # Documentation
└── scripts/                    # Management scripts
```

### App Interdependencies

```
┌─────────────────┐
│    tenants      │  (Foundation - used by all)
└────────┬────────┘
         │
         ▼
┌─────────────────┐         ┌─────────────────┐
│    accounts     │◀────────│ custom_account_u│
└────────┬────────┘         └─────────────────┘
         │
         ├──────────────┬──────────────┬──────────────┐
         ▼              ▼              ▼              ▼
   ┌─────────┐    ┌──────────┐  ┌──────────┐  ┌──────────┐
   │   ats   │    │ hr_core  │  │ services │  │ finance  │
   └────┬────┘    └────┬─────┘  └────┬─────┘  └────┬─────┘
        │              │             │             │
        └──────────────┴─────────────┴─────────────┘
                       │
                       ▼
              ┌────────────────┐
              │ notifications  │
              └────────┬───────┘
                       │
                       ▼
              ┌────────────────┐
              │  messages_sys  │
              └────────────────┘
```

**Dependency Rules:**
- `tenants` has no dependencies (foundation layer)
- `accounts` depends on `tenants` and `custom_account_u`
- Business apps (`ats`, `hr_core`, `services`) depend on `accounts`
- `notifications` used by all business apps
- `messages_sys` depends on `accounts` for user context

---

## Data Flow

### Request/Response Cycle

```
1. Client Request
   └─> https://acme.zumodra.com/app/ats/jobs/

2. Nginx (Reverse Proxy)
   ├─> SSL termination
   ├─> Static file serving
   └─> Proxy to Gunicorn (port 8000)

3. Django Middleware Stack
   ├─> TenantMainMiddleware (extract tenant from domain)
   │   └─> Sets connection.tenant = Tenant('acme')
   ├─> Schema switching (connection.set_schema('acme_corp'))
   ├─> Authentication (JWT or session)
   ├─> CSRF protection
   ├─> Permission checking
   └─> Caching middleware

4. URL Router
   └─> frontend:ats:job_list

5. View Layer
   ├─> Check tenant context (connection.tenant)
   ├─> Query database (scoped to tenant schema)
   ├─> Apply business logic
   └─> Return response (HTML/JSON)

6. Template Rendering
   ├─> Load tenant-specific settings
   ├─> Apply branding (colors, logo)
   └─> Render with HTMX/Alpine.js enhancements

7. Response
   └─> HTML page with <200 OK>
```

### Tenant Context Management

**Database Query Scoping:**
All queries automatically scoped to current tenant schema:

```python
# Automatically queries 'acme_corp' schema
jobs = JobPosting.objects.filter(status='published')

# Schema stored in thread-local connection object
schema_name = connection.schema_name  # 'acme_corp'
```

**Cross-Tenant Operations:**
For operations spanning tenants (e.g., public catalog):

```python
from django_tenants.utils import schema_context

# Query public schema
with schema_context('public'):
    tenants = Tenant.objects.all()

# Back to tenant schema automatically
jobs = JobPosting.objects.all()  # Current tenant schema
```

### Caching Flow

```
1. Request arrives for /app/dashboard/
   │
   ▼
2. Cache Key Generation (tenant-aware)
   cache_key = f"dashboard:{tenant.schema_name}:{user.id}"
   │
   ▼
3. Cache Lookup (Redis)
   ├─> Cache HIT: Return cached response (fast path)
   └─> Cache MISS: Continue to database
   │
   ▼
4. Database Query (tenant-scoped)
   data = Dashboard.objects.filter(...)
   │
   ▼
5. Cache Write
   cache.set(cache_key, data, timeout=300)  # 5 minutes
   │
   ▼
6. Return Response
```

**Cache Invalidation:**
- Signal-based automatic invalidation
- Manual invalidation via `cache.delete()`
- TTL-based expiration

---

## Security Architecture

### Multi-Tenancy Security

**Schema Isolation:**
- Each tenant has dedicated PostgreSQL schema
- No cross-schema queries possible (enforced by PostgreSQL)
- Middleware ensures correct schema context

**Data Isolation Guarantees:**
```python
# Tenant A (schema: acme_corp)
connection.set_schema('acme_corp')
JobPosting.objects.all()  # Only sees acme_corp jobs

# Tenant B (schema: techstartup)
connection.set_schema('techstartup')
JobPosting.objects.all()  # Only sees techstartup jobs
```

### Authentication Flow

```
┌───────────┐
│  Browser  │
└─────┬─────┘
      │ 1. Login Request
      ▼
┌────────────────┐
│  Django Allauth│
└────────┬───────┘
         │ 2. Credentials Valid?
         ▼
   ┌─────────┐
   │ django-otp│ (Optional 2FA)
   └────┬────┘
        │ 3. OTP Valid?
        ▼
   ┌────────────┐
   │ Session + JWT│
   └────┬────────┘
        │ 4. Set session cookie + JWT token
        ▼
   ┌───────────┐
   │  Response │ (redirect to dashboard)
   └───────────┘
```

**JWT Token Structure:**
```json
{
  "user_id": 123,
  "email": "user@acme.com",
  "tenant_id": "uuid-here",
  "role": "recruiter",
  "exp": 1234567890,
  "iat": 1234567000
}
```

### Permission System

**Tenant-Level RBAC:**

```python
class TenantUser(models.Model):
    role = models.CharField(choices=UserRole.choices)
    custom_permissions = models.ManyToManyField(Permission)
```

**Permission Hierarchy:**
- **Owner/PDG**: Full access to all resources
- **Admin**: Full access except billing
- **HR Manager**: HR operations, employee data
- **Recruiter**: ATS operations, candidate data
- **Hiring Manager**: View/feedback on interviews
- **Employee**: Own profile, time-off requests
- **Viewer**: Read-only access

**Permission Checking:**
```python
from accounts.permissions import check_tenant_permission

@check_tenant_permission('ats.add_jobposting')
def create_job(request):
    # Only allowed if user has permission
    pass
```

### SSRF Protection

**URL Validation:**
```python
from core.validators import validate_url_safe

# Blocks requests to:
# - localhost, 127.0.0.1, ::1
# - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
# - Metadata endpoints (169.254.169.254)
# - DNS rebinding attacks

validate_url_safe(webhook_url)  # Raises ValidationError if unsafe
```

**Note:** Localhost blocking is intentional for production SSRF protection. Development uses `DEBUG=True` to allow localhost.

### Input Validation & Sanitization

**HTML Sanitization:**
```python
import bleach

# Allow safe HTML tags only
safe_html = bleach.clean(
    user_input,
    tags=['p', 'strong', 'em', 'ul', 'ol', 'li', 'a'],
    attributes={'a': ['href', 'title']},
    strip=True
)
```

**SQL Injection Protection:**
- Django ORM provides automatic SQL escaping
- Raw SQL queries use parameterized queries only

**XSS Protection:**
- Template auto-escaping enabled
- CSP headers configured (no inline scripts)
- Input sanitization for rich text (TinyMCE)

### Content Security Policy (CSP)

**Strict CSP (No External CDNs):**
```python
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'",),  # No external scripts
        'style-src': ("'self'", "'unsafe-inline'"),  # Alpine.js requires inline
        'img-src': ("'self'", "data:", "blob:"),
        'font-src': ("'self'",),  # Local fonts only
        'connect-src': ("'self'", "wss:"),  # WebSocket allowed
        'frame-src': ("'none'",),
        'object-src': ("'none'",),
        'base-uri': ("'self'",),
        'form-action': ("'self'",),
    }
}
```

**Static Asset Strategy:**
All frontend libraries served from `staticfiles/assets/js/vendor/`:
- Alpine.js
- HTMX
- Chart.js
- No external CDN dependencies

---

## Deployment Architecture

### Docker Services

```yaml
services:
  db:           # PostgreSQL 16 + PostGIS (port 5434)
  redis:        # Redis 7 (port 6380)
  rabbitmq:     # RabbitMQ 3.12 (ports 5673, 15673)
  web:          # Django + Gunicorn (port 8002)
  channels:     # Django Channels (port 8003)
  celery-worker:# Background tasks (4 workers)
  celery-beat:  # Scheduled tasks
  nginx:        # Reverse proxy (port 8084)
  mailhog:      # Email testing (port 8026)
```

### Service Communication

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Network                       │
│                    (zumodra_network)                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  nginx:80 ──┬──> web:8000      (HTTP requests)          │
│             └──> channels:8001 (WebSocket upgrade)      │
│                                                          │
│  web:8000 ───────> db:5432     (PostgreSQL queries)     │
│            └─────> redis:6379  (Cache + Sessions)       │
│                                                          │
│  celery-worker ──> rabbitmq:5672 (Task consumption)     │
│                └─> db:5432      (Task data access)      │
│                                                          │
│  celery-beat ────> rabbitmq:5672 (Task publishing)      │
│                                                          │
│  channels:8001 ──> redis:6379   (Channel layer)         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Nginx Reverse Proxy Configuration

```nginx
upstream django_web {
    server web:8000;
}

upstream django_channels {
    server channels:8001;
}

server {
    listen 80;

    # Static files (served directly by Nginx)
    location /static/ {
        alias /app/static/;
        expires 30d;
    }

    location /media/ {
        alias /app/media/;
        expires 7d;
    }

    # WebSocket upgrade
    location /ws/ {
        proxy_pass http://django_channels;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Django application
    location / {
        proxy_pass http://django_web;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Database Connection Pooling

**pgBouncer (Production):**
```python
DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.postgresql_backend',
        'HOST': 'pgbouncer',  # Connection pooler
        'PORT': 6432,
        'OPTIONS': {
            'pool_mode': 'transaction',
            'max_db_connections': 100,
        }
    }
}
```

**Connection Limits:**
- Development: 20 connections per container
- Production: 100 connections via pgBouncer

---

## API Architecture

### REST API Structure

```
/api/
├── /                       # API root (version info)
├── /schema/                # OpenAPI schema (JSON)
├── /docs/                  # Swagger UI
├── /redoc/                 # ReDoc documentation
│
├── /v1/                    # API version 1 (current)
│   ├── /auth/              # JWT authentication
│   │   ├── /token/         # Obtain JWT token
│   │   ├── /token/refresh/ # Refresh JWT token
│   │   └── /logout/        # Logout
│   │
│   ├── /tenants/           # Multi-tenant management
│   │   ├── /                # List/create tenants
│   │   ├── /{id}/          # Tenant detail
│   │   └── /{id}/members/  # Tenant members
│   │
│   ├── /accounts/          # User accounts
│   │   ├── /profile/       # User profile
│   │   ├── /kyc/           # KYC verification
│   │   └── /settings/      # User settings
│   │
│   ├── /ats/               # Applicant Tracking System
│   │   ├── /jobs/          # Job postings
│   │   ├── /candidates/    # Candidates
│   │   ├── /applications/  # Applications
│   │   ├── /interviews/    # Interviews
│   │   ├── /offers/        # Job offers
│   │   └── /pipelines/     # Custom pipelines
│   │
│   ├── /hr/                # Human Resources
│   │   ├── /employees/     # Employee records
│   │   ├── /timeoff/       # Time-off requests
│   │   ├── /onboarding/    # Onboarding
│   │   └── /departments/   # Departments
│   │
│   ├── /services/          # Marketplace
│   │   ├── /listings/      # Service listings
│   │   ├── /providers/     # Service providers
│   │   └── /contracts/     # Contracts
│   │
│   ├── /finance/           # Finance & Payments
│   │   ├── /invoices/      # Invoices
│   │   ├── /payments/      # Payments
│   │   └── /subscriptions/ # Subscriptions
│   │
│   ├── /messages/          # Messaging (REST)
│   │   ├── /conversations/ # Message threads
│   │   └── /messages/      # Individual messages
│   │
│   ├── /notifications/     # Notifications
│   │   ├── /                # List notifications
│   │   └── /{id}/read/     # Mark as read
│   │
│   ├── /analytics/         # Analytics & Reporting
│   │   ├── /dashboard/     # Dashboard metrics
│   │   └── /reports/       # Custom reports
│   │
│   └── /integrations/      # Third-party integrations
│       ├── /webhooks/      # Webhook management
│       └── /oauth/         # OAuth connections
│
└── /legacy/                # Legacy API (backwards compatibility)
```

### Authentication Methods

**1. JWT Token Authentication (Primary for API):**
```bash
# Obtain token
POST /api/v1/auth/token/
{
  "username": "user@acme.com",
  "password": "secure_password"
}

# Response
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}

# Use token
GET /api/v1/ats/jobs/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**2. Session Authentication (Web UI):**
- Cookie-based sessions for template views
- CSRF protection enabled

### API Versioning

- **URL Path Versioning**: `/api/v1/`, `/api/v2/`
- **Current Version**: v1
- **Deprecation Policy**: 6-month notice before removal

### Rate Limiting

**DRF Throttle Rates:**
```python
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',        # Anonymous requests
        'user': '1000/hour',       # Authenticated users
        'auth': '5/minute',        # Login/logout
        'token': '10/minute',      # JWT token endpoints
        'password': '3/minute',    # Password reset
        'registration': '5/hour',  # User registration
        'file_upload': '20/hour',  # File uploads
        'export': '10/hour',       # Data exports
    }
}
```

### Pagination

**Default Pagination:**
```python
'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
'PAGE_SIZE': 20,
```

**Response Format:**
```json
{
  "count": 150,
  "next": "https://acme.zumodra.com/api/v1/jobs/?page=2",
  "previous": null,
  "results": [
    { "id": 1, "title": "Software Engineer" },
    ...
  ]
}
```

---

## Real-Time Architecture

### WebSocket Flow

```
┌────────────┐                 ┌────────────┐
│  Browser   │                 │  Browser   │
└─────┬──────┘                 └─────┬──────┘
      │ ws://acme.zumodra.com/ws/chat/  │
      ▼                                 ▼
┌──────────────────────────────────────────┐
│         Nginx (WebSocket Upgrade)        │
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│    Django Channels (Daphne/ASGI)         │
│    - ChatConsumer                        │
│    - NotificationConsumer                │
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│    Redis Channel Layer                   │
│    - Pub/Sub for message distribution    │
│    - Group management                    │
└──────────────────────────────────────────┘
```

### Channel Layer Configuration

**Production (Redis):**
```python
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [('redis', 6379)],
            'capacity': 100000,       # Max messages per channel
            'expiry': 60,             # Message TTL (seconds)
            'group_expiry': 86400,    # Group membership TTL
        },
    },
}
```

### WebSocket Consumer Example

```python
from channels.generic.websocket import AsyncJsonWebsocketConsumer

class ChatConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.tenant = self.scope['tenant']
        self.user = self.scope['user']
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.tenant.schema_name}_{self.room_name}'

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def receive_json(self, content):
        # Handle incoming message
        message = content['message']

        # Broadcast to group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'user': self.user.email,
            }
        )

    async def chat_message(self, event):
        # Send message to WebSocket
        await self.send_json(event)
```

### Real-Time Events

**Supported Event Types:**
- `message.received` - New chat message
- `notification.created` - New notification
- `application.updated` - Application status change
- `interview.reminder` - Interview reminder
- `typing_indicator` - User typing

---

## Background Tasks

### Celery Configuration

**Broker:** RabbitMQ (AMQP)
**Result Backend:** Redis

**Task Queues:**
- `default` - General tasks
- `emails` - Email sending
- `payments` - Payment processing
- `analytics` - Report generation
- `notifications` - Push notifications
- `hr` - HR operations
- `ats` - ATS operations

### Task Routing

```python
CELERY_TASK_ROUTES = {
    'notifications.tasks.send_email_notification': {
        'queue': 'emails',
        'routing_key': 'emails'
    },
    'finance.tasks.process_payment': {
        'queue': 'payments',
        'routing_key': 'payments'
    },
    'ats.tasks.calculate_match_scores': {
        'queue': 'ats',
        'routing_key': 'ats'
    },
}
```

### Scheduled Tasks (Celery Beat)

```python
CELERY_BEAT_SCHEDULE = {
    'cleanup-expired-sessions': {
        'task': 'zumodra.tasks.cleanup_expired_sessions',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
    },
    'send-daily-digest': {
        'task': 'notifications.tasks.send_daily_digest',
        'schedule': crontab(hour=8, minute=0),  # Daily at 8 AM
    },
    'calculate-tenant-usage': {
        'task': 'tenants.tasks.calculate_tenant_usage',
        'schedule': crontab(hour=0, minute=0),  # Daily at midnight
    },
    'sync-stripe-subscriptions': {
        'task': 'finance.tasks.sync_stripe_subscriptions',
        'schedule': crontab(hour='*/6'),  # Every 6 hours
    },
}
```

### Task Example

```python
from celery import shared_task
from django_tenants.utils import schema_context

@shared_task(bind=True, max_retries=3)
def send_interview_reminder(self, interview_id, tenant_schema):
    """Send interview reminder email."""
    try:
        with schema_context(tenant_schema):
            interview = Interview.objects.get(id=interview_id)
            send_email(
                to=interview.candidate.email,
                subject=f"Interview Reminder: {interview.job.title}",
                template='emails/interview_reminder.html',
                context={'interview': interview}
            )
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60)
```

---

## Caching Strategy

### Cache Backends

```python
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://redis:6379/2',
        'KEY_PREFIX': 'zumodra',
    },
    'axes': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://redis:6379/3',
    },
}
```

### Tenant-Aware Caching

**Cache Key Generation:**
```python
def make_tenant_cache_key(key_prefix, tenant, *args):
    """Generate tenant-scoped cache key."""
    return f"{key_prefix}:{tenant.schema_name}:{':'.join(map(str, args))}"

# Example
cache_key = make_tenant_cache_key('jobs', tenant, 'published')
# Result: "jobs:acme_corp:published"
```

### Caching Layers

**1. Database Query Caching:**
```python
from django.core.cache import cache

def get_published_jobs(tenant):
    cache_key = f"jobs:published:{tenant.schema_name}"
    jobs = cache.get(cache_key)

    if jobs is None:
        jobs = JobPosting.objects.filter(status='published')
        cache.set(cache_key, jobs, timeout=300)  # 5 minutes

    return jobs
```

**2. View-Level Caching:**
```python
from django.views.decorators.cache import cache_page

@cache_page(60 * 5)  # Cache for 5 minutes
def job_list_view(request):
    # View logic
    pass
```

**3. Template Fragment Caching:**
```django
{% load cache %}
{% cache 300 job_list tenant.schema_name %}
    {% for job in jobs %}
        {{ job.title }}
    {% endfor %}
{% endcache %}
```

### Cache Invalidation

**Signal-Based Invalidation:**
```python
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=JobPosting)
def invalidate_job_cache(sender, instance, **kwargs):
    cache_key = f"jobs:published:{connection.schema_name}"
    cache.delete(cache_key)
```

**Manual Invalidation:**
```python
from django.core.cache import cache

# Clear specific key
cache.delete(f"jobs:published:{tenant.schema_name}")

# Clear pattern
cache.delete_pattern(f"jobs:*:{tenant.schema_name}")
```

---

## Performance Considerations

### Database Optimization

- **Indexes**: Strategic indexes on foreign keys, status fields, timestamps
- **Query Optimization**: Use `select_related()` and `prefetch_related()`
- **Connection Pooling**: pgBouncer for production
- **Read Replicas**: Separate read/write databases (production)

### Caching Strategy

- **Cache Hit Rate Target**: >90%
- **TTL Guidelines**:
  - Static data: 24 hours
  - Dynamic data: 5-15 minutes
  - User-specific: 1-5 minutes

### Scalability

**Horizontal Scaling:**
- **Web/Channels**: Stateless, scale with load balancer
- **Celery Workers**: Add workers for task queue depth
- **Database**: Read replicas + sharding (future)

**Capacity Planning:**
- Target: 500K concurrent WebSocket connections
- Redis channel layer: 100K messages per channel
- Celery: 4 workers × 1000 tasks = 4000 tasks before restart

---

## Monitoring & Observability

### Health Checks

- `/health/` - Full health check (DB, cache, services)
- `/health/ready/` - Readiness probe (Kubernetes)
- `/health/live/` - Liveness probe (Kubernetes)

### Logging

**Log Levels:**
- ERROR: Application errors, exceptions
- WARNING: Deprecations, slow queries
- INFO: Request logging, task execution
- DEBUG: Development debugging

**Log Destinations:**
- Development: Console
- Production: Rotating file logs + Centralized logging (ELK/Datadog)

### Metrics (Optional)

- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboards
- **Metrics Tracked**:
  - Request latency
  - Cache hit rate
  - Database query time
  - Celery task queue depth
  - WebSocket connection count

---

## Future Architecture Enhancements

### Planned Improvements

1. **Database Sharding**: Distribute tenant schemas across multiple databases
2. **CDN Integration**: CloudFlare/CloudFront for static assets and media
3. **Elasticsearch**: Full-text search for jobs, candidates, messages
4. **Kubernetes**: Container orchestration for auto-scaling
5. **Service Mesh**: Istio for microservices communication
6. **GraphQL API**: Alternative to REST for complex queries
7. **Redis Cluster**: High-availability Redis setup
8. **Multi-Region**: Deploy across multiple AWS regions

### Microservices Migration (Long-term)

Potential service boundaries:
- **Authentication Service**: User auth, sessions, JWT
- **Tenant Service**: Tenant management, billing
- **ATS Service**: Job postings, applications, interviews
- **HR Service**: Employee records, time-off, onboarding
- **Notification Service**: Multi-channel notifications
- **Search Service**: Elasticsearch-backed search

---

## Conclusion

Zumodra's architecture is designed for:
- **Scalability**: Multi-tenant schema isolation, horizontal scaling
- **Security**: Defense in depth with RBAC, 2FA, CSRF, SSRF protection
- **Performance**: Multi-layer caching, connection pooling, async tasks
- **Maintainability**: Clear separation of concerns, modular apps
- **Extensibility**: Plugin architecture for integrations, webhooks

This architecture supports the platform's growth from startup to enterprise scale while maintaining strict tenant isolation and security guarantees.

---

**Document Version:** 1.0
**Last Updated:** 2026-01-16
**Maintained By:** Backend Lead (Phase 1)
