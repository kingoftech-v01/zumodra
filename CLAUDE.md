# Zumodra Development Context

## Project Identity

**Zumodra** is a multi-tenant ATS (Applicant Tracking System) and HRIS (Human Resource Information System) SaaS platform with integrated freelance marketplace, built by **Rhematek Solutions** (CEO: Stephane Arthur Victor).

**Mission**: "Verify. Recruit. Hire. Risk-Free."

**Core Differentiator**: Bidirectional KYC verification of both candidates AND recruiters/employers, with progressive data revelation and escrow-protected payments.

---

## Technology Stack

```
Backend:
- Python 3.13+ / Django 5.x
- django-tenants (schema-per-tenant multi-tenancy)
- Django REST Framework (DRF) for APIs
- Celery 5.x + Redis (async tasks, caching, WebSocket channels)
- PostgreSQL 16 with PostGIS (geospatial queries)

Frontend:
- Django templates + HTMX + Alpine.js
- Tailwind CSS + Bootstrap 5 (selective)
- WCAG 2.1 AA accessibility target

Infrastructure:
- Docker + Docker Compose
- Nginx + Gunicorn
- GitHub Actions (CI/CD)

Key Integrations:
- Stripe Connect (escrow payments, subscriptions)
- Sumsub/Onfido (KYC/IDV verification)
- DocuSign (e-signatures)
- Twilio (SMS)
- SendGrid (email)
- Calendly (interview scheduling)
```

---

## Multi-Tenancy Architecture

### Schema Structure
- **Public schema**: Shared data (Plans, Features, GlobalConfigs)
- **Tenant schemas**: Isolated per-tenant data (HR, ATS, users)

### Tenant Hierarchy
```
Tenant (Enterprise)
    └── Circusale (Business Unit/Division)
            └── Users (with roles)
```

### Key Models
```python
# Tenant = Enterprise with subdomain (e.g., acme.zumodra.com)
# Circusale = Location/division with PostGIS coordinates
# TenantUser = User with role assignment per tenant/circusale
```

### Role Hierarchy (Per Tenant)
```
SuperAdmin (platform-wide)
├── TenantAdmin (full tenant control)
├── RHAdmin (HR operations + analytics)
├── Recruiter (ATS pipelines + candidates)
├── HiringManager (own jobs + team candidates)
├── RHOperational (absences + onboarding only)
└── Viewer (read-only dashboards)
```

---

## Core Feature Domains

### 1. Two-Level Verification System
- **Level 1 (KYC)**: ID + selfie + liveness for candidates; business KYC for employers
- **Level 2 (Career)**: Employment verification emails + education verification
- Statuses: `UNVERIFIED`, `PENDING`, `VERIFIED`, `DISPUTED`

### 2. Hybrid Ranking Engine
```
MatchScore = w_r * RuleScore + w_a * AIScore + w_v * VerificationScore + w_t * TrustScore
```
- RuleScore: Boolean filters, hard constraints, keyword matching
- AIScore: Semantic similarity, skills graph, pattern detection
- Weights are tenant-configurable

### 3. Trust System
- Multi-dimension trust scores for candidates, employers, schools
- AI-assisted review verification for negative reviews
- Badges: "ID Verified", "Career Verified", "High Trust"

### 4. Freelance Marketplace with Escrow
- Stripe Connect delayed payouts (escrow-style)
- Workflow: Post -> Fund -> Deliver -> Accept/Dispute -> Payout
- KYC required for both parties before transactions

### 5. Progressive Data Revelation
```
Stage 1: Name, photo, experience summary, skills, city
Stage 2 (after "Interested"): Phone, LinkedIn, availability, salary
Stage 3 (post-interview): Full address, references, work eligibility
Stage 4 (offer accepted): NAS/SSN, medical docs, emergency contacts
```

### 6. Multi-Circuit Talent Management
1. External Recruitment (public job boards)
2. Internal Mobility (current employees)
3. Talent Pool/Alumni (former candidates/employees)
4. Freelancers/Contractors (mission-based)

### 7. Co-op/Student Ecosystem
- Streams: University Co-op, College Co-op, Junior Internships, Apprenticeships
- School-Employer-Student triad with approval workflows
- Academic verification integration

---

## Django Apps Structure

| App | Purpose |
|-----|---------|
| `tenants` / `main` | Tenant lifecycle, plans, billing, domain mapping |
| `accounts` / `custom_account_u` | Users, roles, permissions, KYC status |
| `ats` | Jobs, applications, pipelines, matching engine |
| `hr_core` | Employees, absences, schedules, resignations |
| `documents` | Contracts, e-signatures, secure storage |
| `analytics` | Diversity metrics, workforce health, reporting |
| `integrations` | Stripe, KYC providers, DocuSign, email, SMS |
| `services` | Freelance marketplace services |
| `finance` | Escrow, payments, subscriptions |
| `messages` | Real-time messaging (WebSockets) |
| `marketing` / `newsletter` | Campaigns, events, newsletters |
| `configurations` | Platform settings, skills taxonomy |

---

## Critical Development Rules

### Multi-Tenant Safety
```python
# ALWAYS scope queries by tenant
# NEVER use raw queries without tenant context
# Celery tasks MUST carry tenant_id and switch schema

# Good:
queryset = Model.objects.filter(tenant=request.tenant)

# Bad:
queryset = Model.objects.all()  # Cross-tenant data leak!
```

### Security Requirements
- All admin/HR roles require TOTP 2FA
- Sensitive fields (NAS, salary, medical) encrypted at rest (AES-256)
- CSRF protection on all state-changing endpoints
- Rate limiting on auth endpoints
- Audit logging for security-critical actions

### API Design
- Use DRF serializers with proper validation
- JWT for external API access (48h expiry)
- Session auth for internal web flows
- Always check permissions per request

### Database Migrations
- Every schema change needs a Django migration
- Test migrations on both public and tenant schemas
- Never modify production data directly

---

## Key Business Logic

### Subscription Plans
| Plan | Price | Features |
|------|-------|----------|
| Starter | €15/user | 3 pipelines, basic ATS, email only |
| Pro | €25/user | Unlimited pipelines, CV parsing, SMS |
| Business | €35/user | Multi-circuits, e-signature, analytics |
| Enterprise | Custom | SSO, API, dedicated support |

### Verification Flow
1. User uploads ID + selfie
2. System sends to Sumsub/Onfido
3. Async Celery task processes result
4. Status updated, badge assigned
5. For Level 2: automated emails to employers/schools

### Escrow Payment Flow
1. Client funds milestone -> Stripe captures funds
2. Funds held in platform (delayed payout)
3. Freelancer delivers via platform
4. Client accepts -> payout released
5. Dispute -> AI analysis + evidence collection -> resolution

---

## File Structure Conventions

```
zumodra/
├── apps/                    # Django applications
│   ├── tenants/
│   ├── accounts/
│   ├── ats/
│   └── ...
├── config/                  # Project settings
│   ├── settings/
│   │   ├── base.py
│   │   ├── local.py
│   │   └── production.py
│   ├── urls.py
│   └── wsgi.py
├── templates/               # Django templates
├── static/                  # Static files
├── docs/                    # Documentation
│   └── FEATURES.md          # Complete feature specification
├── docker/                  # Docker configurations
├── .env.example             # Environment variables template
└── CLAUDE.md                # This file
```

---

## Common Patterns

### Creating a Tenant-Scoped View
```python
from django_tenants.utils import get_tenant_model

class MyView(LoginRequiredMixin, View):
    def get(self, request):
        tenant = request.tenant
        # All queries automatically scoped to tenant schema
        items = MyModel.objects.all()  # Only returns tenant's data
        return render(request, 'template.html', {'items': items})
```

### Creating a Celery Task with Tenant Context
```python
from celery import shared_task
from django_tenants.utils import schema_context

@shared_task
def process_verification(tenant_schema, user_id):
    with schema_context(tenant_schema):
        user = User.objects.get(id=user_id)
        # Process within tenant context
```

### HTMX Partial Update Pattern
```html
<!-- In template -->
<div id="candidate-list" hx-get="/candidates/" hx-trigger="load">
    Loading...
</div>

<!-- View returns partial -->
def candidate_list(request):
    candidates = Candidate.objects.filter(...)
    return render(request, 'partials/candidate_list.html', {'candidates': candidates})
```

---

## Environment Variables

Key variables required (see `.env.example`):
```
DATABASE_URL=postgres://...
REDIS_URL=redis://...
SECRET_KEY=...
STRIPE_SECRET_KEY=...
STRIPE_PUBLISHABLE_KEY=...
SUMSUB_API_KEY=...
DOCUSIGN_API_KEY=...
SENDGRID_API_KEY=...
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
```

---

## Testing Requirements

- Target: ≥90% coverage on core apps
- Run: `pytest` or `python manage.py test`
- Always test:
  - Tenant isolation (no cross-tenant leaks)
  - Permission checks (role-based access)
  - Verification flows
  - Payment flows

---

## What NOT to Do

1. **Never bypass tenant isolation** - All queries must be tenant-scoped
2. **Never store secrets in code** - Use environment variables
3. **Never skip migrations** - Database changes need migrations
4. **Never expose PII in logs** - Sanitize sensitive data
5. **Never allow cross-tenant joins** - Schemas are isolated
6. **Never commit .env files** - Only .env.example
7. **Never use debug mode in production** - Security risk
8. **Never skip CSRF protection** - Required for all forms
9. **Never trust user input** - Always validate and sanitize
10. **Never use raw SQL without parameterization** - SQL injection risk

---

## Quick Reference: Common Tasks

### Add a new model
1. Create model in appropriate app
2. Add to `TENANT_APPS` or `SHARED_APPS` in settings
3. Run `python manage.py makemigrations`
4. Run `python manage.py migrate_schemas`

### Add a new API endpoint
1. Create serializer in `serializers.py`
2. Create viewset in `views.py`
3. Register in `urls.py`
4. Add permission classes
5. Test tenant isolation

### Add a new Celery task
1. Create task in `tasks.py`
2. Include tenant_schema parameter
3. Use `schema_context` wrapper
4. Register in Celery beat if scheduled

### Deploy changes
1. Push to feature branch
2. Open PR, wait for CI
3. Merge after approval
4. CI deploys to staging
5. Manual approval for production

---

## Documentation Reference

For complete feature specifications, see:
- [docs/FEATURES.md](docs/FEATURES.md) - Full platform documentation (23 sections)

This includes:
- All feature details
- Technical architecture
- Product roadmap
- Go-to-market strategy
- Security and compliance
- Build execution prompts
- QA procedures

---

## Contact

**Company**: Rhematek Solutions
**CEO**: Stephane Arthur Victor
**Platform**: Zumodra ATS/RH
