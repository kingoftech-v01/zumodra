# ZUMODRA - Comprehensive Project Plan

## 📋 Project Summary

**Zumodra** is a multi-tenant **CRM & Freelance Services Marketplace Platform** combining:
- Service marketplace (similar to Fiverr/Upwork)
- Appointment booking system
- Financial management with escrow
- Email marketing campaigns
- Real-time messaging system
- Blog/CMS for content marketing

### Main Concept (from CLAUDE.md analysis)
This project started as a learning exercise following the Breakout game planning methodology but evolved into a comprehensive business platform. The goal is to create a production-ready SaaS platform with enterprise features.

---

## 🏗️ Technology Stack

### Backend
- **Framework:** Django 5.2.7 with Python 3.x
- **Database:** PostgreSQL with PostGIS (geospatial support)
- **API:** Django REST Framework
- **Authentication:**
  - Django Allauth (email-based, social auth)
  - 2FA with django-allauth-2fa
  - django-otp
- **Task Queue:** Celery 5.5.3 with Redis
- **Background Jobs:** Django-Q2 for scheduled tasks
- **Channels:** Django Channels for WebSockets (real-time messaging)

### Frontend/Static Files
- **Static Files:** Whitenoise 6.11.0 (for serving static files in production)
- **Templates:** Django Templates with Bootstrap 4
- **Rich Text Editor:** TinyMCE 5.0.0
- **Forms:** django-crispy-forms with Bootstrap 4

### CMS & Content
- **CMS:** Wagtail 7.1.2 (for blog and landing pages)
- **Blog:** Wagtail-based with multilingual support via wagtail-localize
- **Newsletter:** django-newsletter with async sending

### Infrastructure & DevOps
- **Web Server:** Nginx (reverse proxy)
- **WSGI Server:** Gunicorn 23.0.0
- **Container:** Docker + Docker Compose
- **Static Files:** Whitenoise (development) → Nginx (production)

### Security
- **Security Packages:**
  - django-axes (brute force protection)
  - django-csp (Content Security Policy)
  - admin_honeypot (fake admin trap)
  - django-sslserver (SSL for dev)
  - django-auditlog (audit logging)
- **Encryption:** django-cryptography
- **2FA:** Required for all users

### Payment Processing
- **Payment Gateway:** Stripe 13.0.1
- **Features:** Subscriptions, one-time payments, escrow, refunds

### Storage & Media
- **Storage:** django-storages 1.14.6 (S3-compatible)
- **Thumbnails:** sorl-thumbnail 12.11.0
- **Images:** Pillow 11.3.0 with HEIF support

### Data & Analytics
- **Analytics:** django-analytical (Google Analytics, Clicky, etc.)
- **User Tracking:** django-user-tracking
- **GeoIP:** geoip2 with MaxMind database
- **Maps:** django-leaflet with Leaflet.js

### Internationalization
- **i18n:** Django's built-in i18n
- **Supported Languages:**
  - English (en)
  - Spanish (es)
  - French (fr)
  - German (de)
  - Italian (it)
  - Portuguese (pt)
  - Russian (ru)
  - Simplified Chinese (zh-hans)
  - Traditional Chinese (zh-hant)

### Additional Tools
- **Import/Export:** django-import-export
- **Forms:** django-formtools, django-widget-tweaks
- **Tags:** django-taggit
- **History:** django-simple-history
- **Phone Numbers:** django-phonenumber-field

---

## 📊 Current Status Analysis

### ✅ Complete & Production-Ready Apps (7)

1. **appointment** - Full appointment booking system with Stripe payments
2. **finance** - Payment processing, subscriptions, escrow, refunds
3. **messages_sys** - Real-time chat with file uploads and typing indicators
4. **newsletter** - Email campaign management
5. **security** - Comprehensive audit logging and security events
6. **admin_honeypot** - Fake admin for security
7. **custom_account_u** - Basic custom user model

### ⚠️ Partially Implemented Apps (5)

8. **blog** - Wagtail CMS models but views reference old Django models ❌ **BUG**
9. **marketing** - Analytics models but duplicate newsletter models ⚠️ **DUPLICATE**
10. **leads** - Lead capture but duplicates newsletter app ⚠️ **DUPLICATE**
11. **dashboard** - 50+ template-only views with no actual logic ❌ **INCOMPLETE**
12. **services** - Comprehensive marketplace models (99%) but only 1 view (1%) ❌ **MAJOR GAP**

### ❌ Empty/Placeholder Apps (5)

13. **jobs** - Empty (models exist in configurations app)
14. **projects** - Empty (models exist in services app)
15. **dashboard_alert** - Empty
16. **dashboard_job** - Empty
17. **dashboard_project** - Empty

### 🔧 Infrastructure Apps (2)

18. **configurations** - Global settings, company, HR, skills taxonomy
19. **main** - Core tenant models (multi-tenancy support - currently disabled)

---

## 🐛 Identified Bugs & Issues

### Critical Issues

1. **Blog App - Model/View Mismatch**
   - **Location:** `/blog/views.py`
   - **Issue:** Views reference `BlogPost`, `Category`, `Tag` models but actual models are Wagtail `BlogPostPage`, `CategoryPage`
   - **Impact:** Blog views will fail with "Model does not exist" errors
   - **Fix Required:** Rewrite views to use Wagtail Page API or migrate back to traditional Django models

2. **Services App - 99% Incomplete Views**
   - **Location:** `/services/views.py`
   - **Issue:** Complex marketplace models exist but only 1 view (`browse_service`) implemented
   - **Missing:**
     - Service CRUD views
     - Provider profile management
     - Proposal submission/acceptance
     - Contract management
     - Search/filter/matching logic
     - API endpoints
   - **Impact:** Core marketplace functionality non-functional

3. **Dashboard App - Template-Only Views**
   - **Location:** `/dashboard/views.py`
   - **Issue:** 50+ views just render templates with no QuerySets or data processing
   - **Impact:** Dashboard shows empty/static data

### Data Duplication Issues

4. **Newsletter Model Duplication**
   - Exists in: `/newsletter/`, `/leads/`, `/marketing/`
   - **Fix Required:** Consolidate into single app

5. **Job Models Split**
   - Job models in `/configurations/` but empty `/jobs/` app exists
   - **Fix Required:** Remove `/jobs/` app

6. **Project Models Split**
   - Service request models in `/services/` but empty `/projects/` app exists
   - **Fix Required:** Remove `/projects/` app

### Configuration Issues

7. **Multi-Tenancy Disabled**
   - `django_tenants` middleware commented out in settings
   - Tenant models exist but not activated
   - **Decision Required:** Enable or remove tenant infrastructure

8. **Hardcoded Secrets in Settings**
   - Secret key, database credentials, email password hardcoded
   - **Security Risk:** High
   - **Fix Required:** Move all secrets to `.env` file

9. **SSL/Security Settings for Development**
   - `SECURE_SSL_REDIRECT = True` will break local development
   - `SESSION_COOKIE_SECURE = True` requires HTTPS
   - **Fix Required:** Conditional settings based on DEBUG mode

10. **Commented Dependencies**
    - `django-q` commented in requirements but `django_q` used in code
    - **Fix Required:** Clarify which version to use

### Missing Configurations

11. **Nginx Configuration Missing**
    - No `nginx.conf` file in project
    - **Required for:** Production deployment

12. **Celery Configuration Incomplete**
    - Broker URL configured but no `celery.py` app initialization visible
    - **Required for:** Background tasks

13. **Docker Issues**
    - Dockerfile exists but may need updates for Nginx integration
    - No docker-compose service for Nginx
    - **Required for:** Production deployment

14. **Wagtail Admin Not Configured**
    - Wagtail installed but admin might not be accessible
    - **Check:** Wagtail URL patterns

---

## 🗑️ Apps to Remove

Create file: `APPS_TO_DELETE.txt`

```
apps/jobs/                    # Empty, models in configurations
apps/projects/                # Empty, models in services
apps/dashboard_alert/         # Empty placeholder
apps/dashboard_job/           # Empty placeholder
apps/dashboard_project/       # Empty placeholder
```

**Rationale:**
- `jobs` - Duplicate of `configurations.Job` model
- `projects` - Duplicate of `services` DServiceRequest workflow
- `dashboard_*` - Empty placeholders that should be features within main dashboard app

---

## 🎯 Priority Implementation Plan

### Phase 1: Foundation & Bug Fixes (P1 - Critical)

#### Week 1-2: Infrastructure Setup
- [ ] Fix hardcoded secrets → move to environment variables
- [ ] Create proper `.env.example` file
- [ ] Fix SSL settings for development vs production
- [ ] Set up Nginx configuration
- [ ] Configure Celery worker and beat scheduler
- [ ] Update Docker Compose with all services (Django, PostgreSQL, Redis, Nginx, Celery)
- [ ] Test full Docker deployment

#### Week 3: Critical Bug Fixes
- [ ] **Blog App:** Decide Wagtail vs traditional Django
  - If Wagtail: Rewrite all views to use Wagtail Page API
  - If Django: Remove Wagtail, create traditional BlogPost models
- [ ] **Security Settings:** Fix SSL/CSRF settings for dev/prod
- [ ] **Database:** Verify PostGIS installation and configuration
- [ ] Run migrations and verify database integrity

### Phase 2: Core Features (P1 - Essential)

#### Week 4-5: Services Marketplace (Top Priority)
- [ ] Create service browsing views (list, detail, search, filter)
- [ ] Provider profile CRUD views
- [ ] Service creation/editing forms
- [ ] Client request submission
- [ ] Proposal system (create, view, accept/reject)
- [ ] Contract initiation and management
- [ ] Service search with geolocation filtering
- [ ] Rating and review system
- [ ] API endpoints for mobile/SPA

#### Week 6: Dashboard Enhancement
- [ ] Dashboard models for metrics tracking
- [ ] Real QuerySets for all dashboard views
- [ ] Analytics aggregation (using marketing app data)
- [ ] User-specific dashboards (client vs provider vs admin)
- [ ] Charts and visualizations (Chart.js or similar)

#### Week 7: Newsletter Consolidation
- [ ] Audit all three newsletter implementations
- [ ] Merge into single canonical app
- [ ] Update all references
- [ ] Remove duplicate code
- [ ] Test email sending with Celery

### Phase 3: Enhancement & Polish (P2 - Important)

#### Week 8-9: Wagtail CMS & Blog
- [ ] Configure Wagtail admin properly
- [ ] Create Wagtail pages for:
  - Homepage (vitrine/landing page)
  - About Us
  - Services showcase
  - Pricing page
  - Blog index and posts
- [ ] Set up wagtail-localize for multilingual content
- [ ] Create StreamField components for flexible layouts
- [ ] SEO optimization (meta tags, sitemaps)

#### Week 10: Internationalization
- [ ] Extract all translatable strings
- [ ] Generate `.po` files for all 9 languages
- [ ] Configure language switcher in templates
- [ ] Test all apps in different languages
- [ ] RTL support for Arabic (if added later)

#### Week 11: Payment & Finance Enhancements
- [ ] Test Stripe webhooks
- [ ] Implement subscription upgrade/downgrade
- [ ] Escrow release workflows
- [ ] Refund automation
- [ ] Invoice generation (PDF)
- [ ] Payment method management UI

#### Week 12: Messaging Enhancements
- [ ] Voice message support
- [ ] Message reactions
- [ ] Message search
- [ ] File preview in chat
- [ ] Video call integration (optional - Jitsi/Twilio)

### Phase 4: Production Readiness (P2 - Polish)

#### Week 13-14: Testing & Optimization
- [ ] Write unit tests for critical models
- [ ] Integration tests for workflows
- [ ] Load testing (locust or similar)
- [ ] Security audit (django-admin check --deploy)
- [ ] Performance optimization (database indexes, query optimization)
- [ ] Static file optimization (minification, CDN)

#### Week 15: Deployment & Monitoring
- [ ] Production environment setup
- [ ] Environment-specific settings files
- [ ] Logging configuration (Sentry integration)
- [ ] Backup strategy (database, media files)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Monitoring setup (uptime, performance)
- [ ] Documentation (API docs, admin guide, user guide)

### Phase 5: Advanced Features (P3 - Nice to Have)

#### Future Enhancements
- [ ] Mobile app (React Native or Flutter)
- [ ] Advanced AI matching for services
- [ ] Video portfolio for providers
- [ ] Live streaming for consultations
- [ ] Referral program
- [ ] Affiliate marketing
- [ ] Multi-currency support
- [ ] Advanced analytics dashboard
- [ ] Export reports (Excel, PDF)
- [ ] Calendar integrations (Google Calendar, Outlook)

---

## 🏛️ Proposed Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Nginx (Reverse Proxy)                 │
│                     (SSL, Static Files, Load Balancing)      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Gunicorn (WSGI Server)                  │
│                     Django Application                        │
│  ┌──────────────┬──────────────┬──────────────┬───────────┐ │
│  │   Wagtail    │   Services   │  Appointment │  Finance  │ │
│  │   CMS/Blog   │  Marketplace │   Booking    │  Payments │ │
│  └──────────────┴──────────────┴──────────────┴───────────┘ │
│  ┌──────────────┬──────────────┬──────────────┬───────────┐ │
│  │  Messaging   │  Newsletter  │  Marketing   │ Security  │ │
│  │  Real-time   │  Campaigns   │  Analytics   │  Audit    │ │
│  └──────────────┴──────────────┴──────────────┴───────────┘ │
└─────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌────────────────────┐              ┌─────────────────────┐
│   PostgreSQL       │              │   Redis             │
│   + PostGIS        │              │   - Cache           │
│   (Primary DB)     │              │   - Celery Broker   │
└────────────────────┘              │   - Channels Layer  │
                                    └─────────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────────┐
                                    │  Celery Workers     │
                                    │  - Email sending    │
                                    │  - Analytics        │
                                    │  - Notifications    │
                                    └─────────────────────┘
```

### Application Layer Structure

```
zumodra/
├── apps/
│   ├── appointment/        ✅ Complete
│   ├── finance/           ✅ Complete
│   ├── messages_sys/      ✅ Complete
│   ├── newsletter/        ✅ Complete
│   ├── security/          ✅ Complete
│   ├── blog/              ⚠️ Fix Wagtail integration
│   ├── services/          ⚠️ Add views/API
│   ├── dashboard/         ⚠️ Add real logic
│   ├── marketing/         ⚠️ Remove duplicates
│   ├── custom_account_u/  ⚠️ Enhance profiles
│   └── configurations/    ⚠️ Helper models
├── docker/
│   ├── nginx/
│   │   └── nginx.conf     ❌ CREATE
│   ├── celery/
│   │   └── worker.sh      ❌ CREATE
│   └── django/
│       └── entrypoint.sh  ❌ CREATE
├── static/                (collected by collectstatic)
├── staticfiles/           (source files)
├── media/                 (user uploads)
├── templates/             (global templates)
├── locale/                (i18n translations)
└── zumodra/              (project settings)
    ├── settings/          ❌ CREATE
    │   ├── base.py
    │   ├── development.py
    │   ├── production.py
    │   └── test.py
    ├── celery.py          ❌ CREATE
    └── urls.py
```

---

## 🔒 Security Enhancements Required

1. **Environment Variables**
   ```python
   # Move these to .env
   SECRET_KEY
   DATABASE_URL
   EMAIL_HOST_PASSWORD
   STRIPE_SECRET_KEY
   STRIPE_PUBLIC_KEY
   REDIS_URL
   ALLOWED_HOSTS
   ```

2. **Conditional Security Settings**
   ```python
   if not DEBUG:
       SECURE_SSL_REDIRECT = True
       SESSION_COOKIE_SECURE = True
       CSRF_COOKIE_SECURE = True
   ```

3. **CSP Configuration**
   - Currently just enabled, needs actual policy

4. **Rate Limiting**
   - Add django-ratelimit for API endpoints

5. **API Authentication**
   - Add JWT or Token authentication for REST API

---

## 📝 Implementation Notes

### Multi-tenancy Decision
- **Current:** Tenant models exist but middleware disabled
- **Options:**
  1. Enable django-tenants for true SaaS multi-tenancy
  2. Use single-schema with company/site filtering
- **Recommendation:** Start with single-schema, add tenancy later if needed

### Wagtail vs Traditional Blog
- **Current:** Wagtail models with Django views (incompatible)
- **Options:**
  1. Full Wagtail: Rich admin, StreamFields, but more complex
  2. Traditional Django: Simpler, more control, but basic admin
- **Recommendation:** Keep Wagtail for CMS/marketing pages, use for blog too

### Database Strategy
- **Primary:** PostgreSQL with PostGIS (geospatial queries for service matching)
- **Cache:** Redis for sessions, Celery, Channels
- **Search:** Consider adding Elasticsearch for advanced search (later)

---

## 📦 New Apps to Create

None needed - existing apps cover all functionality once completed.

Consider creating:
- `api/` - Centralized REST API app with viewsets
- `notifications/` - In-app notification system (separate from messages)
- `analytics/` - Enhanced analytics dashboard

---

## 🎨 Frontend Architecture

### Current State
- Server-rendered Django templates
- Bootstrap 4 styling
- jQuery for interactions
- TinyMCE for rich text

### Enhancement Options
- Add HTMX for dynamic interactions without full SPA
- Consider Vue.js or React for complex UIs (dashboard, messaging)
- Keep server-rendered for SEO-critical pages (blog, landing)

---

## 📚 Documentation Plan

1. **README.md** - Project overview, setup instructions
2. **API_DOCUMENTATION.md** - REST API endpoints
3. **DEPLOYMENT.md** - Production deployment guide
4. **CONTRIBUTING.md** - Development guidelines
5. **USER_GUIDE.md** - End-user documentation
6. **ADMIN_GUIDE.md** - Admin panel guide

---

## 🎓 Learning Objectives (from CLAUDE.md)

Based on the planning framework, this project teaches:
- ✅ Django advanced features (signals, middleware, custom user)
- ✅ Real-time applications (Channels, WebSockets)
- ✅ Payment processing (Stripe integration)
- ✅ Security best practices (2FA, audit logging, CSP)
- ✅ Deployment (Docker, Nginx, Gunicorn)
- ⏳ API design (REST Framework) - TO COMPLETE
- ⏳ CMS integration (Wagtail) - TO COMPLETE
- ⏳ Background tasks (Celery) - TO CONFIGURE

---

## 🎯 Success Metrics

### Technical Metrics
- All migrations apply successfully
- No critical bugs in production
- < 2s page load time (95th percentile)
- 99.9% uptime
- All API endpoints documented
- 80%+ test coverage

### Business Metrics
- User registration functional
- Service marketplace operational
- Appointment booking working
- Payment processing successful
- Email campaigns sending
- Multi-language support active

---

**Last Updated:** December 25, 2025
**Status:** Planning Complete, Implementation Phase 1 Starting
