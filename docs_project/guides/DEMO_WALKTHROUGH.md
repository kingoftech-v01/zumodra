# Zumodra Demo Walkthrough
## Presentation Guide for Demo Day

**Date:** January 17, 2026
**Domain:** https://zumodra.rhematek-solutions.com
**Duration:** 20-30 minutes
**Audience:** Prospective clients, investors, partners

---

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [Pre-Demo Checklist](#pre-demo-checklist)
3. [Demo Credentials](#demo-credentials)
4. [Demo Flow](#demo-flow)
5. [Feature Highlights](#feature-highlights)
6. [Talking Points](#talking-points)
7. [Troubleshooting](#troubleshooting)

---

## Quick Reference

### Primary URLs

| Section | URL | Purpose |
|---------|-----|---------|
| **Homepage** | https://zumodra.rhematek-solutions.com | Public landing page |
| **Login** | https://zumodra.rhematek-solutions.com/accounts/login/ | Authentication |
| **Dashboard** | https://zumodra.rhematek-solutions.com/app/dashboard/ | Main dashboard |
| **ATS Jobs** | https://zumodra.rhematek-solutions.com/app/jobs/jobs/ | Job listings |
| **ATS Pipeline** | https://zumodra.rhematek-solutions.com/app/jobs/pipeline/ | Kanban board |
| **ATS Candidates** | https://zumodra.rhematek-solutions.com/app/jobs/candidates/ | Candidate database |
| **HR Directory** | https://zumodra.rhematek-solutions.com/app/hr/employees/ | Employee directory |
| **HR Time-off** | https://zumodra.rhematek-solutions.com/app/hr/time-off/calendar/ | Time-off calendar |
| **API Docs** | https://zumodra.rhematek-solutions.com/api/docs/ | Interactive API documentation |
| **API Schema** | https://zumodra.rhematek-solutions.com/api/schema/ | OpenAPI specification |

### API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/auth/token/` | POST | Obtain JWT tokens |
| `/api/v1/jobs/jobs/` | GET | List all jobs |
| `/api/v1/jobs/candidates/` | GET | List candidates |
| `/api/v1/hr/employees/` | GET | List employees |
| `/api/v1/dashboard/overview/` | GET | Dashboard stats |
| `/health/` | GET | Health check |

---

## Pre-Demo Checklist

### 24 Hours Before Demo

- [ ] Verify all services are running (web, database, Redis, RabbitMQ)
- [ ] Check SSL certificate is valid
- [ ] Test login with demo credentials
- [ ] Verify sample data exists (jobs, candidates, employees)
- [ ] Test all major URLs are accessible
- [ ] Clear browser cache and cookies
- [ ] Prepare backup browser with logged-in session
- [ ] Test API endpoints with Postman/Swagger
- [ ] Check email notifications are working (MailHog/real SMTP)
- [ ] Verify WebSocket connection for messaging

### 1 Hour Before Demo

- [ ] System health check: `curl https://zumodra.rhematek-solutions.com/health/`
- [ ] Test login flow
- [ ] Open all demo tabs in browser
- [ ] Test HTMX interactions (pipeline drag-and-drop)
- [ ] Verify mobile responsive view
- [ ] Check for any error messages in logs
- [ ] Have backup presentation slides ready

### During Setup

- [ ] Connect to projector/screen share
- [ ] Open Chrome DevTools (optional, for showing network requests)
- [ ] Set browser zoom to 125% for better visibility
- [ ] Have Postman collection ready for API demo
- [ ] Keep system health dashboard open in background tab

---

## Demo Credentials

### Main Demo Account

**Email:** demo@zumodra.com
**Password:** Demo123!
**Role:** Admin (PDG)
**Access:** Full platform access

### Additional Test Accounts (if needed)

| Role | Email | Password | Access Level |
|------|-------|----------|--------------|
| HR Manager | hr@demo.zumodra.local | Demo@2024! | HR Core + Employee Management |
| Recruiter | recruiter@demo.zumodra.local | Demo@2024! | ATS Only |
| Employee | employee@demo.zumodra.local | Demo@2024! | Self-service dashboard |

### API Authentication

```bash
# Get JWT Token
curl -X POST https://zumodra.rhematek-solutions.com/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@zumodra.com", "password": "Demo123!"}'

# Response:
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}

# Use access token in subsequent requests
curl https://zumodra.rhematek-solutions.com/api/v1/jobs/jobs/ \
  -H "Authorization: Bearer <access_token>"
```

---

## Demo Flow

### Part 1: Public Site (3 minutes)

**URL:** https://zumodra.rhematek-solutions.com

#### Actions:
1. Load homepage
2. Scroll through hero section
3. Click "About Us" - showcase company information
4. Click "Pricing" - show subscription tiers
5. Click "Features" - highlight key capabilities
6. Click "Contact" - show contact form

#### Talking Points:
- "Zumodra is an all-in-one HR and recruitment platform designed for modern businesses"
- "We combine ATS, HR management, and freelance marketplace in one unified platform"
- "Built with multi-tenancy from the ground up - each client gets isolated, secure data"
- "Notice the clean, professional design - no external CDN dependencies for security"

---

### Part 2: Authentication & Security (2 minutes)

**URL:** https://zumodra.rhematek-solutions.com/accounts/login/

#### Actions:
1. Show login page
2. Enter credentials: `demo@zumodra.com` / `Demo123!`
3. Mention 2FA capability (optional demo)
4. Successfully log in

#### Talking Points:
- "Enterprise-grade security with JWT authentication"
- "2FA mandatory for all users after 30 days"
- "Brute force protection with django-axes (5 failed attempts = 1-hour lockout)"
- "Session management with automatic timeout"
- "All API calls are authenticated and rate-limited by subscription tier"

---

### Part 3: Dashboard Overview (3 minutes)

**URL:** https://zumodra.rhematek-solutions.com/app/dashboard/

#### Actions:
1. Show dashboard widgets
2. Point out quick stats (open jobs, candidates, interviews, employees)
3. Scroll through recent activity feed
4. Show upcoming interviews widget
5. Demo global search (top right) - search for "engineer"

#### Talking Points:
- "The dashboard provides at-a-glance metrics for your entire organization"
- "Real-time updates via HTMX - no page refreshes needed"
- "Global search across jobs, candidates, employees, and applications"
- "Customizable widgets based on user role and permissions"
- "Notice the clean, modern UI built with Tailwind CSS - all served locally"

#### Key Metrics to Highlight:
- Open jobs count
- Total candidates in pipeline
- Pending interviews
- Active employees
- Recent activity timeline

---

### Part 4: ATS - Applicant Tracking System (8 minutes)

#### A. Job Listings (2 minutes)

**URL:** https://zumodra.rhematek-solutions.com/app/jobs/jobs/

**Actions:**
1. Show job list with filters (status, category, job type)
2. Click on a job posting (e.g., "Senior Software Engineer")
3. Show job details, requirements, and benefits
4. Point out application count and recent applicants
5. Demo quick actions: Edit, Duplicate, Close job

**Talking Points:**
- "Complete job management - create, edit, duplicate, archive, and close jobs"
- "Rich job descriptions with requirements, responsibilities, and benefits"
- "Category-based organization for easy management"
- "Track applications per job with pipeline visualization"
- "Public job board integration (if enabled)"

#### B. Pipeline Board (3 minutes)

**URL:** https://zumodra.rhematek-solutions.com/app/jobs/pipeline/

**Actions:**
1. Show Kanban-style pipeline board
2. Explain pipeline stages (New → Screening → Interviewing → Offer → Hired)
3. Drag a candidate card from one stage to another (HTMX demo)
4. Show real-time update without page refresh
5. Filter by job posting

**Talking Points:**
- "Visual Kanban board for managing candidate pipeline"
- "Drag-and-drop interface powered by HTMX (no JavaScript frameworks needed)"
- "Customizable pipeline stages per job or company-wide"
- "Real-time collaboration - multiple recruiters can work simultaneously"
- "Activity logging tracks every move for audit trails"

**Demo Sequence:**
1. Select a specific job from dropdown
2. Drag candidate "John Doe" from "Screening" to "Interviewing"
3. Show automatic activity log entry
4. Mention notification sent to hiring manager

#### C. Candidate Management (2 minutes)

**URL:** https://zumodra.rhematek-solutions.com/app/jobs/candidates/

**Actions:**
1. Show candidate directory with search and filters
2. Click on a candidate profile
3. Show candidate details: resume, skills, experience
4. Point out application history across multiple jobs
5. Show activity timeline (notes, interviews, status changes)
6. Demo quick actions: Schedule interview, Add note, Send email

**Talking Points:**
- "Centralized candidate database with full search capabilities"
- "Track candidate journey across multiple job applications"
- "Resume parsing and skill extraction (AI-powered)"
- "Communication history and activity logs"
- "Compliance-ready with GDPR data retention policies"

#### D. Interview Scheduling (1 minute)

**URL:** https://zumodra.rhematek-solutions.com/app/jobs/interviews/

**Actions:**
1. Show interview list (upcoming, today, past)
2. Click "Schedule Interview"
3. Show interview form: type, date/time, interviewers, location/meeting link
4. Demonstrate interview types: Phone, Video, In-person, Technical

**Talking Points:**
- "Built-in interview scheduling with calendar integration"
- "Multiple interview types supported"
- "Automatic email notifications to candidates and interviewers"
- "Interview feedback forms with structured ratings"
- "Reschedule and cancel capabilities with reason tracking"

---

### Part 5: HR Core (6 minutes)

#### A. Employee Directory (2 minutes)

**URL:** https://zumodra.rhematek-solutions.com/app/hr/employees/

**Actions:**
1. Show employee directory with department filters
2. Search for an employee
3. Click on employee profile
4. Show employee details: contact info, job title, department, manager
5. Point out time-off balances, certifications, and skills
6. Show direct reports (if manager)

**Talking Points:**
- "Complete employee management system"
- "Department and team-based organization"
- "Manager hierarchy with org chart visualization"
- "Skills tracking and certification management"
- "Employment history and performance reviews"
- "Self-service portals for employees"

#### B. Time-Off Management (3 minutes)

**URL:** https://zumodra.rhematek-solutions.com/app/hr/time-off/calendar/

**Actions:**
1. Show time-off calendar with color-coded leave types
2. Filter by department
3. Click "Request Time Off"
4. Fill out request form (vacation, 3 days, reason)
5. Show approval workflow
6. Point out time-off balances

**Talking Points:**
- "Visual calendar for team absence planning"
- "Multiple leave types: vacation, sick, personal, parental"
- "Accrual-based or unlimited PTO policies"
- "Multi-level approval workflows (manager → HR)"
- "Automatic balance deductions on approval"
- "Integration with payroll systems (via API)"

**Key Features:**
- Conflict detection (overlapping requests)
- Holiday calendar integration
- Carryover policies
- Negative balance prevention

#### C. Organization Chart (1 minute)

**URL:** https://zumodra.rhematek-solutions.com/app/hr/org-chart/

**Actions:**
1. Show hierarchical org chart
2. Hover over employee nodes to see details
3. Expand/collapse departments
4. Filter by department

**Talking Points:**
- "Interactive organization chart with drill-down capabilities"
- "Visual representation of reporting structure"
- "Dynamic updates as employees join/leave"
- "Department-based filtering"

---

### Part 6: API & Integrations (4 minutes)

#### A. API Documentation (2 minutes)

**URL:** https://zumodra.rhematek-solutions.com/api/docs/

**Actions:**
1. Show Swagger UI with all endpoints
2. Expand "ATS" section to show job endpoints
3. Click "GET /api/v1/jobs/jobs/"
4. Show request parameters (filters, pagination)
5. Click "Try it out" and execute
6. Show JSON response with job listings

**Talking Points:**
- "RESTful API with full OpenAPI 3.0 specification"
- "Interactive documentation with try-it-out functionality"
- "JWT authentication for all endpoints"
- "Comprehensive endpoints for all modules: ATS, HR, Finance, Messaging"
- "Webhook support for real-time integrations"
- "Rate limiting based on subscription tier"

**Demo Sequence:**
```bash
# Authenticate
POST /api/v1/auth/token/
Body: {"email": "demo@zumodra.com", "password": "Demo123!"}

# Get jobs
GET /api/v1/jobs/jobs/
Headers: Authorization: Bearer <token>

# Get specific job
GET /api/v1/jobs/jobs/{job_id}/
Headers: Authorization: Bearer <token>

# Create candidate (POST)
POST /api/v1/jobs/candidates/
Headers: Authorization: Bearer <token>
Body: {
  "first_name": "Jane",
  "last_name": "Smith",
  "email": "jane.smith@example.com",
  "phone": "+1234567890",
  "current_title": "Software Engineer"
}
```

#### B. API Endpoints Overview (1 minute)

**Key Endpoints to Mention:**

| Module | Endpoint | Purpose |
|--------|----------|---------|
| **Auth** | `/api/v1/auth/token/` | JWT authentication |
| **ATS** | `/api/v1/jobs/jobs/` | Job management |
| **ATS** | `/api/v1/jobs/candidates/` | Candidate CRUD |
| **ATS** | `/api/v1/jobs/applications/` | Applications |
| **ATS** | `/api/v1/jobs/interviews/` | Interview scheduling |
| **HR** | `/api/v1/hr/employees/` | Employee management |
| **HR** | `/api/v1/hr/time-off/` | Time-off requests |
| **Dashboard** | `/api/v1/dashboard/overview/` | Stats & metrics |
| **Notifications** | `/api/v1/notifications/` | Notifications |

#### C. Webhooks (1 minute)

**URL:** Explain verbally (no dedicated UI for demo)

**Talking Points:**
- "Outbound webhooks for real-time event notifications"
- "Events: application_created, interview_scheduled, offer_accepted, employee_hired"
- "HMAC-SHA256 signature verification for security"
- "Automatic retry with exponential backoff"
- "Configure webhook endpoints per tenant"

---

### Part 7: Additional Features (2 minutes)

#### Key Features to Highlight (briefly):

1. **Real-time Messaging**
   - URL: https://zumodra.rhematek-solutions.com/app/messages/
   - WebSocket-powered chat
   - Direct messages and group channels
   - Online presence indicators

2. **Notifications**
   - URL: https://zumodra.rhematek-solutions.com/notifications/
   - Multi-channel: in-app, email, push
   - Preference management
   - Real-time updates

3. **Analytics & Reporting**
   - URL: https://zumodra.rhematek-solutions.com/analytics/
   - Recruitment metrics
   - Time-to-hire analytics
   - Pipeline conversion rates
   - Employee turnover statistics

4. **Multi-Tenancy**
   - Schema-based data isolation
   - Custom domains per tenant
   - Role-based access control (7 roles)
   - Subscription plans with feature flags

5. **Security Features**
   - 2FA enforcement
   - Audit logging (django-auditlog)
   - Brute force protection
   - Session management
   - GDPR compliance tools

---

## Feature Highlights

### Core Strengths

#### 1. Complete ATS System
- ✅ Job posting creation, editing, duplication, deletion
- ✅ Candidate database with search and filters
- ✅ Application tracking with customizable pipelines
- ✅ Interview scheduling, rescheduling, and cancellation
- ✅ Offer management with acceptance workflow
- ✅ Background checks integration
- ✅ Resume parsing and skill extraction
- ✅ Email templates and bulk actions

#### 2. HR Management
- ✅ Employee directory with org chart
- ✅ Time-off management with approval workflows
- ✅ Onboarding checklists and task tracking
- ✅ Document management and e-signatures
- ✅ Performance reviews and goal tracking
- ✅ Skills and certification tracking
- ✅ Offboarding workflows

#### 3. Multi-Tenancy
- ✅ Schema-based data isolation (PostgreSQL)
- ✅ Custom domains per tenant
- ✅ Role-based access control (PDG, Supervisor, HR Manager, Recruiter, Employee, Viewer)
- ✅ Subscription tiers with feature flags
- ✅ Per-tenant customization (branding, workflows)

#### 4. Security & Compliance
- ✅ JWT authentication with token rotation
- ✅ 2FA mandatory enforcement
- ✅ Brute force protection (django-axes)
- ✅ Audit logging for all actions
- ✅ GDPR-compliant data retention
- ✅ Role-based permissions
- ✅ Content Security Policy (no external CDNs)

#### 5. API & Integrations
- ✅ RESTful API with OpenAPI 3.0 spec
- ✅ JWT authentication
- ✅ Webhook support with HMAC signatures
- ✅ Rate limiting per subscription tier
- ✅ Comprehensive API documentation
- ✅ Third-party integration framework

#### 6. Real-Time Features
- ✅ WebSocket messaging (Django Channels)
- ✅ Live notifications
- ✅ HTMX-powered UI updates (no page refreshes)
- ✅ Online presence indicators
- ✅ Real-time pipeline updates

---

## Talking Points

### Opening (1 minute)

> "Thank you for joining us today. I'm excited to show you Zumodra, an enterprise-grade HR and recruitment platform that combines the power of an Applicant Tracking System, HR Core, and real-time collaboration tools in one unified solution.
>
> Zumodra was built from the ground up with multi-tenancy, security, and scalability in mind. Whether you're a 10-person startup or a 1000-employee enterprise, Zumodra adapts to your needs with flexible subscription tiers and role-based access control.
>
> Today, I'll walk you through the complete hiring workflow—from posting a job to making an offer—as well as our HR management capabilities, API integrations, and real-time features."

### Public Site & Branding (30 seconds)

> "Our public site showcases what Zumodra offers to potential clients. Notice the clean, professional design powered by Tailwind CSS, all served locally for maximum security and performance—no external CDN dependencies.
>
> We support multi-language content and have dedicated pages for pricing, features, and contact information."

### Authentication & Security (1 minute)

> "Security is paramount at Zumodra. Every user authenticates via JWT tokens with automatic rotation. Two-factor authentication is mandatory after 30 days, and we have brute force protection that locks accounts after 5 failed attempts.
>
> All actions are logged for compliance and audit trails. We're GDPR-compliant with built-in data retention policies and consent management."

### Dashboard (1 minute)

> "The dashboard is your command center. At a glance, you see open jobs, candidate counts, pending interviews, and active employees. The global search allows you to find anything—jobs, candidates, employees, applications—instantly.
>
> Notice how the UI updates in real-time without page refreshes? That's HTMX at work, providing a smooth, modern experience without heavy JavaScript frameworks."

### ATS Deep Dive (3 minutes)

> "Let's dive into the Applicant Tracking System, the heart of Zumodra.
>
> **Job Management:** Create, edit, duplicate, and archive job postings with rich descriptions, requirements, and benefits. Filter by status, category, and type.
>
> **Pipeline Board:** This is where the magic happens. Our Kanban-style board lets you visualize your entire hiring pipeline. Drag candidates between stages—notice how smooth that is? Every move is logged, and notifications are sent automatically.
>
> **Candidate Management:** Centralized database with resume parsing, skill extraction, and full search capabilities. Track every candidate interaction across multiple jobs they've applied to.
>
> **Interview Scheduling:** Built-in scheduling with support for phone, video, in-person, and technical interviews. Automatic email reminders and calendar integration."

### HR Core (2 minutes)

> "Beyond recruitment, Zumodra handles your entire employee lifecycle.
>
> **Employee Directory:** Searchable, filterable directory with department organization. Each profile includes skills, certifications, performance history, and direct reports.
>
> **Time-Off Management:** Visual calendar for planning team absences. Support for multiple leave types with accrual tracking, approval workflows, and automatic balance deductions. Conflict detection prevents scheduling issues.
>
> **Organization Chart:** Dynamic, interactive org chart that updates as your company grows and changes."

### API & Integrations (2 minutes)

> "Zumodra is designed to integrate with your existing tools. Our RESTful API provides full access to all platform features with comprehensive OpenAPI documentation.
>
> **Try it out live:** Here in Swagger UI, I can authenticate, list jobs, create candidates, and schedule interviews—all programmatically.
>
> **Webhooks:** Real-time event notifications with HMAC signature verification and automatic retry. Events include application submissions, interview scheduling, and offer acceptances.
>
> **Rate Limiting:** API usage is rate-limited based on your subscription tier, ensuring fair usage and system stability."

### Multi-Tenancy (1 minute)

> "Zumodra's multi-tenant architecture ensures complete data isolation. Each client gets their own schema in PostgreSQL, custom domain support, and role-based access control with 7 distinct roles.
>
> Subscription tiers unlock features progressively: Starter, Professional, Enterprise, and Custom. Feature flags allow per-tenant customization without code changes."

### Real-Time Features (1 minute)

> "We've built real-time collaboration into Zumodra's core. WebSocket-powered messaging allows team communication without leaving the platform. Live notifications keep everyone informed. HTMX-powered UI updates eliminate page refreshes for a seamless experience."

### Closing (1 minute)

> "Zumodra is more than just software—it's a complete hiring and HR solution built for modern businesses. With enterprise-grade security, comprehensive APIs, and an intuitive interface, we help teams hire better and manage employees more effectively.
>
> We're ready to onboard new clients today. Our flexible subscription plans start at $99/month for small teams and scale to enterprise pricing for large organizations.
>
> Thank you for your time. I'm happy to answer any questions."

---

## Troubleshooting

### Issue: Cannot log in with demo credentials

**Symptoms:**
- "Invalid credentials" error
- Login form reloads without error message
- Stuck on login page

**Solutions:**
1. Verify credentials are correct: `demo@zumodra.com` / `Demo123!`
2. Check if demo tenant exists:
   ```bash
   docker compose exec web python manage.py shell
   from django.contrib.auth import get_user_model
   User = get_user_model()
   User.objects.filter(email='demo@zumodra.com').exists()
   ```
3. Reset demo user password:
   ```bash
   docker compose exec web python manage.py changepassword demo@zumodra.com
   ```
4. Create demo tenant if missing:
   ```bash
   docker compose exec web python manage.py bootstrap_demo_tenant
   ```

---

### Issue: Dashboard shows no data (empty widgets)

**Symptoms:**
- Dashboard loads but shows 0 for all stats
- No jobs, candidates, or employees visible

**Solutions:**
1. Check if demo data exists:
   ```bash
   docker compose exec web python manage.py shell
   from ats.models import JobPosting, Candidate
   from hr_core.models import Employee
   print(f"Jobs: {JobPosting.objects.count()}")
   print(f"Candidates: {Candidate.objects.count()}")
   print(f"Employees: {Employee.objects.count()}")
   ```
2. Generate demo data:
   ```bash
   docker compose exec web python manage.py setup_demo_data --num-jobs 20 --num-candidates 100
   ```
3. Verify tenant association:
   ```bash
   docker compose exec web python manage.py shell
   from tenants.models import Tenant
   tenant = Tenant.objects.first()
   print(f"Tenant: {tenant.name}")
   print(f"Schema: {tenant.schema_name}")
   ```

---

### Issue: HTMX interactions not working (pipeline drag-and-drop)

**Symptoms:**
- Cannot drag candidate cards
- Buttons don't trigger partial updates
- Page refreshes instead of HTMX swap

**Solutions:**
1. Check browser console for JavaScript errors (F12)
2. Verify HTMX is loaded:
   ```javascript
   // In browser console
   console.log(typeof htmx);  // Should not be "undefined"
   ```
3. Clear browser cache and reload (Ctrl+Shift+R)
4. Check network tab for 400/500 errors on HTMX requests
5. Verify staticfiles are collected:
   ```bash
   docker compose exec web python manage.py collectstatic --noinput
   ```

---

### Issue: API requests return 401 Unauthorized

**Symptoms:**
- API calls fail with "Authentication credentials were not provided"
- Token authentication not working

**Solutions:**
1. Verify token is obtained correctly:
   ```bash
   curl -X POST https://zumodra.rhematek-solutions.com/api/v1/auth/token/ \
     -H "Content-Type: application/json" \
     -d '{"email": "demo@zumodra.com", "password": "Demo123!"}'
   ```
2. Check token expiration (default 5 minutes for access token)
3. Use refresh token to get new access token:
   ```bash
   curl -X POST https://zumodra.rhematek-solutions.com/api/v1/auth/token/refresh/ \
     -H "Content-Type: application/json" \
     -d '{"refresh": "<refresh_token>"}'
   ```
4. Verify Authorization header format:
   ```
   Authorization: Bearer <access_token>
   ```

---

### Issue: SSL certificate error or HTTPS not working

**Symptoms:**
- Browser shows "Your connection is not private"
- ERR_CERT_AUTHORITY_INVALID error
- Site loads over HTTP instead of HTTPS

**Solutions:**
1. Check SSL certificate validity:
   ```bash
   openssl s_client -connect zumodra.rhematek-solutions.com:443 -servername zumodra.rhematek-solutions.com
   ```
2. Verify Nginx SSL configuration:
   ```bash
   docker compose exec nginx cat /etc/nginx/conf.d/default.conf | grep ssl
   ```
3. Use HTTP temporarily for demo (not recommended):
   ```
   http://zumodra.rhematek-solutions.com
   ```
4. Contact hosting provider to verify SSL setup

---

### Issue: 500 Internal Server Error on specific pages

**Symptoms:**
- Some pages load fine, others show 500 error
- Error page with "Server Error (500)" message

**Solutions:**
1. Check Django logs:
   ```bash
   docker compose logs web --tail=100
   ```
2. Check database connection:
   ```bash
   docker compose exec web python manage.py dbshell
   \l  # List databases
   \q  # Quit
   ```
3. Run migrations if missing:
   ```bash
   docker compose exec web python manage.py migrate
   ```
4. Check Redis connection:
   ```bash
   docker compose exec redis redis-cli ping
   # Should return "PONG"
   ```

---

### Issue: Email notifications not sending

**Symptoms:**
- Interview invitations not sent
- Password reset emails not received
- No emails in MailHog

**Solutions:**
1. Check MailHog UI (development):
   ```
   http://localhost:8026
   ```
2. Verify email settings in `.env`:
   ```bash
   docker compose exec web python manage.py shell
   from django.conf import settings
   print(settings.EMAIL_BACKEND)
   print(settings.EMAIL_HOST)
   print(settings.EMAIL_PORT)
   ```
3. Test email sending:
   ```bash
   docker compose exec web python manage.py shell
   from django.core.mail import send_mail
   send_mail('Test', 'Test message', 'noreply@zumodra.com', ['test@example.com'])
   ```

---

### Issue: WebSocket connection failed for messaging

**Symptoms:**
- Real-time messages not working
- "WebSocket connection failed" in console
- Chat messages don't appear

**Solutions:**
1. Check channels (Daphne) service:
   ```bash
   docker compose ps channels
   docker compose logs channels --tail=50
   ```
2. Verify Redis channel layer:
   ```bash
   docker compose exec redis redis-cli
   KEYS *
   ```
3. Check WebSocket URL:
   ```javascript
   // Should be wss:// for HTTPS, ws:// for HTTP
   wss://zumodra.rhematek-solutions.com/ws/chat/
   ```

---

### Issue: Performance lag or slow page loads

**Symptoms:**
- Pages take >5 seconds to load
- Dashboard widgets load slowly
- API responses are slow

**Solutions:**
1. Check database query performance:
   ```bash
   docker compose exec db psql -U postgres -d zumodra -c "SELECT query, calls, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"
   ```
2. Verify Redis is running:
   ```bash
   docker compose ps redis
   ```
3. Check system resources:
   ```bash
   docker stats
   ```
4. Clear Django cache:
   ```bash
   docker compose exec web python manage.py shell
   from django.core.cache import cache
   cache.clear()
   ```

---

### Emergency Fallback Plan

If the live demo encounters critical issues:

1. **Switch to local development environment:**
   - Have a backup laptop with local Docker setup
   - Pre-loaded with demo data
   - Known working state

2. **Use recorded video walkthrough:**
   - Pre-record key demo sections
   - Have video cued and ready
   - Narrate over video

3. **Fallback to slides:**
   - Screenshots of key features
   - Architecture diagrams
   - Feature comparison table

4. **API-only demo:**
   - Use Postman collection
   - Show API documentation
   - Execute live API calls

---

### Quick Health Check Commands

Before demo, run these commands to verify system health:

```bash
# 1. Check all services are running
docker compose ps

# 2. Check web health endpoint
curl https://zumodra.rhematek-solutions.com/health/

# 3. Test database connection
docker compose exec web python manage.py dbshell -c "SELECT 1;"

# 4. Test Redis connection
docker compose exec redis redis-cli ping

# 5. Check if demo user exists
docker compose exec web python manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); print(User.objects.filter(email='demo@zumodra.com').exists())"

# 6. Check data counts
docker compose exec web python manage.py shell -c "from ats.models import JobPosting, Candidate; from hr_core.models import Employee; print(f'Jobs: {JobPosting.objects.count()}, Candidates: {Candidate.objects.count()}, Employees: {Employee.objects.count()}')"

# 7. Test API authentication
curl -X POST https://zumodra.rhematek-solutions.com/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@zumodra.com", "password": "Demo123!"}'
```

---

## Post-Demo Actions

### Immediate (within 1 hour):
- [ ] Thank attendees via email
- [ ] Send demo recording link (if recorded)
- [ ] Share API documentation link
- [ ] Provide trial signup link
- [ ] Schedule follow-up calls with interested parties

### Within 24 hours:
- [ ] Collect feedback from attendees
- [ ] Document any issues encountered
- [ ] Update demo script based on questions asked
- [ ] Send pricing and proposal documents
- [ ] Add leads to CRM

### Within 1 week:
- [ ] Follow up with all prospects
- [ ] Prepare custom demos for interested clients
- [ ] Address technical questions raised
- [ ] Update demo environment based on feedback

---

## Additional Resources

### Documentation Links
- Full Documentation: https://docs.zumodra.com (internal)
- API Reference: https://zumodra.rhematek-solutions.com/api/docs/
- OpenAPI Schema: https://zumodra.rhematek-solutions.com/api/schema/
- GitHub Repository: (private)

### Support Contacts
- Technical Support: support@zumodra.com
- Sales Inquiries: sales@zumodra.com
- Demo Requests: demo@zumodra.com

### Sales Collateral
- Pricing Sheet: Available in docs/PRICING.md
- Feature Comparison: Available in docs/FEATURES.md
- Architecture Overview: Available in docs/ARCHITECTURE.md
- Security Policy: Available in docs/SECURITY.md

---

## Demo Success Checklist

- [ ] System health verified
- [ ] Demo credentials tested
- [ ] All URLs loading correctly
- [ ] Sample data present and realistic
- [ ] HTMX interactions working smoothly
- [ ] API endpoints responding correctly
- [ ] Browser tabs pre-opened
- [ ] Presentation notes ready
- [ ] Backup plan prepared
- [ ] Questions anticipated and answers prepared

---

**Good luck with the demo! Remember: confidence, clarity, and enthusiasm will make all the difference.**

---

**Version:** 1.0
**Last Updated:** January 16, 2026
**Prepared by:** Zumodra Team
**Next Review:** After demo (January 17, 2026)
