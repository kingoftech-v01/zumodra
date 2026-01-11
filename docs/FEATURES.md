# Zumodra Platform Documentation

**Zumodra ATS/RH Platform**
**Rhematek Solutions**
**CEO: Stephane Arthur Victor**

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Overview and Vision](#2-project-overview-and-vision)
3. [Target Markets and Personas](#3-target-markets-and-personas)
4. [Competitive Landscape](#4-competitive-landscape)
5. [Core Platform Features](#5-core-platform-features)
6. [Multi-Tenancy Architecture](#6-multi-tenancy-architecture)
7. [Human Resources Features](#7-human-resources-features)
8. [Applicant Tracking System (ATS)](#8-applicant-tracking-system-ats)
9. [Freelance Marketplace and Escrow System](#9-freelance-marketplace-and-escrow-system)
10. [Trust and Reputation System](#10-trust-and-reputation-system)
11. [Two-Level Verification System](#11-two-level-verification-system)
12. [Hybrid Ranking Engine](#12-hybrid-ranking-engine)
13. [CV Coaching and Multi-CV System](#13-cv-coaching-and-multi-cv-system)
14. [Co-op and Student Ecosystem](#14-co-op-and-student-ecosystem)
15. [Marketing and Events System](#15-marketing-and-events-system)
16. [Security and Compliance](#16-security-and-compliance)
17. [Technical Architecture](#17-technical-architecture)
18. [Product Roadmap](#18-product-roadmap)
19. [Go-to-Market Strategy](#19-go-to-market-strategy)
20. [Operational and Scalability Strategy](#20-operational-and-scalability-strategy)
21. [Access and Permission Configuration](#21-access-and-permission-configuration)
22. [Build Execution Prompts](#22-build-execution-prompts)
23. [Quality Assurance and Verification](#23-quality-assurance-and-verification)

---

## 1. Executive Summary

### Platform Definition

Zumodra is a multi-tenant SaaS platform that combines a freelance services marketplace with integrated CRM tools, appointment booking, escrow payments, real-time messaging, email marketing, and a Wagtail CMS for content management. The platform has evolved from a Django learning project into a production-ready enterprise solution targeting freelancers, agencies, and businesses requiring seamless service matching, financial security, and client management.

### Mission Statement

**"Verify. Recruit. Hire. Risk-Free."**

Zumodra delivers a comprehensive multi-tenant ATS and HRIS platform that eliminates recruitment fraud through bidirectional KYC verification of candidates and recruiters, automated CV validation, and real competency assessments via skills testing. Recruiters access progressively disclosed candidate data while enterprises manage end-to-end HR workflows within a single, GDPR/eIDAS-compliant SaaS environment.

### Vision

Zumodra aims to become Europe's leading anti-fraud ATS by 2028, powering 10,000 enterprise subscriptions with AI-driven predictive matching, turnover forecasting, and global expansion into the US and Francophone Africa. The platform fundamentally shifts recruitment from polished CVs to verified competencies, reducing time-to-hire by 40% while ensuring 100% candidate legitimacy.

### Transformation Delivered

From the chaos of fraudulent candidacies toward a 100% reliable HR pipeline with real competency matching, enterprise health analytics, and multiple HR circuits (external, internal, freelance).

---

## 2. Project Overview and Vision

### Project Purpose

Zumodra addresses gaps in existing freelance platforms by creating an all-in-one ecosystem where:
- Providers list services
- Clients book appointments or post jobs
- Payments flow through escrow
- Marketing and CRM tools drive retention

All within a multi-tenant architecture for scalability. Unlike standalone marketplaces, it supports enterprise workflows including:
- Multi-language support (9 languages)
- Geospatial service matching via PostGIS
- Role-based dashboards for clients, providers, and admins

### Key Advantages

| Capability | Description |
|------------|-------------|
| **Built-in Escrow** | Full Stripe escrow system beyond Fiverr's 20% flat fees or Upwork's milestone system |
| **Real-time Messaging** | WebSocket messaging with typing indicators and file sharing |
| **Async Tasks** | Celery-powered tasks for newsletters and cron jobs |
| **Multi-tenancy** | White-label SaaS deployment at lower costs than single-tenant CRMs |
| **Security** | 2FA, audit logging, and CSP for superior security |
| **SEO Integration** | Django/Wagtail stack ensures SEO-optimized content marketing |

### Unique Differentiators

1. **Escrow + CRM Fusion**: Combines Upwork-style proposals/contracts with monday CRM-like pipelines, tracking leads from inquiry to review in one system

2. **Geospatial + Multi-Language**: PostGIS for location-based service filtering and i18n for 9 languages, enabling global reach without add-ons

3. **Real-Time + Analytics**: Channels for chat/typing, integrated with django-analytical for geo-tracked user behavior

4. **Production-Ready Stack**: Docker/Nginx/Gunicorn/Celery from day one, with Wagtail for dynamic landing pages/blog

### Competitive Comparison

| Feature | Fiverr/Upwork | Standalone CRMs | Zumodra |
|---------|---------------|-----------------|---------|
| Escrow Payments | Milestone-based | Rare | Full Stripe escrow + refunds |
| Real-Time Chat | Basic messaging | No | WebSockets with indicators |
| Multi-Tenant SaaS | No | Partial | Native django-tenants ready |
| CMS/Marketing | Limited | Separate tools | Wagtail + newsletters |
| Geospatial Search | Basic filters | No | PostGIS integration |
| KYC Verification | None | None | Bidirectional verification |
| Progressive Data Revelation | No | No | Full consent-based system |

---

## 3. Target Markets and Personas

### Primary Target Markets

#### 1. SMEs (10-250 employees)
- **Focus**: Streamlined hiring and absence tracking
- **Needs**: Simplicity, anti-scam protection, diversity analytics
- **Key Features**: Absence dashboard, diversity reports, simple leave approvals, company health dashboard

#### 2. Recruitment Agencies
- **Focus**: High-volume candidate pipelines and nurturing
- **Needs**: ATS pure functionality, advanced CV parsing
- **Key Features**: Multi-pipelines, Boolean search, talent nurturing, bulk CV import (100+/day), saved searches

#### 3. ESN/Consulting Firms
- **Focus**: CDI and freelance mission management
- **Needs**: E-signature contracts, integrated invoicing
- **Key Features**: Freelance circuit, invoice tracking, freelance rate calculator, mission templates, bench management

#### 4. Educational Institutions
- **Focus**: Student/apprentice placement
- **Needs**: Campus job boards, diploma-based matching
- **Key Features**: Student portal, bulk promo import, placement rate analytics, internship period tracking

### Common Value Proposition

All personas benefit from:
- Scam-proof verification with bidirectional KYC
- Progressive data revelation (name/experience → interest → contact → post-interview → NAS/contract)
- Customizable ATS filters
- Role-based dashboards tailored to workflows

---

## 4. Competitive Landscape

### Market Positioning

Zumodra positions itself as the only ATS/HRIS that guarantees verified candidates through bidirectional KYC and progressive data revelation, addressing the growing recruitment fraud crisis affecting 68% of European SMEs.

### Competitive Analysis

| Competitor | Limitations | Zumodra Advantage |
|------------|-------------|-------------------|
| **Welcome to the Jungle** | No KYC, no internal HR | ATS + Complete HR |
| **JobTeaser** | Schools only, no freelances | 4 unified personas |
| **Lever** | ATS only, no onboarding/absences | All-in-one multi-circuits |
| **DocuSign standalone** | No HR integration | E-signature integrated into pipeline |

### Success Factors

1. **Unique Anti-Scam**: Bidirectional KYC (candidates + recruiters) + progressive revelation + NAS post-acceptance
2. **Multi-Circuit HR**: 4 flows (external, internal, talent pool, freelance) in one dashboard
3. **Infinite Customization**: Custom pipelines, modifiable ATS filters per tenant, granular roles
4. **Global Compliance**: eIDAS/ESIGN for e-signature, AES-256 per tenant, immutable audit logs
5. **Aggressive Pricing**: Per employee/month versus per-recruiter pricing of US competitors

---

## 5. Core Platform Features

### 5.1 Completed Features

| Module | Features |
|--------|----------|
| **ATS (Applicant Tracking)** | Complete recruitment pipeline: job postings, candidate management, applications, interviews, offers |
| **Interview Management** | Full CRUD: scheduling, rescheduling, cancellation, feedback collection |
| **Job Management** | Complete job lifecycle: create, edit, duplicate, delete, publish, close, career pages |
| **Candidate Management** | Candidate profiles, CV uploads, job assignment, application tracking |
| **Application Workflows** | Email composition, rejection workflows, pipeline stage management, bulk actions |
| **Appointment Booking** | Full scheduling system with calendar integration |
| **Stripe Finance** | Subscriptions, escrow payments, refunds |
| **Real-time Messages** | WebSocket-based messaging with typing indicators |
| **Newsletters** | Email marketing campaigns |
| **Security Auditing** | Complete audit logging system |
| **HR Core** | Employee directory, time-off management, onboarding workflows |
| **Multi-Tenancy** | Full schema-based tenant isolation with role-based access control |

### 5.2 Partial Features (In Development)

- Advanced ATS filters and Boolean search
- CV parsing and AI matching
- Services marketplace
- Wagtail blog
- Dashboard analytics
- KYC verification integration

### 5.3 Roadmap Features

- Provider profiles
- Proposals system
- Geofiltered search
- Ratings and reviews
- API endpoints
- Multi-role dashboards

### 5.4 Anti-Scam and Security Features (Priority 1)

#### Bidirectional Candidate/Recruiter Verification
- Enhanced KYC (ID + selfie + 30-second video) via Sumsub/Onfido API or manual verification
- "Legitimately Verified" badge publicly visible
- Audit trail for all verification attempts

#### Encrypted Document Management
- Secure upload (AES-256)
- Encrypted storage per tenant
- Granular access ("Unlock complete info" button after mutual acceptance)

#### Global Legal E-Signature
- DocuSign/HelloSign integration with eIDAS (Europe), ESIGN (USA) compliance
- Qualified certificates
- CDI/CDD/freelance contracts signed in 1 click
- Timestamped with immutable audit trail

#### Real Competency Proof
- Auto-administered technical tests (coding challenges, soft skills via video quiz)
- Verified portfolio (validated GitHub/Behance/Dribbble links)

---

## 6. Multi-Tenancy Architecture

### 6.1 Tenant Structure

A **Tenant** represents an Enterprise that can have one or multiple **Circusales** (business units/divisions), and each Circusale has its people (employees or others).

#### Tenant (Enterprise)
- Owns circusales, users, services, and finances
- White-label branding via Wagtail pages
- Custom subdomain (e.g., acme.zumodra.com)
- Own referential: offers, candidates, users, personalized workflows

#### Circusale (Division)
- Location-specific unit (e.g., "Montreal Sales")
- PostGIS coordinates for geolocation
- Budget management
- Team assignments
- Users belong to one primary circusale

#### Model Example

```python
class Circusale(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=CASCADE)
    name = models.CharField(max_length=100)
    address = models.PointField()  # PostGIS
    budget = models.DecimalField()

class TenantUser(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL)
    tenant = models.ForeignKey(Tenant)
    circusale = models.ForeignKey(Circusale)
    role = models.CharField(choices=[('pdg', 'PDG'), ('supervisor', 'Supervisor'), ...])
```

### 6.2 Role-Based Access Control (RBAC)

Implementation via custom `TenantUser` model extending django-tenant-users, with permissions per tenant/circusale.

| Role | Tenant Scope | Circusale Scope | Unique Permissions |
|------|--------------|-----------------|-------------------|
| **PDG/CEO** | Full | All | User management, budgets, global analytics, cross-division approval |
| **Supervisor** | Full view | Own division | Team approval, local analytics, P&L view |
| **HR Personnel** | Hire/view | Assigned | Onboarding, compliance checks, performance reviews |
| **Marketer** | Campaigns | Assigned | Events, geo-leads, local campaigns |
| **Employee** | Personal | Assigned | Timesheets, projects, personal dashboard |

#### Extended Role Hierarchy (Per Tenant, Configurable by Admin RH)

```
├── SuperAdmin (platform-wide)
├── TenantAdmin (full tenant control)
├── RHAdmin (HR operations + analytics)
├── Recruiter (ATS pipelines + candidates)
├── HiringManager (own jobs + team candidates)
├── RHOperational (absences + onboarding only)
└── Viewer (read-only dashboards)
```

### 6.3 Key Implementation Features

1. **Scoped Dashboards**: Dynamic views filter data by `request.tenant` + `user.circusale`
2. **Permission Middleware**: Custom middleware checks `user.role.permissions` against tenant/circusale context
3. **Multi-Address Management**: Enterprises add circusales with addresses; PostGIS enables "services near this division" matching
4. **Data Isolation**: PostgreSQL schemas per tenant + AES-256 field-level encryption

---

## 7. Human Resources Features

### 7.1 Essential HR Features

#### Talent Sourcing and Matching
- AI-powered skill matching using existing taxonomy
- Private talent pools from marketplace data
- Job board integration
- PostGIS extension for location-based hiring

#### Automated Onboarding
- Digital contracts with e-signatures
- Background checks via API (e.g., Checkr)
- Right-to-work verification
- Document storage tied to user profiles

#### Compliance Tracking
- Worker classification tools
- Tax form collection (1099-NEC)
- Multi-country compliance rules
- Audit logs from security app

### 7.2 Advanced HR Workflows

#### Performance and Ratings
- Verified ratings system post-project
- Utilization metrics
- Re-engagement tracking for top freelancers

#### Budget and Spend Analytics
- Real-time spend tracking by department/project
- Predictive forecasting via Celery tasks
- Integration with finance app escrow data

#### Global Payments and Invoicing
- Multi-currency support in Stripe
- Automated invoice generation
- Payroll integration

### 7.3 Time-Off and Scheduling

#### Time-Off Management
- Configurable leave policies per tenant (vacation, sick leave, RTT, unpaid leave, parental leave, special leave)
- Individual leave balances with accrual rules (monthly/yearly, carry-over caps)
- Self-service leave requests (web + mobile-responsive) with:
  - Reason, dates, partial days, attachment (medical certificate)
  - Approval workflows (line manager → HR override)
- Bulk approval/rejection with audit logging
- Conflict detection for team capacity
- Calendar views: Team, department, and global company calendars
- Google Calendar / Microsoft 365 integration

#### Scheduling and Working Hours
- Contracted working hours per employee (full-time, part-time, shift patterns)
- Planned vs. actual presence tracking
- Visual heatmaps for daily/weekly staffing levels
- Overtime and recovery time tracking with manager approval

### 7.4 Employee Lifecycle Management

#### Resignation and Notice Period Workflows
- Structured resignation request form (reason, last working day, feedback)
- Automatic calculation of legal and contractual notice period by country/tenant settings
- Approval chain (manager → HR → legal if required)
- Automatic tasks for knowledge transfer, equipment return, access revocation
- Reminders for upcoming last day, payroll adjustments, benefits termination

#### Offboarding Automation
- Offboarding checklist templates per role (developer, sales, manager):
  - Accounts to disable (email, SaaS tools)
  - Hardware to collect (laptop, badge, phone)
  - Exit interview scheduling and feedback capture
- Single-click "Initiate Offboarding" from employee profile
- Secure archival of employee records with configurable retention policies (5-10 years)
- All sensitive data (NAS, health information) encrypted at rest

### 7.5 Diversity and HR Analytics

#### Diversity and Inclusion Metrics
- Real-time dashboards for:
  - Gender distribution by department and level
  - Age distribution and seniority buckets
  - Ratio of full-time vs. part-time, contract types
- Filterable diversity reporting by team, office, job family, or time period
- Exportable for audits and internal reporting
- Configurable KPIs per tenant based on jurisdiction and policy

#### Absence and Wellbeing Analytics
- KPIs: Absence rate, average duration, top causes
- Early-warning indicators: Sick leave spikes, burnout risk signals
- Executive "Company Health" view
- Manager "Team Health" view with drill-down

#### Recruitment and Workforce Analytics Integration
- Unified analytics combining ATS + HR data
- Time-to-hire vs. retention rate by role
- Source quality linked to performance/tenure
- Customizable analytics widgets with drag-and-drop dashboard builder

### 7.6 HR Feature Comparison

| Feature | Current Zumodra | Added HR Value | Competitive Edge |
|---------|-----------------|----------------|------------------|
| Onboarding | Basic profiles | Automated compliance docs | Reduces 54% productivity lag |
| Payments | Escrow/Stripe | Global tax handling | Instant options vs Upwork delays |
| Analytics | Basic marketing | Spend/utilization dashboards | Predictive forecasting |
| Matching | Service search | AI skill pools | Private networks > public marketplaces |

---

## 8. Applicant Tracking System (ATS)

### 8.1 Customizable Recruitment Pipelines

```
Pipeline Architecture (per tenant, unlimited customization):
├── Drag & drop Kanban interface (5-15 stages)
├── Custom stage names: "CV Review" → "Phone Screen" → "Tech Test" → "Final HR" → "Offer"
├── Stage-specific actions: Auto-move rules (score >80%), mandatory fields (scorecard)
├── Pipeline templates by persona:
│   SME: "Quick Hire" (4 stages)
│   Agency: "High Volume" (8 stages)
│   ESN: "Freelance Mission" (6 stages)
│   School: "Student Placement" (5 stages)
└── Analytics per pipeline: Conversion rates, time-per-stage, bottleneck detection
```

### 8.2 Advanced ATS Filters

**30+ ATS Filters (admin-buildable, savable, Boolean logic):**

| Category | Filters |
|----------|---------|
| **Experience** | Years min/max, job titles, company names |
| **Skills** | Multi-select (Python, AWS, Sales, etc.), tech stack matching |
| **Location** | City, radius (50km), remote/hybrid/office |
| **Compensation** | Salary range, contract type (CDI/CDD/Freelance) |
| **Availability** | Notice period (<1mo, <3mo), immediate start |
| **Diversity** | Gender, age range, disability status (anonymized) |
| **Language** | French/English/Spanish (B2+ certified) |
| **Source** | LinkedIn/Job board/Referral/Spontaneous |
| **Technical** | Test scores (>80%), certifications (AWS, PMP) |
| **Boolean** | "Python AND remote NOT junior" syntax |

### 8.3 Job Posting and Career Pages

- **Multi-channel publishing**: 1-click to Indeed/LinkedIn/JobTeaser + embed code
- **Career pages**: tenant.zumodra.com/careers + tenant.zumodra.com/job/123-react-dev
- **SEO optimized**: Schema.org JobPosting, sitemap.xml per tenant
- **Spontaneous candidacies**: Tenant-configurable (Accept/Refuse/Auto-route to pipeline)

### 8.4 Progressive Data Revelation System

```
Revelation Stages (candidate-controlled consent):

Stage 1 (Initial): Name, photo, experience summary, core skills, location (city)
    ↓ "Interested" click by recruiter
Stage 2 (Pre-interview): Phone, LinkedIn, availability, salary expectations
    ↓ Post-interview confirmation
Stage 3 (Offer stage): Full address, professional references, work eligibility
    ↓ Offer accepted + background check consent
Stage 4 (Onboarding): NAS/Social Security Number, medical docs, emergency contacts
```

### 8.5 CV Submission Options

- **PDF/TXT upload** → AI parsing (skills, experience extraction)
- **Guided form**: Progressive fields (name → experience → salary → NAS post-offer)
- **Portfolio integration**: GitHub/Behance/Dribbble verified links

### 8.6 Automated Interview Scheduling

- Calendly/Google Calendar/Microsoft 365 integration
- Auto-propose 3 slots based on recruiter/candidate availability
- SMS/Email confirmations (Twilio/SendGrid)
- Buffer time + timezone awareness

### 8.7 Multi-Circuit Talent Management

#### Four Talent Circuits in One Platform

1. **External Recruitment**: Classic candidate flow from public job boards
2. **Internal Mobility**: Employees applying or being scouted for roles
3. **Talent Pool / Alumni**: Former candidates and employees kept warm for future roles
4. **Freelancers / Contractors**: Mission-based engagements, availability tracking

A single **Talent Graph** for each tenant links all relationships, roles, history, and circuits.

#### Circuit-Specific Rules and Settings

- Different SLA, communication templates, and KPIs per circuit
- Example metrics:
  - External: time-to-first-contact
  - Internal: time-to-decision
  - Freelance: bench time and utilization rates
  - Alumni: engagement score (open rates, click-throughs, response rates)

### 8.8 Matching Engine and Fair Selection

#### Matching Algorithms

Multi-factor **Matching Score** for each Job-Talent pair:
- Competency fit (weight configurable by tenant)
- Years of relevant experience
- Salary alignment (candidate expectation vs. job band)
- Geographic and remote-work constraints
- Availability and notice period alignment

Explainable scoring with breakdown (e.g., "Skills 85%, Experience 90%, Salary 70%, Location 100%")

#### Fair and Bias-Aware Selection

- Optional **blind screening mode**: Temporarily hides name, photo, gender, age during initial screening
- Diversity guardrails with configurable objectives
- Analytics highlighting systematic pipeline skews

#### ATS Layer for "Bad CV, Strong Talent"

- Structured, guided CV builder for candidates with weak formatting
- Heuristic/AI support highlighting overlooked profiles with strong skills
- "Hidden gem" suggestions: candidates not shortlisted but highly aligned on skills

---

## 9. Freelance Marketplace and Escrow System

Zumodra integrates a **Fiverr-style freelance marketplace** with robust financial protection through Stripe Connect-powered escrow, ensuring neither clients nor freelancers lose money to fraud.

### 9.1 Stripe Connect Architecture

- Use **Stripe Connect Custom/Express** accounts for freelancers
- Platform account holds funds in **delayed payout** mode:
  - Client pays -> funds captured and reserved
  - Freelancer only gets payout after work acceptance

### 9.2 Escrow Workflow

```
1. POSTING & PROPOSAL
   └── Client posts project with scope, milestones, budget
   └── Freelancers apply using verified Zumodra profile and CV

2. FUNDING & ESCROW
   └── Client selects freelancer and funds the milestone
   └── Funds held in platform; platform fee reserved

3. WORK DELIVERY
   └── Freelancer uploads deliverables (files, links, notes)
   └── System logs timestamps and version history

4. ACCEPTANCE / DISPUTE
   └── Client clicks "Accept" -> payout released, recorded as "Completed"
   └── If disputed -> dispute workflow triggers:
       ├── Both sides provide evidence and context
       ├── AI summarizes and categorizes issues
       └── Admin/rules engine decides outcome (full refund, partial, full payout)

5. PAYOUT
   └── Stripe transfers funds to freelancer minus fees
```

### 9.3 Anti-Fraud Protections

| Protection | Description |
|------------|-------------|
| **KYC Required** | Only KYC-verified freelancers and employers can use escrow |
| **Rate Limits** | Anomaly detection on payment flows |
| **Dispute History** | Influences TrustScore (only after validation) |
| **Non-Delivery Protection** | Clear dispute rules; freelancer has path to payment from held funds |
| **Non-Performance Protection** | Client gets refund if freelancer never starts or work fails criteria |

### 9.4 Key Differentiators from Fiverr/Upwork

| Feature | Fiverr/Upwork | Zumodra |
|---------|---------------|---------|
| Client Verification | Basic | Full business KYC, beneficial owner verification |
| Freelancer Verification | Basic | Document + liveness + optional background checks |
| Payment Protection | Milestone-based | True escrow with delayed payouts |
| Identity Assurance | Minimal | Bidirectional KYC before any transaction |
| Dispute Resolution | Platform-controlled | AI-assisted with evidence management |

---

## 10. Trust and Reputation System

Zumodra implements a comprehensive **Trust System** that goes beyond simple star ratings, incorporating verification levels, behavioral signals, and validated reviews.

### 10.1 Trust Levels

Multi-dimension trust score for all platform actors:

#### For Candidates/Freelancers
- Identity verified (Level 1 KYC)
- Career verified (Level 2 - Experience & Education)
- Number and quality of completed contracts/jobs
- Dispute/resolution history (weighted only after validation)
- Review history and average rating

#### For Employers/Clients
- KYC status
- Average rating given by talent
- Payment reliability and dispute rate

#### For Schools/Institutions
- Participation level in verifications
- Responsiveness and data accuracy

### 10.2 Review and Rating System

After job/contract completion, both parties can leave structured reviews:

- **Star rating** (1-5)
- **Short qualitative feedback**
- **Checkboxes** on professionalism, communication, scope clarity, payment speed

**Key Principle**: **No reviews does not equal bad**. Lack of history is treated neutrally. New users are not penalized by default.

### 10.3 AI-Assisted Review Verification

To prevent unfair or malicious reviews:

```
NEGATIVE REVIEW SUBMITTED
    │
    ├── AI analyzes content for policy violations (harassment, hate, etc.)
    │
    ├── AI prompts for EVIDENCE (messages, delivery records, timelines)
    │
    ├── System asks other party for their side (anonymous forms)
    │
    └── RESOLUTION
        ├── Automated reconciliation based on evidence and platform logs
        └── Complex cases flagged for human/admin review
```

**Impact on Trust**:
- Only **validated** negative reviews significantly lower TrustScore
- Frivolous or abusive reviews are filtered out or heavily down-weighted

### 10.4 Trust Surfacing in UX

| Element | Display |
|---------|---------|
| **List Views** | Badges: "ID Verified", "Career Verified", "High Trust", "New to Platform" |
| **Filters** | Show only: "ID Verified" / "Career Verified" / "High Trust" profiles |
| **Profiles** | Trust explanation: "High Trust because: verified identity + 3 verified employers + 5 successful contracts, 0 disputes" |

---

## 11. Two-Level Verification System

Zumodra implements a unique **two-level verification model** that goes beyond standard identity checks to verify actual career history.

### 11.1 Level 1: KYC and Digital Identity

**Goal**: Ensure each person and company is who they claim to be.

#### For Candidates
- Upload government ID, selfie, and optionally a short liveness video
- Third-party IDV provider validates document authenticity and liveness
- Outcome: `ID_VERIFIED`, `PENDING`, `FAILED`
- **Badge**: "ID Verified" visible on profiles

#### For Employers/Clients/Schools
- Business KYC: legal name, registration number, address, beneficial owners
- Domain verification (email DNS, website)
- **Badge**: "Verified Business" visible on company pages

### 11.2 Level 2: Career Verification (Experience and Education)

**Goal**: Ensure the CV accurately reflects work and academic background.

#### Employment Verification

For each job entry, candidates must provide:
- Employer name and location
- Official HR or manager contact email, OR company portal login

**System Process**:
1. Sends **automatic verification emails** with secure questionnaire
2. Questions: employment dates, role, full-time/part-time, rehire eligibility
3. Responses are hashed, timestamped, and attached to profile

#### Education Verification

Information required:
- Institution name, program, degree type, start/end dates

**Verification Paths**:
1. Direct academic API/partner (where available)
2. Email to registrar/career office at official domains
3. Candidate logs into student portal and exports signed transcript/letter

### 11.3 Verification Status

**Per Element Status**:
- `UNVERIFIED` - Not yet verified
- `PENDING` - Verification in progress
- `VERIFIED` - Successfully verified
- `DISPUTED` - Verification failed or contested

**Global Badges**:
- "ID Verified (KYC)" - Level 1 complete
- "Career Verified" - 80%+ of history verified (Level 2)

### 11.4 System Behavior

- Search and ranking **boost** fully verified candidates
- New/unverified users are **not penalized**, just not boosted
- Verification completion shown with progress indicators
- Clear benefits displayed: "Verified profiles get 2x more interviews"

---

## 12. Hybrid Ranking Engine

Zumodra uses a **dual-engine approach** combining deterministic rules with AI/ML scoring for transparent, tunable candidate ranking.

### 12.1 Rules-Based ATS Engine

**Definition**: Deterministic filters and scoring

| Component | Description |
|-----------|-------------|
| **Boolean Search** | AND, OR, NOT on skills, titles, education |
| **Hard Constraints** | Must-have: legal right to work, required degree, minimum experience |
| **Weight Rules** | Recency (latest roles weigh more), Tenure, Location, Availability |

### 12.2 AI Scoring Engine

**Definition**: Machine learning layer for semantic matching and anomaly detection

- **Semantic Similarity**: Between job descriptions and CVs
- **Skills Graph**: Related/adjacent skills (e.g., React <-> JavaScript/TypeScript)
- **Pattern Detection**: Anomalies (gaps, inconsistent dates, suspicious patterns)

### 12.3 Combined Ranking Formula

Each candidate for a job receives:

```
RuleScore (0-100)      - Deterministic filter match
AIScore (0-100)        - Semantic and pattern analysis
VerificationScore (0-100) - Level 1 + Level 2 verification
TrustScore (0-100)     - Platform trust system score

MatchScore = w_r * RuleScore + w_a * AIScore + w_v * VerificationScore + w_t * TrustScore
```

Where weights `w_r`, `w_a`, `w_v`, `w_t` are **tenant-configurable** within safe ranges.

### 12.4 Transparency Features

- Recruiters see score breakdown for each candidate
- Toggle emphasis: "Prioritize verified experience" or "Prioritize skills match"
- Explainable AI: "Matched because: 5 years Python, remote preference, verified at 2 previous employers"

### 12.5 Anti-Fraud CV Scanning

- AI scanning for suspicious patterns and inconsistencies
- Flagged for deeper verification if anomalies detected
- Conflicting dates, improbable trajectories highlighted

---

## 13. CV Coaching and Multi-CV System

Zumodra transforms CV management into a core product feature, helping candidates present themselves optimally while maintaining verification integrity.

### 13.1 Multi-CV Architecture

Candidates can create multiple CV profiles tailored to different roles:

```
CANDIDATE PROFILE
    │
    ├── CV A: Software Engineer
    │   └── Emphasis on Python, Django, backend systems
    │
    ├── CV B: Data Analyst
    │   └── Emphasis on SQL, analytics, visualization
    │
    └── CV C: Technical Lead
        └── Emphasis on leadership, architecture, team management
```

**On Application**:
- Zumodra suggests the **best CV** based on job description match
- Or candidate manually selects which CV to submit

### 13.2 AI + Rules CV Analysis

#### Structural Checks
- Section headings and organization
- Length optimization
- ATS-safe formatting (no tables/images that break parsers)

#### Content Checks
- Quantify impact (add metrics to bullets)
- Remove fluff and filler content
- Align with job keywords

#### Fraud Checks
- Detect suspicious patterns
- Identify conflicting dates
- Flag improbable career trajectories

### 13.3 CV Feedback Tiers

| Tier | Features |
|------|----------|
| **Free** | Basic structure tips, keyword coverage, ATS compatibility score |
| **Pro** | Detailed rewriting suggestions, role-specific templates |
| **Premium** | Automatic tailoring to specific job postings, match score optimization |

### 13.4 "Bad CV, Strong Talent" Support

Zumodra actively helps candidates who have strong skills but weak presentation:

- **Guided CV Builder**: Simple Q&A generates clean, standardized profile
- **Hidden Gem Alerts**: Recruiters notified of overlooked high-skill candidates
- **Presentation vs Substance**: AI compares verified skills against CV formatting
- **Boost Undervalued**: Deliberately surface candidates with strong competencies but weak formatting

---

## 14. Co-op and Student Ecosystem

Zumodra serves as the bridge between educational institutions and the workforce, supporting the complete student-to-professional journey.

### 14.1 Student Streams

| Stream | Description | Parameters |
|--------|-------------|------------|
| **University Co-op** | Formal co-op programs (Waterloo-style) | 4-16 month terms, academic integration |
| **College Co-op** | Technical and vocational programs | 4-8 month terms, skills-focused |
| **Junior Internships** | Entry-level opportunities | 2-4 months, extra safeguards |
| **Apprenticeships** | Trade and technical training | Variable terms, certification tracking |

Each stream has configurable:
- Minimum/maximum duration
- Academic terms allowed
- Age and legal constraints
- Required approvals

### 14.2 School-Employer-Student Triad

```
EMPLOYER                    SCHOOL                      STUDENT
    │                          │                            │
    ├── Posts co-op role ──────┼── Reviews/approves ────────┤
    │                          │                            │
    │                          ├── Monitors postings ───────┤
    │                          │                            │
    ├── Interviews ────────────┼────────────────────────────┼── Applies
    │                          │                            │
    └── Hires/evaluates ───────┼── Tracks progress ─────────┴── Works
```

**School Coordinator Dashboard**:
- See all postings targeting their students
- Approve/decline employer postings
- Monitor student progress and performance

### 14.3 Academic Verification and Records

**Enrollment Verification**:
- APIs where available (EduVault, etc.)
- Email-based workflows with registrar/student services
- Student portal login for transcript export

**Performance Records**:
- Co-op evaluations stored on platform
- Work-term reports and grades tracked
- Signed with e-signature and audit trail

**Lifecycle Continuity**:
- Student's verified academic + co-op history flows into professional/freelancer profile
- Becomes part of long-term verified identity

### 14.4 Young User Protections

For younger cohorts, additional safeguards apply:

- **Manual employer approval** required for junior streams
- **Enhanced content moderation** on job postings
- **Limited personal info exposure** by default
- **Stronger verification requirements** for employers

### 14.5 Value Proposition

**For Students**:
- Verified academic credentials follow them into career
- Early work history is structured and validated
- Single identity across co-op, employment, and freelance

**For Schools**:
- Centralized platform for co-op management
- Real-time visibility into student placements
- Quality control over employer postings

**For Employers**:
- Access to verified student talent pools
- Streamlined co-op hiring process
- Long-term talent pipeline building

---

## 15. Marketing and Events System

### 15.1 Core Marketing Dashboard

Extends the dashboard app with role-specific views for marketers, pulling analytics from django-analytical and user-tracking.

#### Campaign Analytics
- Track CAC, MRR/ARR, churn rates, activation metrics, and feature adoption
- Real-time Redis dashboards with A/B testing for emails/landing pages

#### Lead Nurturing Automation
- Celery-powered sequences for onboarding emails
- Re-engagement for inactive freelancers/clients
- Personalized nurture flows based on service views or geo-location

#### Content Performance
- Wagtail-integrated metrics for blog posts, landing pages, and SEO
- Predictive analytics for high-engagement topics

### 15.2 Event Management System

Built using PostGIS for location-based discovery.

#### Event Publishing
- Create webinars, meetups, workshops (virtual/in-person)
- RSVPs and ticket sales via Stripe
- Live-stream integration (Jitsi)
- Auto-generate calendars and reminders

#### Geo-Targeted Discovery
- Public event map with location/skills filtering ("Python devs events in Montreal")
- Push notifications via Channels for nearby matches

#### Event Analytics
- Track attendance and conversions (e.g., event → service hire)
- NPS feedback and follow-up campaigns
- Transform events into lead pipelines

### 15.3 Advanced Growth Features

#### Feature Marketing
- In-app notifications and email blasts for new platform updates
- Video tutorials and dynamic personalization via user behavior data

#### Affiliate/Referral Program
- Automated tracking of referrals with tiered commissions
- Integration with finance app escrow for payouts

#### AI-Powered Personalization
- Enrich CRM data for hyper-targeted ads/emails (e.g., "Services near you")
- Use existing geoip2 for visitor insights

### 15.4 Marketing Feature Comparison

| Feature | Current Zumodra | Marketing Boost | Unique Edge |
|---------|-----------------|-----------------|-------------|
| Events | None | Geo-discovery + RSVPs | Local networking > Upwork forums |
| Automation | Newsletters only | Full sequences/A/B | 15%+ sales lift via personalization |
| Analytics | Basic tracking | ARR/churn dashboards | Predictive retention |
| Content | Wagtail blog | Event-integrated SEO | Viral local events drive 20% acquisition |

---

## 16. Security and Compliance

### 10.1 Encryption and Data Protection

#### Encryption in Transit
- All traffic enforced over HTTPS using TLS 1.2+ with modern cipher suites and HSTS
- Mutual TLS available for enterprise integrations

#### Encryption at Rest
- Full-disk encryption on database and file storage volumes using AES-256
- Field-level encryption for highly sensitive attributes (NAS, medical notes, salary, contract identifiers)
- Encrypted object storage for documents with per-tenant isolation

#### Key Management
- Centralized key management using dedicated KMS/HSM service
- Regular key rotation policies (every 90 days for application keys; immediate rotation on incident)

### 16.2 Authentication and Authorization

#### Authentication
- Django-based auth with:
  - Mandatory email/password + TOTP 2FA for all admin and HR roles
  - Optional SMS-based 2FA for higher subscription tiers
- Session management with short idle timeouts (15 minutes)
- Refresh token strategies for APIs
- Revocation on password/role change

#### Authorization
- Role-based access control (RBAC) per tenant with granular permissions down to object level
- Separation of duties: HR Admin, Recruiter, Manager, Finance, and Viewer roles with least-privilege defaults
- Progressive consent and access gates for sensitive data

#### Tenant Isolation
- Strong logical isolation by schema per tenant in the database
- Enforced by routing middleware and strict query patterns
- No cross-tenant joins; shared services only read from public, non-sensitive configuration layer

### 16.3 Rate Limiting and API Security

#### Rate Limiting
- IP- and user-level throttling on authentication, password reset, and all public APIs
- Tenant-level ceilings for bulk operations (mass email, exports)

#### API Security
- JWT-based auth for programmatic access with short-lived tokens (48h expiry)
- Strict CORS configuration limited to trusted tenant domains
- Signed webhooks and mutual authentication for integrations

#### Abuse and Fraud Controls
- Automated anomaly detection around login behavior, KYC attempts, and data export patterns
- Optional IP allow-lists and SSO enforcement for enterprise customers

### 16.4 Vulnerability Management

#### Secure Development Lifecycle
- Mandatory code review for all changes with automated static analysis in CI
- Dependency scanning for known CVEs and automated upgrade pipelines
- Secrets never stored in source control

#### Testing and Hardening
- Unit, integration, and end-to-end tests with target of ≥90% coverage on security-relevant modules
- Regular dynamic application security testing (DAST) against staging
- Periodic third-party penetration tests

#### Incident Response
- Defined incident response playbooks (detection, triage, containment, eradication, recovery, post-mortem)
- Audit logging of all administrative and security-critical actions with tamper-evident storage (minimum 5 years retention)

### 16.5 Compliance Roadmap

| Year | Certifications |
|------|----------------|
| Y1 | GDPR, eIDAS |
| Y2 | SOC 2 Type I |
| Y3 | SOC 2 Type II, ISO 27001 |

#### Privacy and Data Protection
- GDPR-aligned processing with clear lawful basis
- DPA templates for customers
- Support for data subject rights (access, rectification, erasure, restriction, portability)
- Regional data residency options

#### Electronic Signature Compliance
- eIDAS (EU) and ESIGN/UETA (US) compliant providers
- Full audit trails for each signing event

#### HR and Employment Compliance
- Configurable retention policies for HR data
- Tools for export and structured reporting for audits

---

## 17. Technical Architecture

### 17.1 Core Technology Stack

```
Django 5.x + django-tenants (schema-per-tenant)
PostgreSQL 16 (sharded by tenant)
Redis 7 (sessions, caching, WebSocket channels)
Celery 5.x + RabbitMQ (async KYC, emails)
Nginx + Gunicorn (8 workers)
Docker Compose (dev/prod)
```

### 17.2 Modular Architecture

The backend is structured as a **modular monolith** with clear domain-driven Django apps:

| App | Responsibility |
|-----|----------------|
| `tenants` | Tenant lifecycle, plans, billing metadata, domain mapping |
| `accounts` | Users, roles, permissions, KYC status, progressive consent |
| `ats` | Jobs, applications, pipelines, filters, matching engine, scheduling |
| `hr_core` | Employees, absences, schedules, resignations, onboarding/offboarding |
| `documents` | Contracts, e-signatures, secure document storage |
| `analytics` | Diversity metrics, workforce health, recruitment funnels, reporting |
| `integrations` | Stripe, KYC providers, DocuSign, email (SendGrid), SMS (Twilio) |

### 17.3 Multi-Tenancy Strategy

**Semi-isolated approach**: One PostgreSQL instance, separate schemas per tenant, shared app tier.

#### Tenant Provisioning
- Creation via onboarding wizard with automatic schema creation
- Migration execution per new tenant
- Separate `Tenant` and `Domain` models map subdomains to schemas

#### Data Isolation
- All tenant-scoped models live in tenant schemas
- Shared reference data (plans, global configs) in `public` schema (read-only to tenants)

#### Tenant-Aware Services
- Middleware injects `request.tenant`
- Celery tasks carry tenant identifiers and switch schema context

### 17.4 External API Integrations

| Service | Purpose | Availability |
|---------|---------|--------------|
| Sumsub/Onfido | KYC verification | All plans |
| DocuSign | E-signature | Pro+ |
| Twilio | SMS notifications | Pro+ |
| Stripe | Subscriptions and payments | All plans |
| SendGrid | Email delivery | All plans |
| Calendly | Interview scheduling | All plans |

### 17.5 Scaling Strategy

| Stage | Tenant Count | Infrastructure |
|-------|--------------|----------------|
| **Stage 1** | 0-1K | Single node + basic HA, vertical scaling |
| **Stage 2** | 1K-5K | Horizontal app scaling, multiple containers, read replicas |
| **Stage 3** | 5K-15K+ | Kubernetes, tenant sharding, multi-region |
| **Stage 4** | Enterprise | Dedicated clusters, VPC-isolated environments |

### 17.6 Frontend Architecture

#### Framework
- Django server-rendered templates with HTMX for partial page updates
- Progressive enhancement with Alpine.js
- Future-ready for React + TypeScript micro-frontend if needed

#### Styling
- Tailwind CSS as core utility framework
- Bootstrap 5 selectively for robust components
- 12-column responsive grid (1440px desktop, 1024px tablet, 375px mobile)

#### Design System
- Primary color: Navy blue (#1E3A8A) for trust
- Accent: Emerald/green (#10B981) for verification
- Sans-serif font stack (Inter/Roboto)
- Feather/Phosphor icons

#### Accessibility
- WCAG 2.1 AA target
- Full keyboard navigation
- ARIA labels for custom components
- Dark mode support with system preference detection

---

## 18. Product Roadmap

### Phase 1: MVP Build (0-6 months)

**Goal**: Launch scam-proof ATS with verified candidate pipelines, achieving 500 tenants and €25K MRR.

**Deliverables**:
- Multi-tenant Django backend with Tenant/User/Profile models
- Bidirectional KYC + progressive revelation
- Customizable pipelines (Kanban drag-drop), CV parsing, 20+ ATS filters
- Basic HR: absences, onboarding checklists, e-signature
- Career pages + job-specific landing pages, spontaneous candidacies

**KPIs**: 70% activation rate, 25% freemium → paid conversion, <10% churn

### Phase 2: Closed Beta and Feedback Loop (6-9 months)

**Goal**: Refine UX based on 1,000 beta users, add multi-circuits, hit €100K MRR.

**Deliverables**:
- 4 recruitment circuits (external/internal/talent pool/freelance)
- Advanced analytics (diversity reports, time-to-hire, absenteeism dashboard)
- Granular RBAC per tenant
- SMS notifications, automated interview scheduling
- Custom filter builder + Boolean search

**KPIs**: NPS >50, 80% activation, feature usage >60%

### Phase 3: Public Launch and Growth (9-14 months)

**Goal**: Scale to 2,500 tenants, €250K MRR, EU market dominance.

**Deliverables**:
- Multi-language (FR/EN/DE), multi-currency, international e-signature compliance
- AI matching scores, talent nurturing campaigns, referral tracking
- Enterprise features: SSO (SAML), API/webhooks, custom reports
- Mobile-responsive dashboards, PWA for candidates

**KPIs**: 85% activation, <3% churn, 30% MoM growth

### Phase 4: Integrations and Expansion (15-24 months)

**Goal**: 7,500 tenants, €750K MRR, US market entry.

**Deliverables**:
- HRIS integrations (Payroll: Silae/Papaya; HRIS: Lucca/HRWorks)
- Advanced analytics: turnover prediction, diversity compliance reports
- White-label for agencies, multi-tenant groups (holdings)
- Mobile app (iOS/Android)

**KPIs**: 90% activation, NPS >70, 40% enterprise mix

### Phase 5: Globalization and Enterprise Scale (Year 3+)

**Goal**: 15,000+ tenants, $5M+ ARR, global leader in anti-fraud ATS.

**Deliverables**:
- AI-driven features: CV authenticity scoring, interview sentiment analysis
- Data warehouse exports, SOC 2 Type II certification
- Africa/Asia expansion with local compliance (CNIL, POPIA)
- Dedicated instances for Fortune 500 clients

**KPIs**: 95% activation, <1.5% churn, 50% international revenue

### Success Gates Between Phases

| Transition | Requirements |
|------------|--------------|
| MVP → Beta | 70% activation, 500 tenants, KYC verification rate >85% |
| Beta → Launch | NPS >50, 4 circuits fully adopted by 60% users |
| Launch → Expansion | <3% churn, 30% MoM growth for 3 consecutive months |
| Expansion → Global | SOC 2 certified, 20% international revenue |

---

## 19. Go-to-Market Strategy

### 13.1 Core Messaging

**"Scam-Proof Recruitment"** - The only ATS/HRIS that guarantees verified candidates through bidirectional KYC and progressive data revelation.

### 13.2 Messaging by Segment

| Segment | Message |
|---------|---------|
| **SMEs (10-250 employees)** | "Hire verified talent in 14 days. No more ghost candidates or fake CVs. Complete HR in one dashboard." |
| **Recruitment Agencies** | "Process 10x more candidates with custom pipelines, CV parsing, and infinite ATS filters. Nurture your talent pool automatically." |
| **ESN/Consulting Firms** | "Manage CDI + freelance missions end-to-end. E-sign contracts, track billable hours, zero compliance risk." |
| **Educational Institutions** | "Match students to real jobs. Campus career pages + verified competency testing = 90% placement rate." |

### 13.3 Customer Acquisition Strategy

1. **Content Marketing**: Weekly LinkedIn posts + YouTube demos showing "Fake CV caught by Zumodra KYC in 60 seconds"
2. **Partnerships**: Co-marketing with ESN networks, business schools, and regional chambers of commerce
3. **Freemium Launch**: Free tier (1 pipeline, 50 candidates/month) converts to paid at 25% rate
4. **Paid Channels**: LinkedIn Ads targeting "Recruitment Manager" + "RH Directeur" (€5K/month budget)
5. **Referral Program**: 1 free month per successful referral

### 13.4 Subscription and Pricing Model

**Per-employee/month pricing** (recruiters count as employees):

| Plan | Price | Target | Key Features |
|------|-------|--------|--------------|
| **Starter** | €15/user | SMEs | 3 pipelines, basic ATS, email only |
| **Pro** | €25/user | Agencies | Unlimited pipelines, CV parsing, SMS |
| **Business** | €35/user | ESN | Multi-circuits, e-signature, analytics |
| **Enterprise** | Custom | Large | SSO, API, dedicated support |

- Minimum €99/month
- Annual discount: 20%
- +30% inflation buffer + 50% margin = sustainable pricing

### 13.5 Onboarding Experience

1. **3-minute signup**: Tenant creation → domain setup → first pipeline in 90 seconds
2. **Guided tour**: Interactive demo with sample candidates + "Verify your first CV now"
3. **Success milestones**: Email sequence (Day 1: First pipeline → Day 3: First candidate → Day 7: First interview booked)

### 13.6 Retention and Viral Loops

- **Weekly value emails**: "You saved 14 hours this week on CV screening."
- **Viral mechanism**: Recruiters invite candidates → candidates refer friends (10% discount)
- **Churn prevention**: Usage alerts + dedicated onboarding call for Pro+

### 13.7 Launch KPIs

| Metric | Target M3 | Target M6 | Target M12 |
|--------|-----------|-----------|------------|
| MRR | €25K | €100K | €500K |
| Churn | <5% | <3% | <2% |
| Activation | 70% | 80% | 85% |
| NPS | 40 | 60 | 75 |

### 13.8 1-Year Adoption Vision

**12 months**: 5,000 tenants, €500K MRR, 3 hires (support, sales, devops). EU focus (France, Belgium, Switzerland). Ready for US beta with ESIGN compliance.

---

## 20. Operational and Scalability Strategy

### 20.1 Technical Infrastructure

- **Architecture**: Django monolithic core with django-tenants, progressive decoupling via Celery
- **Cloud Provider**: Hostinger VPS (initial) → DigitalOcean (scale) → AWS EKS (enterprise)
- **Stack**: PostgreSQL (tenant-sharded), Redis, Celery, Nginx + Certbot
- **CI/CD**: GitHub Actions → Docker build → test → staging → prod approval → blue-green deployment
- **Observability**: Sentry (errors), Prometheus+Grafana (metrics), ELK stack (logs)

### 20.2 Customer Support Tiers

| Plan | Response Time | Channel | Escalation |
|------|---------------|---------|------------|
| Starter | 24h | Email + Intercom | None |
| Pro | 4h | Email/Chat | Support@ |
| Business | 1h | Phone/Chat | Dedicated rep |
| Enterprise | 15min | Phone+Slack | 24/7 team |

### 20.3 Team Structure

**Phase 1 (0-12 months, <€500K MRR)**:

| Role | Headcount | Responsibilities | OKRs |
|------|-----------|------------------|------|
| CEO/Founder | 1 | Product, Sales, Partnerships | €500K MRR, 5K tenants |
| Full-Stack Dev | 1 | Core development | 90% test coverage, <1% downtime |
| Support/Sales | 1 (Month 6) | Onboarding, churn prevention | NPS >60, <5% churn |

**Phase 2 (12-24 months)**: +DevOps Engineer, 2 Support Reps, Marketing Lead, Customer Success Manager

**Phase 3 (Y3+)**: 20-person team across Engineering (8), Sales (4), Support (4), Product (4)

### 20.4 Cost Structure

| Resource | 500 tenants | 5K tenants |
|----------|-------------|------------|
| VPS/Cloud | €200 | €2,000 |
| PostgreSQL | €100 | €800 |
| APIs (KYC/Stripe) | €500 | €3,000 |
| Monitoring | €50 | €200 |
| **Total** | **€850** | **€6,000** |

---

## 21. Access and Permission Configuration

### 21.1 GitHub Access

#### Repositories
- Organization: `github.com/rhematek-solutions`
- Main repo: `github.com/rhematek-solutions/zumodra`

#### Permissions
- Engineers and approved agents: READ, WRITE, create branches, commit, open PRs
- MERGE: PRs into `develop` and feature branches
- `main` branch **protected**: only merge via PR with required reviews and CI checks passing

#### Workflow
1. Create feature branch from `develop`
2. Implement/change code
3. Run tests locally or via CI
4. Open PR → request review
5. After approval + green CI → merge into `develop`
6. Scheduled promotion from `develop` → `main` via release PR

### 21.2 Environment Access

| Environment | Access Level | Allowed Actions |
|-------------|--------------|-----------------|
| **Local** | Full | Experiment, create branches, run migrations |
| **Dev** | Full | Pull code, run migrations, restart services, tail logs |
| **Staging** | Full code, controlled data | Load tests, security scans |
| **Production** | Code changes via CI/CD only | Trigger deployments, run schema migrations, restart services |

#### Prohibited on Production (without explicit approval)
- Manual schema changes (ALTER/DROP)
- Direct data manipulation (DELETE/UPDATE)
- Accessing or exporting raw PII outside approved processes

### 21.3 Database Access

#### Dev/Staging
- READ/WRITE
- Create/drop test schemas, run migrations
- Seed anonymized data

#### Production
- Access restricted to DBAs and designated senior engineers
- Agents may apply migrations via CI/CD pipeline only
- No TRUNCATE/DROP TABLE without change ticket and explicit approval

### 21.4 Secrets and Credentials

- Managed via environment variables and secret manager
- **NEVER** commit credentials, API keys, or private keys to Git
- Keys rotated on fixed schedule or after incidents
- Agents receive only minimum secrets required for tasks

### 21.5 Allowed Agent Operations

**MAY**:
- Read and modify code
- Run tests and linters
- Generate migrations (to be reviewed)
- Update CI/CD workflows (under review)
- Trigger dev/staging deployments via GitHub Actions

**MUST NOT (without human approval)**:
- Apply unreviewed migrations to production
- Change infrastructure outside of codified IaC
- Access or export raw production PII directly

---

## 22. Build Execution Prompts

### 22.1 MVP Functionalities Prompt

```
You are an expert Django SaaS engineer working on Zumodra, a multi-tenant ATS/HR platform with anti-fraud KYC, progressive data revelation, and HR operations.

Goal: Implement or extend MVP features according to PROJECT_TEMPLATE.md Section 5 (MVP Phases 1-4) and the current codebase.

Context:
- Stack: Django 5, django-tenants (schema-per-tenant), PostgreSQL, Redis, Celery, DRF, HTMX, Tailwind
- Domains: tenants, accounts, ats, hr_core, documents, analytics, integrations
- Multi-tenancy: django-tenants with public schema for global config and per-tenant schemas for HR/ATS data

When I call you with a feature request, you must:
1. Identify which MVP phase(s) it belongs to (1-4)
2. List the models, views, serializers, templates, and Celery tasks to change or create
3. Implement the feature in small, reviewable commits, following existing patterns
4. Add/extend tests (unit + integration) to keep coverage >= 90% on affected apps
5. Update relevant docs when behavior changes

Constraints:
- Respect tenant isolation at all times (no cross-tenant data leakage)
- Use only approved external services and patterns
- Never hard-code secrets or environment-specific values
```

### 22.2 Backend/Database Prompt

```
You are responsible for the backend, database schema, and multi-tenant architecture of Zumodra.

Stack & Patterns:
- Django 5, django-tenants (schema-per-tenant)
- PostgreSQL 16 (public + per-tenant schemas)
- Redis 7 (cache, channels, Celery broker)
- Celery 5 for async tasks (KYC, notifications, analytics)
- DRF for all API endpoints

Your tasks when invoked:
1. Design or update models, migrations, and admin configurations in the correct domain app
2. Ensure all tenant-scoped models are compatible with django-tenants
3. Implement service functions and DRF viewsets/serializers with clear boundaries
4. Add Celery tasks for long-running operations with tenant-aware context
5. Keep queries efficient (indexes, select_related/prefetch_related, pagination)

Rules:
- Every schema change must be accompanied by a Django migration
- Multi-tenant safety: queries must always be scoped via request.tenant
- Avoid N+1 queries; use prefetching and profiling when needed
```

### 22.3 Frontend/UI-UX Prompt

```
You handle the frontend implementation for Zumodra, including templates, HTMX interactions, Tailwind styling, and UX coherence.

Environment:
- Django templates, HTMX, Alpine.js where needed
- Tailwind CSS as main utility framework; Bootstrap 5 components selectively
- WCAG 2.1 AA accessibility target, light/dark modes, responsive layouts

When a UI feature is requested:
1. Identify which module it belongs to (ATS, HR, Analytics, Settings, etc.)
2. Design or update Django templates, partials, and HTMX endpoints
3. Ensure responsive behavior (mobile/tablet/desktop)
4. Apply design tokens (colors, typography, spacing) and respect tenant theming
5. Maintain accessibility: semantic HTML, ARIA attributes, keyboard navigation

Rules:
- Do not introduce heavy frontend frameworks unless explicitly requested
- Keep JS minimal and inline with existing HTMX/Alpine patterns
- For complex UX, describe flows before implementing
```

### 22.4 Security Reinforcement Prompt

```
You act as a security engineer for Zumodra's codebase and infrastructure.

Scope:
- Web security (XSS, CSRF, SQLi, SSRF, IDOR)
- AuthN/AuthZ correctness (RBAC, 2FA, tenant isolation)
- Rate limiting and abuse prevention
- Secure handling of secrets and PII

When called for a security review or task:
1. Inspect the relevant code paths (views, serializers, templates, Celery tasks)
2. Identify vulnerabilities or weak patterns and propose concrete patches
3. Add or update tests to cover security cases
4. Recommend configuration changes (Django settings, middleware, CSP, headers)

Checklist:
- Input validation and output encoding
- CSRF protection on state-changing endpoints
- SQL injection safety (ORM usage, no raw SQL unless parameterized)
- Access control checks on every sensitive operation
- Rate limiting on login, password reset, and public APIs
- Logging of security-relevant events without leaking PII
```

### 22.5 Deployment Prompt

```
You manage the deployment pipeline for Zumodra across dev, staging, and production environments.

Infrastructure Baseline:
- Docker images for app, Celery, Nginx, Postgres, Redis
- CI/CD via GitHub Actions
- Nginx reverse proxy with Let's Encrypt/Certbot SSL

When a deployment or infra task is requested:
1. Confirm which environment(s) are targeted
2. Generate or update Dockerfiles and docker-compose/Kubernetes manifests
3. Ensure migrations are applied in a safe, idempotent way
4. Configure health checks, readiness/liveness probes, and rollbacks
5. Respect ACCESS_INSTRUCTIONS.md and permissions_policy.json limits

Standard Deployment Steps:
- Build & tag Docker images
- Run test suite (unit/integration) and security checks
- Apply migrations
- Collect static files
- Reload/restart services with minimal downtime
- Verify critical endpoints and background workers
```

---

## 23. Quality Assurance and Verification

### 23.1 Functional and Regression Verification

Verify all critical user journeys work end-to-end for at least one tenant:

1. Tenant creation → onboarding wizard → first pipeline setup
2. Recruiter signup/login with 2FA → create job → receive and process applications
3. Candidate signup → KYC flow → apply to job → move through pipeline → offer
4. HR operations: create employee, approve leave, run analytics dashboard

Confirm no previously working core feature is broken (regression pass on auth, ATS board, KYC, HR dashboards, e-signature, notifications).

### 23.2 Automated Test and Coverage Verification

Run the full automated test suite:
- Unit tests
- Integration/API tests
- End-to-end/functional tests

Confirm:
- All tests pass successfully
- Code coverage for core apps meets or exceeds ≥90%

### 23.3 Security and Hardening Checks

1. **Authentication & Authorization**:
   - Tenant isolation preserved
   - RBAC roles enforce least privilege
   - 2FA works for privileged accounts

2. **Web Security Controls**:
   - CSRF protection on all state-changing endpoints
   - XSS, SQL injection, and IDOR mitigations in place
   - HTTPS enforced, HSTS enabled, secure cookies set

3. **Security Scan Results**: No critical or high-severity unresolved findings

### 23.4 Performance and Observability

1. Application health validation:
   - Uptime for app, database, Redis, Celery workers within SLOs
   - Key endpoints respond within acceptable latency

2. Observability verification:
   - Logs being ingested and searchable
   - Metrics and dashboards functioning
   - Alerts configured for critical conditions

### 23.5 Deployment and Configuration Validation

1. Deployment process verification:
   - Docker images built from expected commit
   - Migrations applied cleanly
   - Static assets collected and served correctly

2. Environment configuration:
   - All required environment variables set
   - No debug flags enabled in production
   - Correct domain, SSL, and reverse proxy configuration

### 23.6 Go-Live Checklist

Before marking a release as "LIVE & HARDENED":

- [ ] All planned features implemented and tested
- [ ] All automated tests pass with acceptable coverage
- [ ] No unresolved critical security or stability issues
- [ ] Monitoring, logging, and alerting operational
- [ ] Rollback strategy defined and tested

### 23.7 Final Sign-off Format

```
Release: <version/tag>
Environment: <staging|production>

Functional tests: PASS/FAIL (summary)
Automated tests: PASS/FAIL (coverage: XX%)
Security checks: PASS/FAIL (notes)
Performance/health: PASS/FAIL (notes)
Deployment validation: PASS/FAIL (notes)

Blockers: <none | list with severity>
Recommendation: <APPROVE FOR LIVE | DO NOT APPROVE>
Signed by: <name/role>, <date/time>
```

---

## Appendix A: Django Models Reference

### Core Models

| Model | Description | Key Fields | Relations |
|-------|-------------|------------|-----------|
| **User** | Platform users | username, email, password, first_name, last_name, is_active, last_login | OneToOne with Profile |
| **Profile** | Detailed user information | photo, bio, address, phone, CV, KYC_status | FK to User, FK to Badge |
| **Badge** | Certificates/verifications | name, description, date_attribution, type | ManyToMany to Profile |
| **Recruiter** | Recruiter-specific profile | company, sector, TVA, company_address | FK to User |
| **Service** | Service offerings | title, description, rate, duration, category | FK to Profile |
| **Evaluation** | Ratings and reviews | note, comment, date | FK to Service, FK to User |
| **Document** | Uploaded documents | type, file, upload_date | FK to Profile |
| **AuditLog** | Platform action logs | action_type, description, timestamp | FK to User |
| **Conversation** | User discussions | participants, creation_date | ManyToMany to User |
| **Message** | Conversation messages | content, timestamp | FK to Conversation, FK to User |
| **Payment** | Payment information | amount, status, date, type | FK to User |
| **Matching** | Compatibility scores | score | FK to Profile (client), FK to Profile (provider) |
| **Tenant** | Enterprise tenant | name, subdomain, branding | |
| **TenantSettings** | Tenant configuration | settings | FK to Tenant |
| **Plan** | Subscription plan | name, features, price | |
| **Subscription** | Tenant subscription | status, start_date, end_date | FK to Tenant, FK to Plan |

### Key Relationships

- **User ↔ Profile**: One-to-one relationship; each user has a detailed profile
- **Profile ↔ Badge**: Many-to-many; a profile can have multiple badges
- **Profile ↔ Service**: Service offered by a profile (provider)
- **Service ↔ Evaluation**: A service can have multiple evaluations from different clients
- **Conversation ↔ User**: Discussion between multiple users (generally 2)
- **Payment ↔ User**: Each payment linked to a user (client or provider)

---

## Appendix B: API Endpoints Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login/` | POST | User login with credentials |
| `/api/auth/logout/` | POST | User logout |
| `/api/auth/register/` | POST | New user registration |
| `/api/auth/2fa/setup/` | POST | Setup 2FA |
| `/api/auth/2fa/verify/` | POST | Verify 2FA code |

### Tenants

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tenants/` | GET, POST | List/create tenants |
| `/api/tenants/{id}/` | GET, PUT, DELETE | Tenant details |
| `/api/tenants/{id}/settings/` | GET, PUT | Tenant settings |

### ATS

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/jobs/` | GET, POST | List/create job postings |
| `/api/jobs/{id}/` | GET, PUT, DELETE | Job details |
| `/api/applications/` | GET, POST | List/create applications |
| `/api/applications/{id}/` | GET, PUT | Application details |
| `/api/pipelines/` | GET, POST | List/create pipelines |
| `/api/pipelines/{id}/stages/` | GET, POST | Pipeline stages |

### HR

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/employees/` | GET, POST | List/create employees |
| `/api/employees/{id}/` | GET, PUT, DELETE | Employee details |
| `/api/absences/` | GET, POST | List/create absence requests |
| `/api/absences/{id}/approve/` | POST | Approve absence request |
| `/api/onboarding/` | GET, POST | List/create onboarding checklists |

---

## Appendix C: Configuration Files

### permissions_policy.json

```json
{
  "version": "1.0",
  "description": "Permissions policy for engineering agents on the Zumodra platform.",
  "environments": {
    "local": {
      "code": ["read", "write", "refactor", "test", "lint"],
      "ci": ["run_tests"],
      "db": ["read", "write", "migrate"],
      "infra": [],
      "secrets": []
    },
    "dev": {
      "code": ["read", "write", "refactor"],
      "ci": ["run_tests", "deploy_dev"],
      "db": ["read", "write", "migrate"],
      "infra": ["restart_service", "check_logs"],
      "secrets": ["use_runtime"]
    },
    "staging": {
      "code": ["read", "write", "refactor"],
      "ci": ["run_tests", "deploy_staging"],
      "db": ["read", "migrate"],
      "infra": ["restart_service", "check_logs"],
      "secrets": ["use_runtime"]
    },
    "production": {
      "code": ["read"],
      "ci": ["run_tests", "deploy_production_with_approval"],
      "db": ["migrate_schema_only"],
      "infra": ["restart_service_with_approval", "check_logs"],
      "secrets": ["use_runtime"],
      "restrictions": [
        "no_direct_data_modification",
        "no_drop_or_truncate_tables",
        "no_export_of_raw_PII",
        "no_secret_rotation"
      ]
    }
  },
  "global_restrictions": [
    "no_commit_of_secrets_to_git",
    "no_disabling_of_logging",
    "no_bypass_of_branch_protection"
  ],
  "audit": {
    "require_linked_ticket_for": [
      "deploy_staging",
      "deploy_production_with_approval",
      "migrate_schema_only",
      "restart_service_with_approval"
    ],
    "log_fields": [
      "actor",
      "environment",
      "operation",
      "timestamp",
      "git_commit",
      "ticket_id"
    ]
  }
}
```

---

*Document Version: 1.0*
*Last Updated: January 2026*
*Zumodra ATS/RH Platform - Rhematek Solutions*
