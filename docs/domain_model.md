# Zumodra Domain Model Documentation

> **Status**: FROZEN as of 2025-12-31
> **Version**: 1.0.0
> **Purpose**: Authoritative reference for all core domain models

---

## Table of Contents

1. [Overview](#overview)
2. [Multi-Tenancy Layer](#multi-tenancy-layer)
3. [User & Authentication](#user--authentication)
4. [Verification & Trust](#verification--trust)
5. [ATS (Applicant Tracking System)](#ats-applicant-tracking-system)
6. [HR Core](#hr-core)
7. [Services & Marketplace](#services--marketplace)
8. [Finance & Escrow](#finance--escrow)
9. [Messaging System](#messaging-system)
10. [Analytics](#analytics)
11. [AI Matching](#ai-matching)
12. [Careers & Co-op](#careers--co-op)
13. [Notifications](#notifications)
14. [Newsletter](#newsletter)
15. [Entity Relationship Diagram](#entity-relationship-diagram)

---

## Overview

Zumodra is a multi-tenant SaaS platform with **120+ models** across **13 core apps**. The architecture follows a schema-per-tenant isolation pattern using `django-tenants`.

### Core Principles

- **Tenant Isolation**: All business data is scoped to a tenant schema
- **UUID Primary Keys**: Most entities use UUIDs for security and distributed systems
- **Soft Deletes**: Critical entities support soft deletion via `is_active` flags
- **Audit Trails**: Timestamp fields (`created_at`, `updated_at`) on all models
- **PostGIS Integration**: Geospatial features for location-based matching

---

## Multi-Tenancy Layer

**App**: `tenants`

### Tenant
The root entity representing an enterprise/organization.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `name` | CharField | Organization name |
| `slug` | SlugField | URL-safe identifier |
| `schema_name` | CharField | PostgreSQL schema name |
| `plan` | FK → Plan | Subscription tier |
| `is_active` | Boolean | Tenant status |
| `created_at` | DateTime | Creation timestamp |

### Plan
Subscription tiers with feature limits.

| Field | Type | Description |
|-------|------|-------------|
| `name` | CharField | Plan name (Free, Pro, Enterprise) |
| `max_users` | Integer | User limit |
| `max_jobs` | Integer | Job posting limit |
| `features` | JSONField | Feature flags |
| `price_monthly` | Decimal | Monthly cost |

### Domain
Custom domains for white-label tenants.

| Field | Type | Description |
|-------|------|-------------|
| `domain` | CharField | Domain name |
| `tenant` | FK → Tenant | Owner tenant |
| `is_primary` | Boolean | Primary domain flag |

### Circusale (Business Unit)
Divisions/locations within a tenant.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | FK → Tenant | Parent tenant |
| `name` | CharField | Division name |
| `address` | PointField | PostGIS location |
| `budget` | Decimal | Allocated budget |
| `manager` | FK → User | Division manager |

### TenantSettings
Tenant-specific configuration.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | OneToOne → Tenant | Parent tenant |
| `branding` | JSONField | Logo, colors, theme |
| `features_enabled` | JSONField | Feature toggles |
| `default_language` | CharField | i18n default |

---

## User & Authentication

**App**: `accounts`

### CustomUser (AUTH_USER_MODEL)
Extended Django user with tenant association.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `email` | EmailField | Primary identifier (unique) |
| `phone` | CharField | Phone number |
| `tenant` | FK → Tenant | Tenant association |
| `circusale` | FK → Circusale | Business unit |
| `role` | CharField | PDG, Supervisor, HR, Employee, etc. |
| `is_verified` | Boolean | Email verification status |
| `two_factor_enabled` | Boolean | 2FA status |
| `profile_type` | CharField | client, provider, admin |

### Profile
Extended user profile with verification status.

| Field | Type | Description |
|-------|------|-------------|
| `user` | OneToOne → User | Parent user |
| `bio` | TextField | User biography |
| `avatar` | ImageField | Profile image |
| `location` | PointField | PostGIS coordinates |
| `skills` | M2M → Skill | User skills |
| `verification_level` | Integer | 0-3 verification tier |

### StudentProfile
Student-specific profile for co-op programs.

| Field | Type | Description |
|-------|------|-------------|
| `user` | OneToOne → User | Parent user |
| `university` | CharField | Institution name |
| `program` | CharField | Degree program |
| `expected_graduation` | DateField | Graduation date |
| `gpa` | Decimal | Grade point average |

### CoopTerm
Co-op work term tracking.

| Field | Type | Description |
|-------|------|-------------|
| `student` | FK → StudentProfile | Student |
| `employer` | FK → Tenant | Employer tenant |
| `position` | CharField | Job title |
| `start_date` | DateField | Term start |
| `end_date` | DateField | Term end |
| `status` | CharField | pending, active, completed |
| `supervisor_evaluation` | TextField | Performance review |

---

## Verification & Trust

**App**: `accounts`

### KYCVerification
Know Your Customer identity verification.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `user` | FK → User | Subject user |
| `status` | CharField | PENDING, IN_PROGRESS, VERIFIED, REJECTED |
| `provider` | CharField | Verification provider (e.g., Stripe Identity) |
| `provider_reference` | CharField | External reference ID |
| `document_type` | CharField | passport, driver_license, id_card |
| `submitted_at` | DateTime | Submission timestamp |
| `verified_at` | DateTime | Verification timestamp |
| `rejection_reason` | TextField | Reason if rejected |
| `metadata` | JSONField | Provider response data |

### EmploymentVerification
Employment history verification.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `user` | FK → User | Subject user |
| `company_name` | CharField | Employer name |
| `position` | CharField | Job title |
| `start_date` | DateField | Employment start |
| `end_date` | DateField | Employment end |
| `status` | CharField | PENDING, VERIFIED, REJECTED |
| `verification_method` | CharField | email, document, api |
| `verifier_email` | EmailField | HR contact email |
| `verification_token` | CharField | Secure token for email verification |
| `token_expires_at` | DateTime | Token expiry |
| `verified_at` | DateTime | Verification timestamp |

### EducationVerification
Educational credential verification.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `user` | FK → User | Subject user |
| `institution` | CharField | School/university name |
| `degree` | CharField | Degree type |
| `field_of_study` | CharField | Major/concentration |
| `graduation_date` | DateField | Graduation date |
| `status` | CharField | PENDING, VERIFIED, REJECTED |
| `verification_method` | CharField | email, document, api |
| `document` | FileField | Uploaded transcript/diploma |
| `verified_at` | DateTime | Verification timestamp |

### TrustScore
Aggregated trust score for users.

| Field | Type | Description |
|-------|------|-------------|
| `user` | OneToOne → User | Subject user |
| `overall_score` | Decimal | Composite score (0-100) |
| `kyc_score` | Decimal | KYC component |
| `employment_score` | Decimal | Employment verification component |
| `education_score` | Decimal | Education verification component |
| `activity_score` | Decimal | Platform activity component |
| `dispute_score` | Decimal | Dispute history component |
| `last_calculated` | DateTime | Last calculation timestamp |

### ProgressiveConsent
GDPR-compliant consent tracking.

| Field | Type | Description |
|-------|------|-------------|
| `user` | FK → User | Subject user |
| `consent_type` | CharField | marketing, analytics, data_sharing |
| `granted` | Boolean | Consent status |
| `granted_at` | DateTime | Consent timestamp |
| `ip_address` | GenericIPAddress | Consent origin |
| `user_agent` | TextField | Browser info |

### DataAccessLog
Audit trail for data access.

| Field | Type | Description |
|-------|------|-------------|
| `user` | FK → User | Accessing user |
| `target_user` | FK → User | Data subject |
| `access_type` | CharField | view, export, delete |
| `data_category` | CharField | profile, financial, verification |
| `timestamp` | DateTime | Access timestamp |
| `justification` | TextField | Reason for access |

---

## ATS (Applicant Tracking System)

**App**: `ats`

### Job
Job postings within a tenant.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `tenant` | FK → Tenant | Owner tenant |
| `title` | CharField | Job title |
| `description` | TextField | Job description |
| `department` | FK → Department | Department |
| `location` | PointField | PostGIS coordinates |
| `employment_type` | CharField | full_time, part_time, contract |
| `salary_min` | Decimal | Salary range minimum |
| `salary_max` | Decimal | Salary range maximum |
| `status` | CharField | draft, published, closed |
| `published_at` | DateTime | Publication date |
| `closes_at` | DateTime | Application deadline |
| `required_skills` | M2M → Skill | Required skills |

### Candidate
Applicant profiles.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `user` | FK → User | Optional linked user |
| `email` | EmailField | Contact email |
| `first_name` | CharField | First name |
| `last_name` | CharField | Last name |
| `phone` | CharField | Phone number |
| `resume` | FileField | Resume document |
| `source` | CharField | referral, job_board, direct |
| `created_at` | DateTime | Creation timestamp |

### Application
Job applications linking candidates to jobs.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `job` | FK → Job | Target job |
| `candidate` | FK → Candidate | Applicant |
| `stage` | FK → PipelineStage | Current pipeline stage |
| `status` | CharField | active, hired, rejected, withdrawn |
| `applied_at` | DateTime | Application timestamp |
| `score` | Decimal | AI/manual score |
| `notes` | TextField | Internal notes |

### PipelineStage
Customizable recruitment pipeline stages.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | FK → Tenant | Owner tenant |
| `name` | CharField | Stage name |
| `order` | Integer | Display order |
| `is_terminal` | Boolean | Final stage flag |
| `auto_actions` | JSONField | Automated actions |

### Interview
Interview scheduling and tracking.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `application` | FK → Application | Related application |
| `interviewer` | FK → User | Interviewer |
| `scheduled_at` | DateTime | Interview time |
| `duration_minutes` | Integer | Duration |
| `interview_type` | CharField | phone, video, onsite |
| `meeting_link` | URLField | Video call URL |
| `status` | CharField | scheduled, completed, cancelled |

### InterviewFeedback
Post-interview evaluations.

| Field | Type | Description |
|-------|------|-------------|
| `interview` | FK → Interview | Parent interview |
| `interviewer` | FK → User | Evaluator |
| `rating` | Integer | 1-5 rating |
| `recommendation` | CharField | hire, no_hire, maybe |
| `strengths` | TextField | Positive notes |
| `concerns` | TextField | Concerns |
| `submitted_at` | DateTime | Submission timestamp |

### Offer
Job offers to candidates.

| Field | Type | Description |
|-------|------|-------------|
| `application` | FK → Application | Related application |
| `salary` | Decimal | Offered salary |
| `start_date` | DateField | Proposed start date |
| `expires_at` | DateTime | Offer expiry |
| `status` | CharField | pending, accepted, declined, expired |
| `document` | FileField | Offer letter |

---

## HR Core

**App**: `hr_core`

### Employee
Employee records within tenant.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `user` | OneToOne → User | Linked user account |
| `employee_id` | CharField | Internal employee ID |
| `department` | FK → Department | Department |
| `manager` | FK → Employee | Direct manager |
| `hire_date` | DateField | Start date |
| `employment_type` | CharField | full_time, part_time, contractor |
| `status` | CharField | active, on_leave, terminated |

### Department
Organizational departments.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | FK → Tenant | Owner tenant |
| `name` | CharField | Department name |
| `parent` | FK → Department | Parent department |
| `head` | FK → Employee | Department head |
| `budget` | Decimal | Annual budget |

### TimeOffRequest
Leave/vacation requests.

| Field | Type | Description |
|-------|------|-------------|
| `employee` | FK → Employee | Requester |
| `leave_type` | CharField | vacation, sick, personal |
| `start_date` | DateField | Leave start |
| `end_date` | DateField | Leave end |
| `status` | CharField | pending, approved, denied |
| `approver` | FK → Employee | Approving manager |
| `notes` | TextField | Request notes |

### OnboardingChecklist
New hire onboarding tasks.

| Field | Type | Description |
|-------|------|-------------|
| `employee` | FK → Employee | New hire |
| `task` | CharField | Task description |
| `category` | CharField | documentation, training, equipment |
| `due_date` | DateField | Due date |
| `completed` | Boolean | Completion status |
| `completed_at` | DateTime | Completion timestamp |

---

## Services & Marketplace

**App**: `services`

### ServiceProvider
Freelancer/agency profiles.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `user` | OneToOne → User | Provider user |
| `business_name` | CharField | Business/brand name |
| `description` | TextField | Provider description |
| `hourly_rate` | Decimal | Default hourly rate |
| `availability` | CharField | available, busy, unavailable |
| `rating` | Decimal | Average rating |
| `completed_projects` | Integer | Project count |
| `verification_level` | Integer | Trust tier |

### Service
Service listings.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `provider` | FK → ServiceProvider | Service owner |
| `title` | CharField | Service title |
| `description` | TextField | Service description |
| `category` | FK → Category | Service category |
| `price` | Decimal | Base price |
| `price_type` | CharField | fixed, hourly, custom |
| `delivery_time` | Integer | Days to deliver |
| `is_active` | Boolean | Active status |

### ServiceProposal
Proposals for client requests.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `service` | FK → Service | Related service |
| `client` | FK → User | Client user |
| `provider` | FK → ServiceProvider | Proposing provider |
| `description` | TextField | Proposal details |
| `price` | Decimal | Proposed price |
| `delivery_days` | Integer | Proposed timeline |
| `status` | CharField | pending, accepted, rejected |

### ServiceContract
Active service agreements.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `proposal` | FK → ServiceProposal | Source proposal |
| `client` | FK → User | Client |
| `provider` | FK → ServiceProvider | Provider |
| `total_amount` | Decimal | Contract value |
| `status` | CharField | active, completed, disputed, cancelled |
| `started_at` | DateTime | Contract start |
| `completed_at` | DateTime | Completion timestamp |
| `escrow_transaction` | FK → EscrowTransaction | Linked escrow |

### Review
Service reviews and ratings.

| Field | Type | Description |
|-------|------|-------------|
| `contract` | FK → ServiceContract | Reviewed contract |
| `reviewer` | FK → User | Review author |
| `rating` | Integer | 1-5 rating |
| `comment` | TextField | Review text |
| `created_at` | DateTime | Review timestamp |

---

## Finance & Escrow

**App**: `finance`

### EscrowTransaction
Escrow-held payments.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `contract` | FK → ServiceContract | Related contract |
| `payer` | FK → User | Client/payer |
| `payee` | FK → User | Provider/payee |
| `amount` | Decimal | Escrowed amount |
| `currency` | CharField | Currency code |
| `status` | CharField | held, released, refunded, disputed |
| `stripe_payment_intent` | CharField | Stripe reference |
| `held_at` | DateTime | Escrow timestamp |
| `released_at` | DateTime | Release timestamp |

### ConnectedAccount
Stripe Connect accounts for payouts.

| Field | Type | Description |
|-------|------|-------------|
| `user` | OneToOne → User | Account owner |
| `stripe_account_id` | CharField | Stripe account ID |
| `account_type` | CharField | express, standard, custom |
| `is_verified` | Boolean | Verification status |
| `payout_enabled` | Boolean | Payout capability |
| `created_at` | DateTime | Creation timestamp |

### PlatformFee
Platform commission tracking.

| Field | Type | Description |
|-------|------|-------------|
| `escrow` | FK → EscrowTransaction | Source transaction |
| `amount` | Decimal | Fee amount |
| `percentage` | Decimal | Fee percentage |
| `collected_at` | DateTime | Collection timestamp |

### Subscription
Tenant subscription records.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | FK → Tenant | Subscriber tenant |
| `plan` | FK → Plan | Subscription plan |
| `stripe_subscription_id` | CharField | Stripe reference |
| `status` | CharField | active, past_due, cancelled |
| `current_period_start` | DateTime | Period start |
| `current_period_end` | DateTime | Period end |

### Invoice
Billing invoices.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | FK → Tenant | Billed tenant |
| `stripe_invoice_id` | CharField | Stripe reference |
| `amount` | Decimal | Invoice amount |
| `status` | CharField | draft, open, paid, void |
| `due_date` | DateField | Payment due date |
| `paid_at` | DateTime | Payment timestamp |

---

## Messaging System

**App**: `messages_sys`

### Conversation
Chat conversations between users.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `participants` | M2M → User | Conversation members |
| `contract` | FK → ServiceContract | Optional linked contract |
| `created_at` | DateTime | Creation timestamp |
| `updated_at` | DateTime | Last activity |

### Message
Individual messages.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `conversation` | FK → Conversation | Parent conversation |
| `sender` | FK → User | Message author |
| `content` | TextField | Message text |
| `message_type` | CharField | text, file, system |
| `is_read` | Boolean | Read status |
| `created_at` | DateTime | Send timestamp |

### Attachment
Message file attachments.

| Field | Type | Description |
|-------|------|-------------|
| `message` | FK → Message | Parent message |
| `file` | FileField | Uploaded file |
| `filename` | CharField | Original filename |
| `file_type` | CharField | MIME type |
| `file_size` | Integer | Size in bytes |

---

## Analytics

**App**: `analytics`

### MetricSnapshot
Point-in-time metrics.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | FK → Tenant | Owner tenant |
| `metric_type` | CharField | applications, hires, revenue |
| `value` | Decimal | Metric value |
| `period` | CharField | daily, weekly, monthly |
| `recorded_at` | DateTime | Snapshot timestamp |

### FunnelMetric
Recruitment funnel analytics.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | FK → Tenant | Owner tenant |
| `job` | FK → Job | Optional job filter |
| `stage` | FK → PipelineStage | Funnel stage |
| `count` | Integer | Candidates at stage |
| `conversion_rate` | Decimal | Conversion percentage |
| `recorded_at` | DateTime | Snapshot timestamp |

### UserActivity
User behavior tracking.

| Field | Type | Description |
|-------|------|-------------|
| `user` | FK → User | Tracked user |
| `action` | CharField | page_view, click, search |
| `target` | CharField | Target element/page |
| `metadata` | JSONField | Additional data |
| `ip_address` | GenericIPAddress | Request origin |
| `timestamp` | DateTime | Activity timestamp |

---

## AI Matching

**App**: `ai_matching`

### MatchingProfile
AI-ready user profiles.

| Field | Type | Description |
|-------|------|-------------|
| `user` | OneToOne → User | Profile owner |
| `skills_vector` | ArrayField | Skill embeddings |
| `experience_vector` | ArrayField | Experience embeddings |
| `preferences` | JSONField | Matching preferences |
| `last_updated` | DateTime | Last embedding update |

### MatchResult
AI match results.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `source` | FK → User | Source user/job |
| `target` | FK → User | Matched user/job |
| `match_type` | CharField | job_candidate, service_client |
| `score` | Decimal | Match score (0-1) |
| `factors` | JSONField | Score breakdown |
| `created_at` | DateTime | Match timestamp |

### SkillTaxonomy
Hierarchical skill definitions.

| Field | Type | Description |
|-------|------|-------------|
| `name` | CharField | Skill name |
| `parent` | FK → SkillTaxonomy | Parent skill |
| `category` | CharField | technical, soft, domain |
| `synonyms` | ArrayField | Alternate names |
| `embedding` | ArrayField | Skill embedding |

---

## Careers & Co-op

**App**: `careers`

### CareerPage
Public career pages.

| Field | Type | Description |
|-------|------|-------------|
| `tenant` | OneToOne → Tenant | Owner tenant |
| `slug` | SlugField | URL slug |
| `title` | CharField | Page title |
| `description` | TextField | Company description |
| `logo` | ImageField | Company logo |
| `is_published` | Boolean | Publication status |

### PublicJob
Jobs displayed on career pages.

| Field | Type | Description |
|-------|------|-------------|
| `job` | FK → Job | Internal job |
| `career_page` | FK → CareerPage | Display page |
| `custom_description` | TextField | Public description |
| `apply_url` | URLField | Application URL |

---

## Notifications

**App**: `notifications`

### Notification
User notifications.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `user` | FK → User | Recipient |
| `notification_type` | CharField | info, warning, action_required |
| `title` | CharField | Notification title |
| `message` | TextField | Notification body |
| `action_url` | URLField | Optional action link |
| `is_read` | Boolean | Read status |
| `created_at` | DateTime | Creation timestamp |

### NotificationPreference
User notification settings.

| Field | Type | Description |
|-------|------|-------------|
| `user` | OneToOne → User | Settings owner |
| `email_enabled` | Boolean | Email notifications |
| `push_enabled` | Boolean | Push notifications |
| `sms_enabled` | Boolean | SMS notifications |
| `digest_frequency` | CharField | immediate, daily, weekly |

---

## Newsletter

**App**: `newsletter`

### Newsletter
Email campaigns.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `tenant` | FK → Tenant | Owner tenant |
| `subject` | CharField | Email subject |
| `content` | TextField | Email body |
| `status` | CharField | draft, scheduled, sent |
| `scheduled_at` | DateTime | Send time |
| `sent_at` | DateTime | Actual send time |

### Subscriber
Newsletter subscribers.

| Field | Type | Description |
|-------|------|-------------|
| `email` | EmailField | Subscriber email |
| `tenant` | FK → Tenant | Owner tenant |
| `is_active` | Boolean | Subscription status |
| `subscribed_at` | DateTime | Subscription timestamp |
| `unsubscribed_at` | DateTime | Unsubscription timestamp |

---

## Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MULTI-TENANCY                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────┐     ┌──────────┐     ┌─────────────┐                          │
│  │  Tenant  │────▶│   Plan   │     │   Domain    │                          │
│  └────┬─────┘     └──────────┘     └─────────────┘                          │
│       │                                                                      │
│       ▼                                                                      │
│  ┌──────────┐     ┌───────────────┐                                         │
│  │Circusale │     │TenantSettings │                                         │
│  └──────────┘     └───────────────┘                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER & VERIFICATION                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────┐     ┌──────────┐     ┌────────────────┐                       │
│  │   User   │────▶│ Profile  │────▶│  TrustScore    │                       │
│  └────┬─────┘     └──────────┘     └────────────────┘                       │
│       │                                   ▲                                  │
│       │           ┌───────────────────────┼───────────────────┐             │
│       │           │                       │                   │             │
│       ▼           ▼                       ▼                   ▼             │
│  ┌──────────┐ ┌──────────────┐ ┌─────────────────┐ ┌──────────────────┐    │
│  │   KYC    │ │ Employment   │ │   Education     │ │ Progressive      │    │
│  │Verificat.│ │ Verification │ │  Verification   │ │ Consent          │    │
│  └──────────┘ └──────────────┘ └─────────────────┘ └──────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           ATS & RECRUITMENT                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────┐     ┌───────────┐     ┌─────────────┐                         │
│  │   Job    │◀───▶│Application│◀───▶│  Candidate  │                         │
│  └────┬─────┘     └─────┬─────┘     └─────────────┘                         │
│       │                 │                                                    │
│       ▼                 ▼                                                    │
│  ┌──────────┐     ┌───────────┐     ┌─────────────┐                         │
│  │ Pipeline │     │ Interview │────▶│  Feedback   │                         │
│  │  Stage   │     └───────────┘     └─────────────┘                         │
│  └──────────┘           │                                                    │
│                         ▼                                                    │
│                   ┌───────────┐                                              │
│                   │   Offer   │                                              │
│                   └───────────┘                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         SERVICES & FINANCE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌──────────┐     ┌──────────────┐                     │
│  │ServiceProvider│───▶│ Service  │     │   Client     │                     │
│  └──────────────┘     └────┬─────┘     └──────┬───────┘                     │
│                            │                   │                             │
│                            ▼                   ▼                             │
│                      ┌───────────────────────────┐                          │
│                      │    ServiceProposal        │                          │
│                      └────────────┬──────────────┘                          │
│                                   │                                          │
│                                   ▼                                          │
│                      ┌───────────────────────────┐                          │
│                      │    ServiceContract        │                          │
│                      └────────────┬──────────────┘                          │
│                                   │                                          │
│                    ┌──────────────┼──────────────┐                          │
│                    ▼              ▼              ▼                          │
│              ┌──────────┐  ┌───────────┐  ┌──────────┐                      │
│              │  Escrow  │  │  Review   │  │ Message  │                      │
│              │Transaction│  └───────────┘  │Conversation│                   │
│              └────┬─────┘                  └──────────┘                      │
│                   │                                                          │
│                   ▼                                                          │
│              ┌──────────────┐     ┌───────────────────┐                     │
│              │ PlatformFee  │     │ ConnectedAccount  │                     │
│              └──────────────┘     └───────────────────┘                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Relationships Summary

| From | To | Relationship | Description |
|------|-----|--------------|-------------|
| Tenant | User | 1:N | Users belong to a tenant |
| Tenant | Circusale | 1:N | Business units within tenant |
| User | Profile | 1:1 | Extended user data |
| User | KYCVerification | 1:N | KYC attempts |
| User | EmploymentVerification | 1:N | Employment records |
| User | EducationVerification | 1:N | Education records |
| User | TrustScore | 1:1 | Aggregated trust |
| User | ServiceProvider | 1:1 | Provider profile |
| Job | Application | 1:N | Applications per job |
| Application | Candidate | N:1 | Candidate applications |
| Application | Interview | 1:N | Interview rounds |
| ServiceContract | EscrowTransaction | 1:1 | Payment escrow |
| ServiceContract | Conversation | 1:1 | Contract discussion |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-12-31 | Initial frozen domain model |

---

> **Note**: This document represents the frozen domain model. Any changes require a formal review process and version increment.
