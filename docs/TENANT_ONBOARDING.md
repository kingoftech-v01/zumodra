# Zumodra Tenant Onboarding Guide

**Version:** 1.1.0
**Last Updated:** January 2026

Welcome to Zumodra! This guide will help you set up your organization and start using the platform.

---

## Table of Contents

1. [Demo Tenant](#demo-tenant)
2. [Getting Started](#getting-started)
3. [Initial Setup](#initial-setup)
4. [Team Management](#team-management)
5. [ATS Configuration](#ats-configuration)
6. [HR Core Setup](#hr-core-setup)
7. [Marketplace Setup](#marketplace-setup)
8. [Integrations](#integrations)
9. [Best Practices](#best-practices)
10. [Getting Help](#getting-help)

---

## Demo Tenant

A pre-configured demo tenant is available for testing and exploration. It contains realistic sample data across all platform features.

### Demo Tenant URL

```
http://demo.localhost:8000
```

### Demo Login Credentials

| Role | Email | Password |
|------|-------|----------|
| **Admin** | admin@demo.zumodra.local | Demo@2024! |
| **HR Manager** | hr@demo.zumodra.local | Demo@2024! |
| **Recruiter** | recruiter@demo.zumodra.local | Demo@2024! |
| **Hiring Manager** | hiring@demo.zumodra.local | Demo@2024! |
| **Employee** | employee@demo.zumodra.local | Demo@2024! |
| **Candidate** | candidate@demo.zumodra.local | Demo@2024! |

### Demo Data Included

The demo tenant contains:

**ATS (Applicant Tracking)**
- 8 job categories (Engineering, Design, Marketing, Sales, etc.)
- 15 job postings with various statuses
- 50 candidates with skills and experience
- Applications spread across pipeline stages
- Scheduled interviews (past and future)
- Draft and sent offers

**HR Core**
- 25 employees with profiles
- Time-off types (PTO, Sick Leave, Personal)
- Pending and approved time-off requests

**Marketplace**
- 6 service categories
- 10 service providers with profiles
- Sample services and proposals

**Verification & Trust**
- KYC verifications (pending, approved)
- Trust scores for demo users

**Messaging**
- Conversations between users
- Sample messages

### Creating the Demo Tenant

The demo tenant is automatically created when running with Docker:

```bash
# Enable demo tenant creation
CREATE_DEMO_TENANT=1 docker-compose up -d

# Or manually:
python manage.py bootstrap_demo_tenant

# Reset and recreate:
python manage.py bootstrap_demo_tenant --reset
```

### Demo Tenant Command Options

```bash
python manage.py bootstrap_demo_tenant [options]

Options:
  --reset            Delete existing demo tenant and recreate
  --dry-run          Preview what would be created
  --skip-marketplace Skip marketplace/services data
  --skip-messaging   Skip messaging/conversations data
```

---

## Getting Started

### Welcome to Your Tenant

When your Zumodra tenant is created, you receive:

- **Tenant URL:** `https://yourcompany.zumodra.com`
- **Admin Account:** The email provided during signup
- **Trial Period:** 60 days (beta) or 14 days (standard)

### First Login

1. Navigate to your tenant URL
2. Enter your credentials
3. Complete the welcome wizard
4. Set up two-factor authentication (recommended)

### Dashboard Overview

Your dashboard provides quick access to:

| Section | Purpose |
|---------|---------|
| **ATS** | Job postings, applications, candidates |
| **HR Core** | Employees, time-off, onboarding |
| **Marketplace** | Services, contracts, escrow |
| **Analytics** | Reports and metrics |
| **Settings** | Configuration and integrations |

---

## Initial Setup

### Step 1: Complete Company Profile

Navigate to **Settings > Company Profile**:

1. **Company Information**
   - Company name and logo
   - Industry and size
   - Website URL

2. **Address**
   - Primary office location
   - Additional locations (circusales)

3. **Contact Details**
   - Main contact email
   - Phone number

### Step 2: Configure Branding

Navigate to **Settings > Branding**:

```
Primary Color:    [Pick your brand color]
Secondary Color:  [Pick accent color]
Logo:            [Upload company logo]
Favicon:         [Upload favicon]
```

Your branding appears on:
- Career pages
- Email notifications
- Candidate portal
- Public profiles

### Step 3: Set Timezone & Locale

Navigate to **Settings > Localization**:

| Setting | Recommendation |
|---------|----------------|
| Timezone | Your primary office timezone |
| Date Format | Match your country standard |
| Currency | Your billing currency |
| Language | Primary team language |

---

## Team Management

### Invite Team Members

Navigate to **Settings > Team**:

1. Click **Invite User**
2. Enter email address
3. Select role
4. Assign to circusale (if applicable)
5. Send invitation

### Available Roles

| Role | Access Level |
|------|--------------|
| **Admin** | Full access to all features and settings |
| **HR Manager** | Employee management, time-off, reports |
| **Hiring Manager** | Job postings, applications, interviews |
| **Recruiter** | Candidates, applications, sourcing |
| **Employee** | Personal profile, time-off requests |
| **Viewer** | Read-only access to assigned areas |

### Role Permissions Matrix

```
Feature          Admin  HR Mgr  Hiring Mgr  Recruiter  Employee
─────────────────────────────────────────────────────────────────
Create Jobs        ✓      -         ✓           -          -
View Candidates    ✓      ✓         ✓           ✓          -
Schedule Intv.     ✓      ✓         ✓           ✓          -
Make Offers        ✓      -         ✓           -          -
Manage Employees   ✓      ✓         -           -          -
Approve Time-Off   ✓      ✓         -           -          -
View Analytics     ✓      ✓         ✓           -          -
Manage Settings    ✓      -         -           -          -
```

### Setting Up Circusales (Multi-Location)

If your company has multiple offices/locations:

1. Navigate to **Settings > Circusales**
2. Click **Add Circusale**
3. Enter details:
   - Name (e.g., "Montreal Office")
   - Address
   - Manager
   - Budget (optional)
4. Assign team members

---

## ATS Configuration

### Step 1: Create Recruitment Pipeline

Navigate to **ATS > Pipelines**:

Default stages (customize as needed):
1. **New** - Fresh applications
2. **Screening** - Initial review
3. **Phone Interview** - First contact
4. **Technical Interview** - Skills assessment
5. **Final Interview** - Team/culture fit
6. **Offer** - Offer extended
7. **Hired** - Successfully onboarded
8. **Rejected** - Not moving forward

### Step 2: Set Up Job Categories

Navigate to **ATS > Categories**:

Create categories matching your departments:
- Engineering
- Design
- Marketing
- Sales
- Operations
- HR

### Step 3: Configure Career Page

Navigate to **Settings > Career Page**:

1. **Page Content**
   - Title and description
   - Company culture section
   - Benefits and perks

2. **Design**
   - Apply your branding
   - Add hero image
   - Custom CSS (optional)

3. **SEO**
   - Meta title
   - Meta description
   - Social sharing image

### Step 4: Create Your First Job

Navigate to **ATS > Jobs > Create**:

```
Title:           [Job title]
Department:      [Select category]
Location:        [Select circusale]
Type:            [Full-time/Contract/Part-time]
Remote Policy:   [On-site/Hybrid/Remote]

Description:     [Detailed job description]
Requirements:    [Skills and qualifications]
Benefits:        [What you offer]

Salary Range:    [Min] - [Max] [Currency]
Show Salary:     [Yes/No]

Pipeline:        [Select pipeline]
```

### Step 5: Enable Application Form

Configure what information you collect:

**Required Fields:**
- Name
- Email
- Resume/CV

**Optional Fields:**
- Cover letter
- Phone number
- LinkedIn profile
- Portfolio URL
- Custom questions

---

## HR Core Setup

### Step 1: Configure Time-Off Types

Navigate to **HR > Time-Off Types**:

| Type | Default Days | Accrual |
|------|--------------|---------|
| PTO | 15 | Monthly |
| Sick Leave | 10 | Monthly |
| Personal Days | 3 | Annual |
| Parental Leave | 12 weeks | N/A |

### Step 2: Set Up Approval Workflow

Navigate to **HR > Workflows**:

1. **Time-Off Approval**
   - Manager approval required
   - HR notification on approval
   - Calendar sync

2. **Expense Approval**
   - Amount thresholds
   - Manager → Finance flow

### Step 3: Import Existing Employees

Option 1: **Manual Entry**
- Navigate to **HR > Employees > Add**
- Enter employee details

Option 2: **CSV Import**
- Download template
- Fill in employee data
- Upload and map fields

Required fields for import:
```csv
email,first_name,last_name,job_title,department,hire_date
john@company.com,John,Doe,Developer,Engineering,2024-01-15
```

---

## Marketplace Setup

### For Service Providers

Navigate to **Marketplace > My Services**:

1. **Create Service Listing**
   - Title and description
   - Category and skills
   - Pricing (hourly/fixed)
   - Delivery time

2. **Portfolio**
   - Add work samples
   - Link past projects
   - Upload documents

3. **Availability**
   - Set working hours
   - Block unavailable dates

### For Clients

Navigate to **Marketplace > Browse**:

1. Search for services
2. Review provider profiles
3. Request proposals
4. Compare and select
5. Fund escrow
6. Manage contract

### Escrow Workflow

```
1. Client accepts proposal
2. Client funds escrow (Stripe)
3. Provider delivers work
4. Client approves delivery
5. Funds released to provider
6. Both parties leave reviews
```

---

## Integrations

### Available Integrations

| Integration | Purpose | Setup |
|-------------|---------|-------|
| **Slack** | Notifications | OAuth |
| **Google Calendar** | Interview scheduling | OAuth |
| **Outlook** | Interview scheduling | OAuth |
| **Stripe** | Payments | API keys |

### Slack Integration

Navigate to **Settings > Integrations > Slack**:

1. Click **Connect to Slack**
2. Authorize Zumodra app
3. Select notification channels:
   - New applications → #recruiting
   - Interviews → #interviews
   - Offers → #hr-updates

### Calendar Integration

Navigate to **Settings > Integrations > Calendar**:

1. Choose provider (Google/Outlook)
2. Authorize access
3. Select calendars to sync
4. Configure availability

---

## Best Practices

### Getting the Most from Zumodra

#### For Recruiting

- **Use AI Matching:** Enable AI candidate scoring for faster screening
- **Template Responses:** Create email templates for common communications
- **Pipeline Discipline:** Move candidates through stages promptly
- **Feedback Loop:** Log interview feedback immediately

#### For HR

- **Onboarding Checklists:** Create standardized onboarding tasks
- **Regular Reviews:** Schedule performance check-ins
- **Self-Service:** Enable employee self-service for common requests
- **Analytics:** Review reports monthly

#### For Marketplace

- **Complete Profiles:** Detailed profiles attract better matches
- **Clear Contracts:** Define deliverables before starting
- **Regular Updates:** Communicate progress with clients
- **Prompt Delivery:** Meet deadlines to build reputation

### Security Recommendations

1. **Enable 2FA** for all admin accounts
2. **Review access** quarterly
3. **Use SSO** if available (Enterprise plan)
4. **Audit logs** regularly (Enterprise plan)

---

## Getting Help

### Documentation

- **User Guide:** https://docs.zumodra.com/user-guide
- **API Docs:** https://api.zumodra.com/docs
- **FAQ:** https://zumodra.com/faq

### Support Channels

| Plan | Support |
|------|---------|
| Starter | Email (48h response) |
| Professional | Email + Chat (24h response) |
| Enterprise | Priority + Dedicated CSM |

### Contact

- **General Support:** support@zumodra.com
- **Beta Feedback:** beta@zumodra.com
- **Sales:** sales@zumodra.com
- **Security Issues:** security@zumodra.com

### Community

- **Slack Community:** zumodra.slack.com (invite required)
- **Knowledge Base:** help.zumodra.com
- **Feature Requests:** feedback.zumodra.com

---

## Quick Reference

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl/Cmd + K` | Quick search |
| `Ctrl/Cmd + N` | New item (context-aware) |
| `Ctrl/Cmd + S` | Save current form |
| `Esc` | Close modal/panel |
| `?` | Show shortcuts |

### Status Definitions

**Applications:**
- `New` - Unreviewed
- `In Review` - Being evaluated
- `Shortlisted` - Advancing
- `Rejected` - Not moving forward
- `Hired` - Accepted offer

**Contracts:**
- `Draft` - Not yet active
- `Pending Funding` - Awaiting escrow
- `Active` - Work in progress
- `Completed` - Successfully finished
- `Disputed` - Under review

### Glossary

| Term | Definition |
|------|------------|
| **Circusale** | Business location or branch |
| **Pipeline** | Recruitment workflow stages |
| **Escrow** | Secure payment holding |
| **KYC** | Identity verification |
| **Trust Score** | User reliability rating |

---

## Checklist: First Week

- [ ] Complete company profile
- [ ] Set up branding
- [ ] Invite core team members
- [ ] Create first pipeline
- [ ] Add job categories
- [ ] Configure career page
- [ ] Post first job
- [ ] Import employees (if applicable)
- [ ] Connect calendar integration
- [ ] Set up Slack notifications
- [ ] Review security settings
- [ ] Enable 2FA for admins

---

**Need personalized onboarding?** Contact your Customer Success Manager or email onboarding@zumodra.com.

**Document maintained by:** Customer Success Team
**Last Updated:** December 2025
