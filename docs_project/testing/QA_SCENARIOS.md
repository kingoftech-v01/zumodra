# Zumodra QA Test Scenarios

**Version:** 1.0.0
**Last Updated:** December 2025

This document defines end-to-end QA scenarios for critical business flows. Each scenario includes automated test references and manual verification checklists.

---

## Table of Contents

1. [ATS Hiring Flow](#1-ats-hiring-flow)
2. [Marketplace Mission with Escrow](#2-marketplace-mission-with-escrow)
3. [Co-op Term Lifecycle](#3-co-op-term-lifecycle)
4. [Candidate Multi-CV Usage](#4-candidate-multi-cv-usage)
5. [KYC Verification Flow](#5-kyc-verification-flow)
6. [Trust Score Progression](#6-trust-score-progression)

---

## 1. ATS Hiring Flow

**Scenario:** Complete hiring process from job posting to candidate hire.

### Automated Tests

```bash
# Run ATS flow tests
pytest tests/test_ats_flows.py -v

# Run specific scenario
pytest tests/test_ats_flows.py::TestCompleteHiringFlow -v
```

### Test Data Setup

```python
# Create test data
python manage.py shell
>>> from conftest import *
>>> plan = PlanFactory()
>>> tenant = TenantFactory(plan=plan)
>>> hiring_manager = UserFactory()
>>> TenantUserFactory(user=hiring_manager, tenant=tenant, role='hiring_manager')
```

### Steps

| Step | Action | Expected Result | Test Reference |
|------|--------|-----------------|----------------|
| 1 | Create job posting | Job saved with status 'draft' | `test_create_job_posting` |
| 2 | Add job details (description, salary, requirements) | All fields saved correctly | `test_job_posting_salary_range` |
| 3 | Publish job | Status changes to 'open', published_at set | `test_job_posting_publish` |
| 4 | Candidate submits application | Application created, status 'new' | `test_submit_application` |
| 5 | Hiring manager receives notification | Email/in-app notification sent | `test_application_received_notification` |
| 6 | Move application to screening stage | Stage updated, activity logged | `test_move_application_through_stages` |
| 7 | Schedule interview | Interview created, candidate notified | `test_schedule_interview` |
| 8 | Complete interview, add feedback | Feedback saved with ratings | `test_interview_feedback` |
| 9 | Create offer | Offer draft created | `test_create_offer` |
| 10 | Send offer to candidate | Offer status 'sent', candidate notified | `test_send_offer` |
| 11 | Candidate accepts offer | Status 'accepted', hiring team notified | `test_accept_offer` |
| 12 | Move to hired stage | Application status 'hired' | `test_full_hiring_flow` |

### Manual Verification Checklist

- [ ] Job appears on public careers page after publishing
- [ ] Application form validates required fields
- [ ] Email notifications are properly formatted
- [ ] Interview calendar integration works (if configured)
- [ ] Offer letter PDF generates correctly
- [ ] All pipeline stages are tracked in activity log
- [ ] Rejection flow sends appropriate notification
- [ ] Metrics update on dashboard (applications, time-to-hire)

---

## 2. Marketplace Mission with Escrow

**Scenario:** Complete service contract from proposal to payout.

### Automated Tests

```bash
# Run marketplace flow tests
pytest tests/test_marketplace_flows.py -v

# Run complete flow
pytest tests/test_marketplace_flows.py::TestCompleteMarketplaceFlow -v
```

### Steps

| Step | Action | Expected Result | Test Reference |
|------|--------|-----------------|----------------|
| 1 | Provider creates service listing | Service active, visible in search | `test_create_service_listing` |
| 2 | Client views service and requests proposal | Proposal request sent | - |
| 3 | Provider sends proposal | Proposal status 'pending' | `test_create_proposal` |
| 4 | Client accepts proposal | Status 'accepted', contract created | `test_accept_proposal` |
| 5 | Contract created from proposal | Contract status 'pending_funding' | `test_create_contract_from_proposal` |
| 6 | Client funds escrow | EscrowTransaction 'completed', contract 'active' | `test_fund_contract_escrow` |
| 7 | Provider delivers work | Contract status 'pending_approval' | - |
| 8 | Client approves delivery | Contract 'completed' | - |
| 9 | Escrow released to provider | Release transaction created | `test_release_escrow_on_completion` |
| 10 | Both parties leave reviews | Reviews saved, trust scores updated | `test_client_leaves_review` |

### Milestone-Based Contract

| Step | Action | Expected Result | Test Reference |
|------|--------|-----------------|----------------|
| 1 | Create contract with milestones | Multiple milestones saved | `test_contract_milestone_completion` |
| 2 | Complete milestone 1 | Status 'completed', partial release | `test_partial_release_for_milestone` |
| 3 | Complete remaining milestones | Each triggers partial release | - |
| 4 | Final milestone + completion | Full contract completed | - |

### Dispute Flow

| Step | Action | Expected Result | Test Reference |
|------|--------|-----------------|----------------|
| 1 | Client files dispute | Dispute 'open', contract 'disputed' | `test_file_dispute` |
| 2 | Both parties provide evidence | Evidence attached to dispute | - |
| 3 | Admin resolves dispute | Resolution recorded | `test_resolve_dispute_in_client_favor` |
| 4 | Funds distributed per resolution | Refund/release as specified | `test_resolve_dispute_with_partial_payment` |

### Manual Verification Checklist

- [ ] Service listing appears in search with correct filters
- [ ] Proposal pricing displays correctly with currency
- [ ] Stripe payment flow completes successfully
- [ ] Escrow balance displays correctly in dashboard
- [ ] Email notifications sent at each stage
- [ ] Contract documents accessible to both parties
- [ ] Dispute evidence upload works (images, files)
- [ ] Provider earnings appear in finance dashboard
- [ ] Platform fees deducted correctly
- [ ] Reviews display on provider profile

---

## 3. Co-op Term Lifecycle

**Scenario:** Complete co-op/internship term from posting to completion.

### Automated Tests

```bash
# Run co-op related tests (part of ATS tests)
pytest tests/test_ats_flows.py -v -k "coop or intern"
```

### Steps

| Step | Action | Expected Result | Test Reference |
|------|--------|-----------------|----------------|
| 1 | Employer creates co-op posting | Job with type 'coop' created | - |
| 2 | School coordinator reviews posting | Posting appears in coordinator dashboard | - |
| 3 | Coordinator approves posting | Posting visible to students | - |
| 4 | Student views on student dashboard | Active term shows available opportunities | - |
| 5 | Student applies with CV | Application linked to student profile | - |
| 6 | Employer reviews, interviews, offers | Standard ATS flow | `TestCompleteHiringFlow` |
| 7 | Student accepts, term starts | CoopTerm created with start date | - |
| 8 | Mid-term evaluation | Evaluation form submitted | - |
| 9 | Final evaluation | Completion status updated | - |
| 10 | Term ends, appears in history | Past term in student dashboard | - |

### Role-Based Access

| Role | Can View | Can Edit | Can Approve |
|------|----------|----------|-------------|
| Student | Own applications, terms | Own profile, CVs | - |
| Employer | Own postings, applicants | Own postings, offers | - |
| Coordinator | All postings, students | Approval status | Postings, terms |

### Manual Verification Checklist

- [ ] Student dashboard shows active/upcoming/past terms correctly
- [ ] Employer dashboard shows applicants with filters
- [ ] Coordinator sees pending approvals prominently
- [ ] Evaluation forms save and display correctly
- [ ] Term dates validate (end after start)
- [ ] Credit/hour requirements tracked
- [ ] School-specific requirements enforced
- [ ] Reports export correctly (CSV, PDF)

---

## 4. Candidate Multi-CV Usage

**Scenario:** Candidate manages multiple CVs and uses them in applications.

### Automated Tests

```bash
# Run CV-related tests
pytest tests/test_verification_flows.py -v -k "cv"
pytest tests/test_ats_flows.py -v -k "application"
```

### Steps

| Step | Action | Expected Result | Test Reference |
|------|--------|-----------------|----------------|
| 1 | Candidate creates first CV | CV saved as primary | - |
| 2 | Add experience entries | Experience linked to CV | - |
| 3 | Add education entries | Education linked to CV | - |
| 4 | Add skills | Skills linked to CV | - |
| 5 | Create second CV (different focus) | Second CV created, not primary | - |
| 6 | Request AI analysis | AI score calculated, feedback generated | - |
| 7 | Apply to job, select CV | Application uses selected CV | - |
| 8 | System suggests best CV match | Recommendation shown | - |
| 9 | View CV usage stats | Interview rate, use count shown | - |
| 10 | Set different CV as primary | Primary flag updated | - |

### CV Coaching Features

| Feature | Input | Output |
|---------|-------|--------|
| AI Score | CV content | 0-100 score |
| ATS Compatibility | CV structure | Compatibility percentage |
| Keyword Analysis | CV + job description | Missing/matching keywords |
| Structure Feedback | CV sections | Section-by-section recommendations |

### Manual Verification Checklist

- [ ] CV creation form validates required fields
- [ ] Experience/education entries sort chronologically
- [ ] Skills display as tags with categories
- [ ] Duplicate CV action works correctly
- [ ] Delete CV warns if it's primary
- [ ] AI analysis completes within reasonable time
- [ ] Feedback displays in readable format
- [ ] CV selector in application form works
- [ ] Best match recommendation shows correct CV
- [ ] Usage statistics update after applications

---

## 5. KYC Verification Flow

**Scenario:** User completes identity verification and achieves verified status.

### Automated Tests

```bash
# Run verification tests
pytest tests/test_verification_flows.py -v
pytest tests/test_verification_flows.py::TestKYCVerification -v
```

### Steps

| Step | Action | Expected Result | Test Reference |
|------|--------|-----------------|----------------|
| 1 | User initiates KYC | Verification request created | `test_create_kyc_verification_request` |
| 2 | Select document type | Document type saved | - |
| 3 | Upload document images | Images stored securely | - |
| 4 | Submit for verification | Status 'submitted' | `test_kyc_verification_submission` |
| 5 | System processes (mock/real) | Status 'processing' | - |
| 6a | Verification approved | Status 'verified', score set | `test_kyc_verification_approved` |
| 6b | Verification rejected | Status 'rejected', reason provided | `test_kyc_verification_rejected` |
| 7 | Trust score updates | Identity score reflects verification | `test_trust_score_update_on_verification` |

### Document Types

| Type | Accepted Formats | Countries |
|------|------------------|-----------|
| Passport | Image (JPG, PNG) | All |
| Driver's License | Image (JPG, PNG) | CA, US, UK, EU |
| National ID | Image (JPG, PNG) | Country-specific |
| Utility Bill (address) | Image, PDF | All |

### Manual Verification Checklist

- [ ] Document upload accepts valid formats only
- [ ] File size limits enforced (5MB per image)
- [ ] Preview shows uploaded documents
- [ ] Progress indicator during processing
- [ ] Rejection reason clearly displayed
- [ ] Retry option available after rejection
- [ ] Verification badge appears after approval
- [ ] Expiration date tracked (1 year default)
- [ ] Renewal notification before expiry
- [ ] Audit log records all verification attempts

---

## 6. Trust Score Progression

**Scenario:** User progresses through trust levels from NEW to PREMIUM.

### Automated Tests

```bash
# Run trust score tests
pytest tests/test_verification_flows.py::TestTrustScore -v
```

### Trust Levels

| Level | Score Range | Requirements |
|-------|-------------|--------------|
| NEW | 0-20 | Account created |
| BASIC | 20-40 | Email verified, profile complete |
| VERIFIED | 40-60 | KYC completed |
| HIGH | 60-80 | Employment/education verified |
| PREMIUM | 80-100 | Multiple verifications + positive history |

### Score Components

| Component | Weight | Factors |
|-----------|--------|---------|
| Identity | 20% | KYC verification status |
| Career | 20% | Employment + education verification |
| Activity | 15% | Platform usage, engagement |
| Reviews | 20% | Average review rating |
| Disputes | 15% | Dispute history (lower = better) |
| Payments | 10% | Payment reliability |

### Progression Steps

| Step | Action | Score Impact | Test Reference |
|------|--------|--------------|----------------|
| 1 | Create account | +5 (NEW) | - |
| 2 | Verify email | +5 | - |
| 3 | Complete profile | +10 | - |
| 4 | Complete KYC | +20-25 | `test_trust_score_update_on_verification` |
| 5 | Verify employment | +10-15 | `test_career_verification_with_trust_update` |
| 6 | Verify education | +5-10 | - |
| 7 | Complete first contract | +5 | - |
| 8 | Receive positive review | +3-5 per review | - |
| 9 | Maintain clean record | +1/month | - |

### Manual Verification Checklist

- [ ] Trust badge displays correct level
- [ ] Score breakdown accessible to user
- [ ] Level progression triggers notification
- [ ] Badge appears on public profiles
- [ ] Employers can filter by trust level
- [ ] Score recalculates on verification changes
- [ ] Dispute negatively impacts score
- [ ] Recovery path after score drops
- [ ] Premium benefits documented and applied

---

## Running All Scenarios

### Full Test Suite

```bash
# Run all QA-related tests
pytest tests/ -v --tb=short

# Run with coverage report
pytest tests/ --cov=. --cov-report=html

# Run specific scenario categories
pytest -m workflow -v      # End-to-end workflows
pytest -m integration -v   # Integration tests
```

### Test Environment Setup

```bash
# Start test environment
docker compose -f docker-compose.dev.yml up -d

# Load test fixtures
python manage.py loaddata fixtures/qa_test_data.json

# Run tests against test database
DJANGO_SETTINGS_MODULE=zumodra.settings_test pytest
```

### Smoke Tests (Quick Validation)

```bash
# Basic health checks
curl http://localhost:8000/health/
curl http://localhost:8000/health/ready/

# API authentication test
curl -X POST http://localhost:8000/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "testpass123"}'
```

---

## Reporting

### Test Results

After running tests, check:

1. **Console output** - Summary of passed/failed tests
2. **Coverage report** - `htmlcov/index.html`
3. **JUnit XML** - `pytest --junitxml=results.xml` for CI integration

### Issue Tracking

When tests fail:

1. Note the test name and error message
2. Check the test file for expected behavior
3. Reproduce manually if needed
4. Create issue with:
   - Steps to reproduce
   - Expected vs actual result
   - Test output/screenshots
   - Environment details

---

**Document maintained by:** QA Team
**Review frequency:** Monthly or after major releases
