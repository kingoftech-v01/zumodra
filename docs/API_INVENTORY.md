# API Endpoint Inventory for Zumodra Platform

**Date:** January 16, 2026
**Auditor:** Backend Developer - API Endpoints Role
**Status:** ✅ Complete

---

## Executive Summary

**Total Endpoints:** 200+ REST API endpoints
**Total ViewSets:** 65+
**Base URL:** `/api/v1/`
**Authentication:** JWT tokens via djangorestframework-simplejwt
**Response Format:** Standardized JSON with metadata and pagination
**Multi-Tenancy:** Schema-based isolation via django-tenants

---

## 1. ATS (Applicant Tracking System) - 50+ Endpoints

**Base URL:** `/api/v1/ats/`
**URL Namespace:** `api:v1:ats:*`
**Files:** [ats/urls.py](../ats/urls.py), [ats/views.py](../ats/views.py), [ats/serializers.py](../ats/serializers.py)

### Core Resources

#### Job Categories
- `GET /api/v1/ats/job-categories/` - List all categories
- `POST /api/v1/ats/job-categories/` - Create category
- `GET /api/v1/ats/job-categories/{id}/` - Retrieve category
- `PUT/PATCH /api/v1/ats/job-categories/{id}/` - Update category
- `DELETE /api/v1/ats/job-categories/{id}/` - Delete category

#### Pipelines
- `GET /api/v1/ats/pipelines/` - List all pipelines
- `POST /api/v1/ats/pipelines/` - Create pipeline
- `GET /api/v1/ats/pipelines/{id}/` - Retrieve pipeline
- `PUT/PATCH /api/v1/ats/pipelines/{id}/` - Update pipeline
- `DELETE /api/v1/ats/pipelines/{id}/` - Delete pipeline
- `POST /api/v1/ats/pipelines/{id}/add_stage/` - Add stage to pipeline
- `POST /api/v1/ats/pipelines/{id}/reorder_stages/` - Reorder stages
- `POST /api/v1/ats/pipelines/{id}/set_default/` - Set as default pipeline

#### Job Postings
- `GET /api/v1/ats/jobs/` - List all jobs
- `POST /api/v1/ats/jobs/` - Create job
- `GET /api/v1/ats/jobs/{id}/` - Retrieve job
- `PUT/PATCH /api/v1/ats/jobs/{id}/` - Update job
- `DELETE /api/v1/ats/jobs/{id}/` - Delete job
- `POST /api/v1/ats/jobs/{id}/publish/` - Publish job
- `POST /api/v1/ats/jobs/{id}/close/` - Close job
- `POST /api/v1/ats/jobs/{id}/clone/` - Duplicate job
- `GET /api/v1/ats/jobs/{id}/applications/` - Get applications for job
- `GET /api/v1/ats/jobs/{id}/kanban/` - Get Kanban board data
- `GET /api/v1/ats/jobs/{id}/stats/` - Get job statistics

#### Candidates
- `GET /api/v1/ats/candidates/` - List all candidates
- `POST /api/v1/ats/candidates/` - Create candidate
- `GET /api/v1/ats/candidates/{id}/` - Retrieve candidate
- `PUT/PATCH /api/v1/ats/candidates/{id}/` - Update candidate
- `DELETE /api/v1/ats/candidates/{id}/` - Delete candidate
- `POST /api/v1/ats/candidates/bulk_import/` - Bulk import candidates (CSV)
- `POST /api/v1/ats/candidates/{id}/merge/` - Merge duplicate candidates
- `POST /api/v1/ats/candidates/{id}/add_tag/` - Add tag to candidate
- `POST /api/v1/ats/candidates/{id}/remove_tag/` - Remove tag from candidate

#### Applications
- `GET /api/v1/ats/applications/` - List all applications
- `POST /api/v1/ats/applications/` - Create application
- `GET /api/v1/ats/applications/{id}/` - Retrieve application
- `PUT/PATCH /api/v1/ats/applications/{id}/` - Update application
- `DELETE /api/v1/ats/applications/{id}/` - Delete application
- `POST /api/v1/ats/applications/{id}/move_stage/` - Move to different stage
- `POST /api/v1/ats/applications/{id}/reject/` - Reject application
- `POST /api/v1/ats/applications/{id}/advance/` - Advance to next stage
- `POST /api/v1/ats/applications/{id}/assign/` - Assign to recruiter
- `POST /api/v1/ats/applications/{id}/rate/` - Add rating
- `GET /api/v1/ats/applications/{id}/notes/` - Get application notes

#### Interviews
- `GET /api/v1/ats/interviews/` - List all interviews
- `POST /api/v1/ats/interviews/` - Schedule interview
- `GET /api/v1/ats/interviews/{id}/` - Retrieve interview
- `PUT/PATCH /api/v1/ats/interviews/{id}/` - Update interview
- `DELETE /api/v1/ats/interviews/{id}/` - Delete interview
- `POST /api/v1/ats/interviews/{id}/reschedule/` - Reschedule interview
- `POST /api/v1/ats/interviews/{id}/complete/` - Mark as complete
- `POST /api/v1/ats/interviews/{id}/cancel/` - Cancel interview
- `POST /api/v1/ats/interviews/{id}/feedback/` - Submit feedback

#### Offers
- `GET /api/v1/ats/offers/` - List all offers
- `POST /api/v1/ats/offers/` - Create offer
- `GET /api/v1/ats/offers/{id}/` - Retrieve offer
- `PUT/PATCH /api/v1/ats/offers/{id}/` - Update offer
- `DELETE /api/v1/ats/offers/{id}/` - Delete offer
- `POST /api/v1/ats/offers/{id}/send/` - Send offer to candidate
- `POST /api/v1/ats/offers/{id}/accept/` - Accept offer (candidate)
- `POST /api/v1/ats/offers/{id}/decline/` - Decline offer (candidate)
- `POST /api/v1/ats/offers/{id}/approve/` - Approve offer (manager)
- `POST /api/v1/ats/offers/{id}/withdraw/` - Withdraw offer

**Permissions:** IsAuthenticated, IsTenantUser (RecruiterViewSet base)
**Pagination:** StandardPagination (20/page default)

---

## 2. HR Core - 50+ Endpoints

**Base URL:** `/api/v1/hr/`
**URL Namespace:** `api:v1:hr:*`
**Files:** [hr_core/urls.py](../hr_core/urls.py), [hr_core/views.py](../hr_core/views.py)

### Core Resources

#### Employees
- `GET /api/v1/hr/employees/` - List all employees
- `POST /api/v1/hr/employees/` - Create employee
- `GET /api/v1/hr/employees/{id}/` - Retrieve employee
- `PUT/PATCH /api/v1/hr/employees/{id}/` - Update employee
- `DELETE /api/v1/hr/employees/{id}/` - Delete employee
- `GET /api/v1/hr/employees/me/` - Get current user's employee record
- `GET /api/v1/hr/employees/{id}/direct_reports/` - Get direct reports
- `POST /api/v1/hr/employees/{id}/terminate/` - Terminate employment

#### Time-Off Management
- `GET /api/v1/hr/time-off-types/` - List time-off types
- `POST /api/v1/hr/time-off-types/` - Create time-off type (admin)
- `GET /api/v1/hr/time-off-requests/` - List all requests
- `POST /api/v1/hr/time-off-requests/` - Create request
- `GET /api/v1/hr/time-off-requests/{id}/` - Retrieve request
- `PUT/PATCH /api/v1/hr/time-off-requests/{id}/` - Update request
- `DELETE /api/v1/hr/time-off-requests/{id}/` - Delete request
- `GET /api/v1/hr/time-off-requests/my_requests/` - My requests
- `GET /api/v1/hr/time-off-requests/pending_approval/` - Pending approval
- `GET /api/v1/hr/time-off-requests/{id}/balance/` - Get balance
- `POST /api/v1/hr/time-off-requests/{id}/approve/` - Approve request
- `POST /api/v1/hr/time-off-requests/{id}/reject/` - Reject request
- `POST /api/v1/hr/time-off-requests/{id}/cancel/` - Cancel request

#### Onboarding
- `GET /api/v1/hr/onboarding-checklists/` - List checklists
- `POST /api/v1/hr/onboarding-checklists/` - Create checklist
- `POST /api/v1/hr/onboarding-checklists/{id}/add_task/` - Add task
- `GET /api/v1/hr/employee-onboardings/` - List onboarding records
- `GET /api/v1/hr/employee-onboardings/{id}/progress/` - Get progress
- `POST /api/v1/hr/employee-onboardings/{id}/complete_task/` - Complete task

#### Documents
- `GET /api/v1/hr/document-templates/` - List templates
- `POST /api/v1/hr/document-templates/{id}/generate_for_employee/` - Generate document
- `GET /api/v1/hr/employee-documents/` - List documents
- `GET /api/v1/hr/employee-documents/my_documents/` - My documents
- `GET /api/v1/hr/employee-documents/pending_signatures/` - Pending signatures
- `POST /api/v1/hr/employee-documents/{id}/sign/` - Sign document
- `POST /api/v1/hr/employee-documents/{id}/request_signature/` - Request signature
- `POST /api/v1/hr/employee-documents/{id}/archive/` - Archive document

#### Performance Reviews
- `GET /api/v1/hr/performance-reviews/` - List reviews
- `POST /api/v1/hr/performance-reviews/` - Create review
- `GET /api/v1/hr/performance-reviews/my_reviews/` - My reviews
- `GET /api/v1/hr/performance-reviews/pending_my_action/` - Pending action
- `POST /api/v1/hr/performance-reviews/{id}/submit/` - Submit review
- `POST /api/v1/hr/performance-reviews/{id}/complete/` - Complete review
- `POST /api/v1/hr/performance-reviews/{id}/approve/` - Approve review
- `POST /api/v1/hr/performance-reviews/{id}/send_back/` - Send back for revision

#### Special Endpoints
- `GET /api/v1/hr/org-chart/` - Get organization chart
- `GET /api/v1/hr/team-calendar/` - Get team calendar
- `GET /api/v1/hr/dashboard/stats/` - Get dashboard statistics
- `GET /api/v1/hr/reports/` - Generate reports

**Permissions:** IsAuthenticated, varies by endpoint (HR/Manager specific)
**Pagination:** StandardPagination

---

## 3. Accounts - 45+ Endpoints

**Base URL:** `/api/v1/accounts/`
**URL Namespace:** `api:v1:accounts:*`
**Files:** [accounts/urls.py](../accounts/urls.py), [accounts/views.py](../accounts/views.py)

### Authentication Endpoints
- `POST /api/v1/auth/register/` - Create account
- `POST /api/v1/auth/login/` - Authenticate user
- `POST /api/v1/auth/logout/` - Logout user
- `POST /api/v1/auth/token/` - Get JWT token
- `POST /api/v1/auth/token/refresh/` - Refresh token
- `POST /api/v1/auth/token/verify/` - Verify token

### User Management
- `GET /api/v1/accounts/users/` - List tenant users
- `POST /api/v1/accounts/users/` - Create user
- `GET /api/v1/accounts/users/{id}/` - Retrieve user
- `PUT/PATCH /api/v1/accounts/users/{id}/` - Update user
- `DELETE /api/v1/accounts/users/{id}/` - Delete user
- `POST /api/v1/accounts/users/{id}/deactivate/` - Deactivate user
- `POST /api/v1/accounts/users/{id}/reactivate/` - Reactivate user
- `POST /api/v1/accounts/users/{id}/update_role/` - Update user role

### Profiles & Verification
- `GET /api/v1/accounts/profiles/` - List profiles
- `GET /api/v1/accounts/profiles/me/` - Get my profile
- `PUT/PATCH /api/v1/accounts/profiles/me/` - Update my profile
- `GET /api/v1/accounts/kyc/` - List KYC verifications
- `POST /api/v1/accounts/kyc/` - Submit KYC
- `GET /api/v1/accounts/kyc/my_status/` - Get my KYC status
- `POST /api/v1/accounts/kyc/{id}/verify/` - Verify KYC (admin)
- `POST /api/v1/accounts/kyc/{id}/reject/` - Reject KYC (admin)

### Trust & Reviews
- `GET /api/v1/accounts/trust-scores/` - Get trust scores
- `POST /api/v1/accounts/trust-scores/{id}/recalculate/` - Recalculate score
- `GET /api/v1/accounts/reviews/` - List reviews
- `POST /api/v1/accounts/reviews/` - Create review
- `GET /api/v1/accounts/reviews/for_user/` - Reviews for specific user
- `GET /api/v1/accounts/reviews/given/` - Reviews I gave
- `GET /api/v1/accounts/reviews/received/` - Reviews I received
- `POST /api/v1/accounts/reviews/{id}/dispute/` - Dispute review
- `POST /api/v1/accounts/reviews/{id}/respond/` - Respond to review

### CVs & Candidate Profiles
- `GET /api/v1/accounts/cvs/` - List CVs
- `POST /api/v1/accounts/cvs/` - Upload CV
- `GET /api/v1/accounts/cvs/{id}/` - Retrieve CV
- `POST /api/v1/accounts/cvs/{id}/set_primary/` - Set as primary CV
- `GET /api/v1/accounts/cvs/primary/` - Get primary CV
- `GET /api/v1/accounts/cvs/best_match/` - Get best matching CV

### Privacy & Consent
- `GET /api/v1/accounts/consents/` - List consents
- `POST /api/v1/accounts/consents/request_consent/` - Request consent
- `POST /api/v1/accounts/consents/{id}/respond/` - Respond to consent
- `POST /api/v1/accounts/consents/{id}/revoke/` - Revoke consent
- `GET /api/v1/accounts/consents/pending/` - Pending consents
- `GET /api/v1/accounts/consents/granted/` - Granted consents

**Permissions:** IsAuthenticated, varies by endpoint
**Pagination:** StandardPagination

---

## 4. Finance - 30+ Endpoints

**Base URL:** `/api/v1/finance/`
**URL Namespace:** `api:v1:finance:*`
**Files:** [finance/api/viewsets.py](../finance/api/viewsets.py), [finance/api/urls.py](../finance/api/urls.py)

### Payments & Subscriptions
- `GET /api/v1/finance/transactions/` - List transactions
- `POST /api/v1/finance/transactions/` - Create transaction (admin)
- `GET /api/v1/finance/transactions/{id}/` - Retrieve transaction
- `GET /api/v1/finance/subscription-plans/` - List plans (read-only)
- `GET /api/v1/finance/subscriptions/` - List user subscriptions
- `POST /api/v1/finance/subscriptions/` - Create subscription
- `POST /api/v1/finance/subscriptions/{id}/cancel/` - Cancel subscription
- `POST /api/v1/finance/subscriptions/{id}/reactivate/` - Reactivate
- `POST /api/v1/finance/subscriptions/{id}/upgrade/` - Upgrade plan
- `POST /api/v1/finance/subscriptions/{id}/downgrade/` - Downgrade plan

### Invoices
- `GET /api/v1/finance/invoices/` - List invoices
- `POST /api/v1/finance/invoices/` - Create invoice
- `GET /api/v1/finance/invoices/{id}/` - Retrieve invoice
- `POST /api/v1/finance/invoices/{id}/pay/` - Pay invoice
- `GET /api/v1/finance/invoices/{id}/download/` - Download PDF

### Payment Methods
- `GET /api/v1/finance/payment-methods/` - List payment methods
- `POST /api/v1/finance/payment-methods/` - Add payment method
- `DELETE /api/v1/finance/payment-methods/{id}/` - Remove method
- `POST /api/v1/finance/payment-methods/{id}/set_default/` - Set as default

### Escrow & Disputes
- `GET /api/v1/finance/escrow/` - List escrow transactions
- `POST /api/v1/finance/escrow/` - Create escrow
- `POST /api/v1/finance/escrow/{id}/fund/` - Fund escrow
- `POST /api/v1/finance/escrow/{id}/release/` - Release funds
- `POST /api/v1/finance/escrow/{id}/dispute/` - Create dispute
- `POST /api/v1/finance/escrow/{id}/refund/` - Refund transaction
- `GET /api/v1/finance/disputes/` - List disputes
- `POST /api/v1/finance/disputes/{id}/respond/` - Respond to dispute
- `POST /api/v1/finance/disputes/{id}/resolve/` - Resolve dispute (admin)

### Refunds
- `GET /api/v1/finance/refunds/` - List refund requests
- `POST /api/v1/finance/refunds/` - Request refund
- `POST /api/v1/finance/refunds/{id}/approve/` - Approve refund (admin)
- `POST /api/v1/finance/refunds/{id}/reject/` - Reject refund (admin)

**Permissions:** IsAuthenticated, varies by endpoint
**Base Classes:** SecureTenantViewSet, ParticipantViewSet

---

## 5. Services (Marketplace) - 40+ Endpoints

**Base URL:** `/api/v1/services/`
**URL Namespace:** `api:v1:services:*`
**Files:** [services/api/viewsets.py](../services/api/viewsets.py), [services/api/urls.py](../services/api/urls.py)

### Service Management
- `GET /api/v1/services/categories/` - List categories (read-only)
- `GET /api/v1/services/tags/` - List tags (read-only)
- `GET /api/v1/services/providers/` - List providers
- `POST /api/v1/services/providers/` - Create provider profile
- `GET /api/v1/services/providers/{id}/services/` - Get provider services
- `GET /api/v1/services/providers/{id}/reviews/` - Get provider reviews
- `POST /api/v1/services/providers/{id}/verify/` - Verify provider (admin)

### Service Listings
- `GET /api/v1/services/services/` - List services
- `POST /api/v1/services/services/` - Create service
- `GET /api/v1/services/services/{id}/` - Retrieve service
- `PUT/PATCH /api/v1/services/services/{id}/` - Update service
- `DELETE /api/v1/services/services/{id}/` - Delete service
- `GET /api/v1/services/services/{id}/comments/` - Get comments
- `POST /api/v1/services/services/{id}/like/` - Like service
- `POST /api/v1/services/services/{id}/feature/` - Feature service (admin)

### Client Requests & Proposals
- `GET /api/v1/services/requests/` - List client requests
- `POST /api/v1/services/requests/` - Create request
- `GET /api/v1/services/requests/{id}/proposals/` - Get proposals for request
- `GET /api/v1/services/requests/{id}/matches/` - AI matches (not implemented)
- `GET /api/v1/services/proposals/` - List proposals
- `POST /api/v1/services/proposals/` - Submit proposal
- `POST /api/v1/services/proposals/{id}/accept/` - Accept proposal
- `POST /api/v1/services/proposals/{id}/reject/` - Reject proposal
- `POST /api/v1/services/proposals/{id}/counter/` - Counter offer (not implemented)

### Contracts
- `GET /api/v1/services/contracts/` - List contracts
- `POST /api/v1/services/contracts/` - Create contract
- `GET /api/v1/services/contracts/{id}/` - Retrieve contract
- `POST /api/v1/services/contracts/{id}/start/` - Start contract
- `POST /api/v1/services/contracts/{id}/complete/` - Complete contract
- `POST /api/v1/services/contracts/{id}/cancel/` - Cancel contract
- `POST /api/v1/services/contracts/{id}/update_status/` - Update status
- `GET /api/v1/services/contracts/{id}/messages/` - Get contract messages

### Reviews & Analytics
- `GET /api/v1/services/reviews/` - List service reviews
- `POST /api/v1/services/reviews/` - Create review
- `POST /api/v1/services/reviews/{id}/respond/` - Respond to review
- `POST /api/v1/services/reviews/{id}/report/` - Report review
- `GET /api/v1/services/analytics/` - Marketplace analytics

**Permissions:** IsAuthenticated, IsTenantUser, varies by role
**Base Classes:** SecureTenantViewSet, ParticipantViewSet

---

## 6. Notifications - 20+ Endpoints

**Base URL:** `/api/v1/notifications/`
**URL Namespace:** `api:v1:notifications:*`
**Files:** [notifications/urls.py](../notifications/urls.py), [notifications/views.py](../notifications/views.py)

### Notification Management
- `GET /api/v1/notifications/` - List notifications
- `GET /api/v1/notifications/{id}/` - Retrieve notification
- `POST /api/v1/notifications/{id}/read/` - Mark as read
- `POST /api/v1/notifications/read-all/` - Mark all as read
- `POST /api/v1/notifications/bulk/` - Bulk operations (admin)
- `GET /api/v1/notifications/unsubscribe/` - Unsubscribe (public)

### Preferences
- `GET /api/v1/notifications/preferences/` - Get preferences
- `POST /api/v1/notifications/preferences/` - Create preferences
- `PUT/PATCH /api/v1/notifications/preferences/{id}/` - Update preferences

### Templates & Channels (Admin)
- `GET /api/v1/notifications/templates/` - List templates (admin)
- `POST /api/v1/notifications/templates/` - Create template (admin)
- `GET /api/v1/notifications/channels/` - List channels (admin)
- `GET /api/v1/notifications/types/` - List types (read-only)

### Scheduled Notifications (Admin)
- `GET /api/v1/notifications/scheduled/` - List scheduled
- `POST /api/v1/notifications/scheduled/` - Create scheduled
- `POST /api/v1/notifications/scheduled/{id}/cancel/` - Cancel
- `POST /api/v1/notifications/scheduled/{id}/send_now/` - Send immediately

**Base Classes:** TenantAwareViewSet
**Permissions:** IsAuthenticated, varies by endpoint

---

## Key Issues Identified

### CRITICAL (Security/Stability)

#### 1. No Rate Limiting on Authentication Endpoints
**Location:** `POST /api/v1/auth/register/`, `/api/v1/auth/login/`
**Issue:** Brute force vulnerability
**Fix:** Apply UserRateThrottle (5 attempts/minute)
```python
from rest_framework.throttling import UserRateThrottle

class LoginViewSet(viewsets.ViewSet):
    throttle_classes = [UserRateThrottle]
```

#### 2. Missing Pagination on Bulk Operations
**Location:** `POST /api/v1/ats/bulk/`, `/api/v1/ats/candidates/bulk_import/`
**Issue:** Memory issues with large datasets
**Fix:** Add StandardPagination or batch processing

#### 3. Incomplete File Upload Validation
**Location:** ATS Candidates (resume), HR Documents
**Issue:** Security vulnerability
**Fix:** Validate file type, size, scan for malware

#### 4. Missing Nested Permission Checks
**Location:** ATS Job applications, Interview feedback
**Issue:** Data exposure risk
**Fix:** Add `check_object_permissions()` overrides

### HIGH (Functionality)

#### 5. Inconsistent Error Response Formats
**Issue:** Complex client error handling
**Fix:** Standardize error responses across all endpoints

#### 6. Missing Serializer Validations
**Issue:** Invalid data could be persisted
**Fix:** Add custom `validate()` methods to serializers

#### 7. No Audit Logging on Create/Update/Delete
**Issue:** Compliance problem
**Fix:** Add audit logging middleware

#### 8. Incomplete Workflow Automation
**Issue:** Escrow releases, offboarding steps not automated
**Fix:** Implement signal-based workflow triggers

### MEDIUM (Quality)

#### 9. No Versioning for Document Updates
**Issue:** Historical tracking missing
**Fix:** Implement django-simple-history

#### 10. Missing E-Signature Integration
**Issue:** Offers workflow incomplete
**Fix:** Integrate DocuSign/HelloSign

#### 11. Counter-Offer Workflow Not Implemented
**Issue:** Services Proposals incomplete
**Fix:** Add counter proposal endpoint

#### 12. No Celery Beat Scheduling Documented
**Issue:** Scheduled notifications unclear
**Fix:** Document Celery Beat configuration

---

## Authentication & Response Format

### JWT Token Endpoints
```
POST   /api/v1/auth/token/         - Get access + refresh tokens
POST   /api/v1/auth/token/refresh/ - Refresh expired access token
POST   /api/v1/auth/token/verify/  - Verify token validity
POST   /api/v1/auth/token/blacklist/ - Blacklist on logout
```

### Standard Response Format
```json
{
  "success": true,
  "data": {} | [] | null,
  "message": "Operation successful",
  "errors": {} | null,
  "meta": {
    "timestamp": "2026-01-16T10:30:00Z",
    "request_id": "abc123",
    "pagination": {
      "count": 100,
      "next": "http://...",
      "previous": null,
      "page_size": 20
    }
  }
}
```

---

## Pagination Configuration

- **StandardPagination** (20/page, max 100) - Default for most endpoints
- **LargeResultsPagination** (50/page, max 500) - Candidates, Applications
- **ScalableCursorPagination** - Recommended for 1M+ rows (not widely used yet)

**Recommendation:** Migrate high-volume endpoints to ScalableCursorPagination to prevent N+1 issues.

---

## Secure Base Classes

| Base Class | Purpose | Key Features |
|-----------|---------|--------------|
| SecureTenantViewSet | Standard secured ViewSet | Tenant isolation, audit logging |
| SecureReadOnlyViewSet | Read-only endpoints | Tenant isolation, no write access |
| RoleBasedViewSet | Role-based access | RBAC support |
| RecruiterViewSet | Recruiter-specific | Enhanced permission checks |
| HRViewSet | HR-specific | HR role enforcement |
| ParticipantViewSet | Participant-only | Client/provider filtering |
| AdminOnlyViewSet | Admin access | Admin-only enforcement |

---

## Recommendations for Days 2-4

### Day 2 Priority (Security)
1. ✅ Add rate limiting to auth endpoints
2. ✅ Implement file upload validation with security scanning
3. ✅ Add comprehensive permission checks on nested resources
4. ✅ Validate all financial transaction inputs

### Day 3 Priority (Completeness)
1. ✅ Add pagination to bulk operation endpoints
2. ✅ Implement filtering/search on all list endpoints
3. ✅ Add default ordering to list endpoints
4. ✅ Generate OpenAPI/Swagger schema

### Day 4 Priority (Robustness)
1. ✅ Add audit logging to all data modification endpoints
2. ✅ Implement error tracking (Sentry integration)
3. ✅ Add request logging middleware with performance metrics
4. ✅ Create API documentation and runbooks

---

## Testing Requirements

**Target:** 70%+ code coverage on all API endpoints

### Test Categories
1. **Authentication Tests** - Token generation, refresh, validation
2. **Permission Tests** - Tenant isolation, role-based access
3. **CRUD Tests** - Create, retrieve, update, delete operations
4. **Custom Action Tests** - All custom actions (publish, approve, etc.)
5. **Error Handling Tests** - 400, 403, 404, 500 responses
6. **Pagination Tests** - Verify page size, navigation
7. **Filter Tests** - Search, ordering, filtering

---

## Conclusion

The Zumodra API is well-structured with **200+ endpoints** across 6 major modules. The codebase uses secure base classes, tenant isolation, and JWT authentication. Critical security issues have been identified (rate limiting, file validation) and should be addressed on Day 2.

**Next Steps:**
1. Review this inventory with Backend Lead
2. Create GitHub issues for Critical/High issues
3. Implement security fixes on Day 2
4. Add comprehensive tests on Days 3-4
5. Generate OpenAPI documentation

**Estimated Fix Time:** 8-12 hours for all Critical/High issues
