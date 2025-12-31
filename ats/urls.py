"""
ATS URLs - REST API routing for Applicant Tracking System

This module provides URL routing with:
- Standard CRUD endpoints for all models
- Nested-like routes via ViewSet actions (applications under jobs, etc.)
- Custom action endpoints
- Dashboard and AI match score endpoints

Note: Nested routes are implemented via @action decorators in ViewSets
rather than drf-nested-routers for simplicity. For example:
- GET /api/ats/jobs/{uuid}/applications/ - handled by JobPostingViewSet.applications()
- GET /api/ats/applications/{uuid}/interviews/ - via ApplicationViewSet (add as needed)
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    JobCategoryViewSet, PipelineViewSet, PipelineStageViewSet,
    JobPostingViewSet, CandidateViewSet, ApplicationViewSet,
    InterviewViewSet, InterviewFeedbackViewSet, OfferViewSet,
    SavedSearchViewSet, DashboardStatsView, AIMatchScoreView,
    BulkOperationsView,
    # Advanced ATS features (Cycle 3)
    InterviewSlotViewSet, InterviewSchedulingView,
    OfferTemplateViewSet, OfferApprovalViewSet, OfferWorkflowView,
    PipelineAnalyticsView, AdvancedReportsView
)

app_name = 'ats'

# Main router - all CRUD operations and custom actions are handled via ViewSets
router = DefaultRouter()

# Categories
router.register(r'categories', JobCategoryViewSet, basename='category')

# Pipelines and Stages
router.register(r'pipelines', PipelineViewSet, basename='pipeline')
router.register(r'stages', PipelineStageViewSet, basename='stage')

# Jobs
router.register(r'jobs', JobPostingViewSet, basename='job')

# Candidates
router.register(r'candidates', CandidateViewSet, basename='candidate')

# Applications
router.register(r'applications', ApplicationViewSet, basename='application')

# Interviews and Feedback
router.register(r'interviews', InterviewViewSet, basename='interview')
router.register(r'feedback', InterviewFeedbackViewSet, basename='feedback')

# Offers
router.register(r'offers', OfferViewSet, basename='offer')

# Saved Searches
router.register(r'saved-searches', SavedSearchViewSet, basename='saved-search')

# Advanced ATS Features (Cycle 3)
# Interview Slots - Interviewer availability management
router.register(r'interview-slots', InterviewSlotViewSet, basename='interview-slot')

# Offer Templates - Reusable offer letter templates
router.register(r'offer-templates', OfferTemplateViewSet, basename='offer-template')

# Offer Approvals - Approval workflow for offers
router.register(r'approvals', OfferApprovalViewSet, basename='approval')


urlpatterns = [
    # Main router URLs - includes all ViewSet routes and actions
    path('', include(router.urls)),

    # Dashboard and statistics
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),

    # AI Match Score endpoints
    path('ai/match-score/', AIMatchScoreView.as_view(), name='ai-match-score'),

    # Bulk operations
    path('bulk/', BulkOperationsView.as_view(), name='bulk-operations'),

    # ============== ADVANCED ATS FEATURES (CYCLE 3) ==============

    # Interview Scheduling endpoints
    path(
        'interviews/schedule/',
        InterviewSchedulingView.as_view(),
        {'action': 'schedule'},
        name='interview-schedule'
    ),
    path(
        'interviews/<uuid:uuid>/reschedule/',
        InterviewSchedulingView.as_view(),
        {'action': 'reschedule'},
        name='interview-reschedule'
    ),
    path(
        'interviews/<uuid:uuid>/cancel/',
        InterviewSchedulingView.as_view(),
        {'action': 'cancel'},
        name='interview-cancel'
    ),
    path(
        'interviews/<uuid:uuid>/send-reminders/',
        InterviewSchedulingView.as_view(),
        {'action': 'send-reminders'},
        name='interview-send-reminders'
    ),

    # Offer Workflow endpoints
    path(
        'offers/<uuid:uuid>/generate-letter/',
        OfferWorkflowView.as_view(),
        {'action': 'generate-letter'},
        name='offer-generate-letter'
    ),
    path(
        'offers/<uuid:uuid>/send-for-signature/',
        OfferWorkflowView.as_view(),
        {'action': 'send-for-signature'},
        name='offer-send-for-signature'
    ),
    path(
        'offers/<uuid:uuid>/check-signature-status/',
        OfferWorkflowView.as_view(),
        {'action': 'check-signature-status'},
        name='offer-check-signature-status'
    ),
    path(
        'offers/<uuid:uuid>/counter/',
        OfferWorkflowView.as_view(),
        {'action': 'counter'},
        name='offer-counter'
    ),
    path(
        'offers/<uuid:uuid>/request-approval/',
        OfferWorkflowView.as_view(),
        {'action': 'request-approval'},
        name='offer-request-approval'
    ),

    # Pipeline Analytics endpoints
    path(
        'pipelines/<int:pk>/analytics/',
        PipelineAnalyticsView.as_view(),
        {'action': 'analytics'},
        name='pipeline-analytics'
    ),
    path(
        'pipelines/<int:pk>/conversion-rates/',
        PipelineAnalyticsView.as_view(),
        {'action': 'conversion-rates'},
        name='pipeline-conversion-rates'
    ),
    path(
        'pipelines/<int:pk>/bottlenecks/',
        PipelineAnalyticsView.as_view(),
        {'action': 'bottlenecks'},
        name='pipeline-bottlenecks'
    ),
    path(
        'pipelines/<int:pk>/sla-status/',
        PipelineAnalyticsView.as_view(),
        {'action': 'sla-status'},
        name='pipeline-sla-status'
    ),
    path(
        'pipelines/compare/',
        PipelineAnalyticsView.as_view(),
        {'action': 'compare'},
        name='pipeline-compare'
    ),

    # Advanced Reports endpoints
    path(
        'reports/<str:report_type>/',
        AdvancedReportsView.as_view(),
        name='advanced-reports'
    ),
]


"""
ATS API Endpoints Reference
============================

Authentication:
All endpoints require authentication via JWT token or session.
Include header: Authorization: Bearer <token>

Job Categories:
---------------
GET    /api/ats/categories/                    - List all categories
POST   /api/ats/categories/                    - Create category
GET    /api/ats/categories/{id}/               - Get category details
PUT    /api/ats/categories/{id}/               - Update category
PATCH  /api/ats/categories/{id}/               - Partial update category
DELETE /api/ats/categories/{id}/               - Delete category
GET    /api/ats/categories/{id}/jobs/          - Get jobs in category

Pipelines:
----------
GET    /api/ats/pipelines/                     - List all pipelines
POST   /api/ats/pipelines/                     - Create pipeline (with stages)
GET    /api/ats/pipelines/{uuid}/              - Get pipeline with stages
PUT    /api/ats/pipelines/{uuid}/              - Update pipeline
PATCH  /api/ats/pipelines/{uuid}/              - Partial update pipeline
DELETE /api/ats/pipelines/{uuid}/              - Delete pipeline
POST   /api/ats/pipelines/{uuid}/add_stage/    - Add stage to pipeline
POST   /api/ats/pipelines/{uuid}/reorder_stages/ - Reorder stages
POST   /api/ats/pipelines/{uuid}/set_default/  - Set as default pipeline

Pipeline Stages:
----------------
GET    /api/ats/stages/                        - List all stages
GET    /api/ats/stages/{id}/                   - Get stage details
PUT    /api/ats/stages/{id}/                   - Update stage
DELETE /api/ats/stages/{id}/                   - Delete stage
GET    /api/ats/stages/{id}/applications/      - Get applications in stage

Job Postings:
-------------
GET    /api/ats/jobs/                          - List all jobs (with filters)
POST   /api/ats/jobs/                          - Create job posting
GET    /api/ats/jobs/{uuid}/                   - Get job details
PUT    /api/ats/jobs/{uuid}/                   - Update job posting
PATCH  /api/ats/jobs/{uuid}/                   - Partial update job posting
DELETE /api/ats/jobs/{uuid}/                   - Delete job posting
POST   /api/ats/jobs/{uuid}/publish/           - Publish draft job
POST   /api/ats/jobs/{uuid}/close/             - Close job posting
POST   /api/ats/jobs/{uuid}/clone/             - Clone job posting
GET    /api/ats/jobs/{uuid}/applications/      - Get job applications
GET    /api/ats/jobs/{uuid}/kanban/            - Get Kanban board data
GET    /api/ats/jobs/{uuid}/stats/             - Get job statistics

Candidates:
-----------
GET    /api/ats/candidates/                    - List all candidates (with filters)
POST   /api/ats/candidates/                    - Create candidate (with resume upload)
GET    /api/ats/candidates/{uuid}/             - Get candidate details
PUT    /api/ats/candidates/{uuid}/             - Update candidate
PATCH  /api/ats/candidates/{uuid}/             - Partial update candidate
DELETE /api/ats/candidates/{uuid}/             - Delete candidate
GET    /api/ats/candidates/{uuid}/applications/ - Get candidate's applications
POST   /api/ats/candidates/bulk_import/        - Bulk import candidates
POST   /api/ats/candidates/merge/              - Merge duplicate candidates
POST   /api/ats/candidates/{uuid}/add_tag/     - Add tag to candidate
POST   /api/ats/candidates/{uuid}/remove_tag/  - Remove tag from candidate

Applications:
-------------
GET    /api/ats/applications/                  - List all applications (with filters)
POST   /api/ats/applications/                  - Create application
GET    /api/ats/applications/{uuid}/           - Get application details
PUT    /api/ats/applications/{uuid}/           - Update application
PATCH  /api/ats/applications/{uuid}/           - Partial update application
DELETE /api/ats/applications/{uuid}/           - Delete application
POST   /api/ats/applications/{uuid}/move_stage/ - Move to different stage
POST   /api/ats/applications/{uuid}/reject/    - Reject application
POST   /api/ats/applications/{uuid}/advance/   - Advance to next stage
POST   /api/ats/applications/{uuid}/assign/    - Assign to user
POST   /api/ats/applications/{uuid}/rate/      - Rate application
GET    /api/ats/applications/{uuid}/notes/     - Get application notes
POST   /api/ats/applications/{uuid}/notes/     - Add note
GET    /api/ats/applications/{uuid}/activities/ - Get activity timeline
POST   /api/ats/applications/bulk_action/      - Bulk action on applications

Interviews:
-----------
GET    /api/ats/interviews/                    - List all interviews
POST   /api/ats/interviews/                    - Schedule interview
GET    /api/ats/interviews/{uuid}/             - Get interview details
PUT    /api/ats/interviews/{uuid}/             - Update interview
PATCH  /api/ats/interviews/{uuid}/             - Partial update interview
DELETE /api/ats/interviews/{uuid}/             - Delete interview
POST   /api/ats/interviews/{uuid}/reschedule/  - Reschedule interview
POST   /api/ats/interviews/{uuid}/complete/    - Mark as completed
POST   /api/ats/interviews/{uuid}/cancel/      - Cancel interview
GET    /api/ats/interviews/{uuid}/feedback/    - Get interview feedback
POST   /api/ats/interviews/{uuid}/feedback/    - Submit feedback
GET    /api/ats/interviews/my_interviews/      - Get my interviews
GET    /api/ats/interviews/upcoming/           - Get upcoming interviews

Interview Feedback:
-------------------
GET    /api/ats/feedback/                      - List all feedback (own only)
POST   /api/ats/feedback/                      - Submit feedback
GET    /api/ats/feedback/{id}/                 - Get feedback details
PUT    /api/ats/feedback/{id}/                 - Update feedback
PATCH  /api/ats/feedback/{id}/                 - Partial update feedback

Offers:
-------
GET    /api/ats/offers/                        - List all offers
POST   /api/ats/offers/                        - Create offer
GET    /api/ats/offers/{uuid}/                 - Get offer details
PUT    /api/ats/offers/{uuid}/                 - Update offer
PATCH  /api/ats/offers/{uuid}/                 - Partial update offer
DELETE /api/ats/offers/{uuid}/                 - Delete offer
POST   /api/ats/offers/{uuid}/send/            - Send offer to candidate
POST   /api/ats/offers/{uuid}/accept/          - Mark as accepted
POST   /api/ats/offers/{uuid}/decline/         - Mark as declined
POST   /api/ats/offers/{uuid}/approve/         - Approve offer
POST   /api/ats/offers/{uuid}/withdraw/        - Withdraw offer

Saved Searches:
---------------
GET    /api/ats/saved-searches/                - List saved searches
POST   /api/ats/saved-searches/                - Create saved search
GET    /api/ats/saved-searches/{uuid}/         - Get saved search details
PUT    /api/ats/saved-searches/{uuid}/         - Update saved search
PATCH  /api/ats/saved-searches/{uuid}/         - Partial update saved search
DELETE /api/ats/saved-searches/{uuid}/         - Delete saved search
GET    /api/ats/saved-searches/{uuid}/run/     - Execute saved search

Dashboard & AI:
---------------
GET    /api/ats/dashboard/stats/               - Get dashboard statistics
POST   /api/ats/ai/match-score/                - Calculate AI match score
GET    /api/ats/ai/match-score/?job_id=X       - Get scores for job
GET    /api/ats/ai/match-score/?candidate_id=X - Get scores for candidate

Bulk Operations:
----------------
POST   /api/ats/bulk/                          - Perform bulk operations
  Operations:
  - calculate_all_scores: Calculate AI scores for all applications of a job
    Body: {"operation": "calculate_all_scores", "job_id": 123}
  - bulk_stage_update: Move multiple applications to a stage
    Body: {"operation": "bulk_stage_update", "stage_id": 1, "application_ids": [1,2,3]}


Filter Parameters
==================

Job Postings (/api/ats/jobs/):
------------------------------
- status: draft, pending_approval, open, on_hold, closed, filled, cancelled
- category: category ID
- pipeline: pipeline ID
- job_type: full_time, part_time, contract, internship, temporary, freelance
- experience_level: entry, junior, mid, senior, lead, executive
- remote_policy: on_site, remote, hybrid, flexible
- location: city, state, or country (searches all)
- location_city, location_state, location_country: specific location fields
- is_remote: true/false (remote-friendly filter)
- salary_min: minimum salary (gte)
- salary_max: maximum salary (lte)
- salary_range: format "min-max" (e.g., "50000-100000")
- salary_currency: currency code (e.g., "CAD", "USD")
- required_skills: comma-separated skills (ALL must match)
- any_skill: comma-separated skills (ANY can match)
- hiring_manager: user ID
- recruiter: user ID
- created_by: user ID
- is_featured: true/false
- is_internal_only: true/false
- has_deadline: true/false
- deadline_soon: true/false (within 7 days)
- created_after: datetime (ISO format)
- created_before: datetime (ISO format)
- published_after: datetime
- published_before: datetime
- search: full-text search across title, description, requirements
- min_applications: minimum application count
- max_applications: maximum application count

Candidates (/api/ats/candidates/):
----------------------------------
- name: first or last name (partial match)
- email: email (partial match)
- headline: headline (partial match)
- current_company: company name (partial match)
- current_title: job title (partial match)
- min_experience: minimum years of experience
- max_experience: maximum years of experience
- city: city (partial match)
- state: state (partial match)
- country: country (partial match)
- location: searches city, state, and country
- willing_to_relocate: true/false
- skills: comma-separated skills (ALL must match)
- any_skill: comma-separated skills (ANY can match)
- source: career_page, linkedin, indeed, referral, agency, direct, imported, other
- referred_by: user ID
- tags: comma-separated tags
- salary_min: minimum desired salary
- salary_max: maximum desired salary
- languages: comma-separated languages (ALL must match)
- created_after: datetime
- created_before: datetime
- last_activity_after: datetime
- in_stage: stage ID (candidates with applications in specific stage)
- applied_to_job: job ID (candidates who applied to specific job)
- has_resume: true/false
- has_linkedin: true/false
- has_github: true/false
- search: full-text search across name, email, headline, company, etc.

Applications (/api/ats/applications/):
--------------------------------------
- job: job ID
- candidate: candidate ID
- current_stage: stage ID
- assigned_to: user ID
- status: new, in_review, shortlisted, interviewing, offer_pending,
         offer_extended, hired, rejected, withdrawn, on_hold
- statuses: comma-separated statuses (matches ANY)
- min_rating: minimum overall rating (0-5)
- max_rating: maximum overall rating (0-5)
- has_rating: true/false
- min_ai_score: minimum AI match score (0-100)
- max_ai_score: maximum AI match score (0-100)
- has_ai_score: true/false
- applied_after: datetime
- applied_before: datetime
- applied_today: true/false
- applied_this_week: true/false
- stage_changed_after: datetime
- stage_changed_before: datetime
- utm_source: UTM source parameter
- utm_medium: UTM medium parameter
- utm_campaign: UTM campaign parameter
- has_cover_letter: true/false
- has_interviews: true/false
- has_offers: true/false
- is_unassigned: true/false
- rejection_reason: partial match
- search: candidate name, email, job title

Interviews (/api/ats/interviews/):
----------------------------------
- application: application ID
- interview_type: phone, video, in_person, technical, panel, assessment, final
- status: scheduled, confirmed, in_progress, completed, cancelled, no_show, rescheduled
- organizer: user ID
- interviewer: user ID (filters by interviewer)
- scheduled_after: datetime
- scheduled_before: datetime
- today: true/false (interviews today)
- this_week: true/false (interviews this week)
- upcoming: true/false (future interviews)
- needs_feedback: true/false (completed without feedback)
- candidate_notified: true/false

Offers (/api/ats/offers/):
--------------------------
- application: application ID
- status: draft, pending_approval, approved, sent, accepted, declined,
         expired, withdrawn
- created_by: user ID
- approved_by: user ID
- min_salary: minimum base salary
- max_salary: maximum base salary
- salary_currency: currency code
- created_after: datetime
- created_before: datetime
- start_date_after: date
- start_date_before: date
- expiring_soon: true/false (within 3 days)
- requires_signature: true/false
- is_signed: true/false
- pending_approval: true/false


Advanced ATS Features (Cycle 3)
================================

Interview Slots:
----------------
GET    /api/ats/interview-slots/                  - List interview slots
POST   /api/ats/interview-slots/                  - Create interview slot
GET    /api/ats/interview-slots/{uuid}/           - Get slot details
PUT    /api/ats/interview-slots/{uuid}/           - Update slot
PATCH  /api/ats/interview-slots/{uuid}/           - Partial update slot
DELETE /api/ats/interview-slots/{uuid}/           - Delete slot
POST   /api/ats/interview-slots/bulk-create/      - Bulk create recurring slots
GET    /api/ats/interview-slots/available/        - Get available slots for date range
POST   /api/ats/interview-slots/find-common/      - Find common slots for panel interviews

Interview Scheduling:
---------------------
POST   /api/ats/interviews/schedule/              - Schedule interview with slot
POST   /api/ats/interviews/{uuid}/reschedule/     - Reschedule interview
POST   /api/ats/interviews/{uuid}/cancel/         - Cancel interview
POST   /api/ats/interviews/{uuid}/send-reminders/ - Send manual reminders

Offer Templates:
----------------
GET    /api/ats/offer-templates/                  - List offer templates
POST   /api/ats/offer-templates/                  - Create offer template
GET    /api/ats/offer-templates/{uuid}/           - Get template details
PUT    /api/ats/offer-templates/{uuid}/           - Update template
PATCH  /api/ats/offer-templates/{uuid}/           - Partial update template
DELETE /api/ats/offer-templates/{uuid}/           - Delete template
POST   /api/ats/offer-templates/{uuid}/apply/     - Apply template to an offer

Offer Approvals:
----------------
GET    /api/ats/approvals/                        - List offer approvals
GET    /api/ats/approvals/?offer_id=X             - List approvals for specific offer
GET    /api/ats/approvals/{uuid}/                 - Get approval details
POST   /api/ats/approvals/{uuid}/approve/         - Approve offer
POST   /api/ats/approvals/{uuid}/reject/          - Reject offer

Offer Workflow:
---------------
POST   /api/ats/offers/{uuid}/generate-letter/    - Generate offer letter from template
POST   /api/ats/offers/{uuid}/send-for-signature/ - Send offer for e-signature
POST   /api/ats/offers/{uuid}/check-signature-status/ - Check e-signature status
POST   /api/ats/offers/{uuid}/counter/            - Create counter-offer
POST   /api/ats/offers/{uuid}/request-approval/   - Request approval from approvers

Pipeline Analytics:
-------------------
GET    /api/ats/pipelines/{id}/analytics/         - Full pipeline analytics
GET    /api/ats/pipelines/{id}/conversion-rates/  - Stage conversion rates
GET    /api/ats/pipelines/{id}/bottlenecks/       - Identify bottlenecks
GET    /api/ats/pipelines/{id}/sla-status/        - SLA compliance status
GET    /api/ats/pipelines/compare/?pipeline_a_id=X&pipeline_b_id=Y - Compare pipelines

Advanced Reports:
-----------------
GET    /api/ats/reports/recruiting-funnel/        - Recruiting funnel report
GET    /api/ats/reports/dei/                      - DEI (Diversity, Equity, Inclusion) metrics
GET    /api/ats/reports/cost-per-hire/            - Cost per hire analysis
GET    /api/ats/reports/time-to-fill/             - Time to fill metrics
GET    /api/ats/reports/source-quality/           - Source effectiveness analysis
GET    /api/ats/reports/recruiter-performance/    - Recruiter performance metrics


Pagination & Ordering
=====================

All list endpoints support:
- page: page number (default: 1)
- page_size: items per page (default: 20, max: 100)
- ordering: field name to order by (prefix with - for descending)
- search: full-text search (if supported)

Example: GET /api/ats/jobs/?page=2&page_size=10&ordering=-created_at&search=developer
"""
