"""
HR Core API URLs - REST API routing for Human Resources

This module defines URL patterns for the HR Core API including:
- Employee management endpoints
- Time-off request endpoints
- Onboarding endpoints
- Document management endpoints
- Performance review endpoints
- Offboarding endpoints
- Special views (org chart, calendar, dashboard)
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    # ViewSets
    EmployeeViewSet,
    TimeOffTypeViewSet,
    TimeOffRequestViewSet,
    OnboardingChecklistViewSet,
    OnboardingTaskViewSet,
    EmployeeOnboardingViewSet,
    DocumentTemplateViewSet,
    EmployeeDocumentViewSet,
    OffboardingViewSet,
    PerformanceReviewViewSet,
    PerformanceImprovementPlanViewSet,
    PIPMilestoneViewSet,
    PIPProgressNoteViewSet,
    # Special Views
    OrgChartView,
    TeamCalendarView,
    HRDashboardStatsView,
    HRReportsView,
)

app_name = 'hr'  # Changed from 'hr_core' to match frontend namespace (2026-01-18)

# Create router and register viewsets
router = DefaultRouter()

# Employee endpoints
router.register(r'employees', EmployeeViewSet, basename='employee')

# Time-off endpoints
router.register(r'time-off-types', TimeOffTypeViewSet, basename='time-off-type')
router.register(r'time-off-requests', TimeOffRequestViewSet, basename='time-off-request')

# Onboarding endpoints
router.register(r'onboarding-checklists', OnboardingChecklistViewSet, basename='onboarding-checklist')
router.register(r'onboarding-tasks', OnboardingTaskViewSet, basename='onboarding-task')
router.register(r'employee-onboardings', EmployeeOnboardingViewSet, basename='employee-onboarding')

# Document endpoints
router.register(r'document-templates', DocumentTemplateViewSet, basename='document-template')
router.register(r'employee-documents', EmployeeDocumentViewSet, basename='employee-document')

# Offboarding endpoints
router.register(r'offboardings', OffboardingViewSet, basename='offboarding')

# Performance review endpoints
router.register(r'performance-reviews', PerformanceReviewViewSet, basename='performance-review')

# Performance Improvement Plan (PIP) endpoints
router.register(r'pips', PerformanceImprovementPlanViewSet, basename='pip')
router.register(r'pip-milestones', PIPMilestoneViewSet, basename='pip-milestone')
router.register(r'pip-progress-notes', PIPProgressNoteViewSet, basename='pip-progress-note')

urlpatterns = [
    # Special views (non-CRUD endpoints)
    path('org-chart/', OrgChartView.as_view(), name='org-chart'),
    path('team-calendar/', TeamCalendarView.as_view(), name='team-calendar'),
    path('dashboard/stats/', HRDashboardStatsView.as_view(), name='dashboard-stats'),
    path('reports/', HRReportsView.as_view(), name='hr-reports'),

    # Router URLs (all ViewSets)
    path('', include(router.urls)),
]

"""
API Endpoints Documentation
===========================

EMPLOYEES
---------
GET    /hr/employees/                    - List all employees (filtered by permission)
POST   /hr/employees/                    - Create new employee
GET    /hr/employees/{id}/               - Get employee detail
PUT    /hr/employees/{id}/               - Update employee
PATCH  /hr/employees/{id}/               - Partial update employee
DELETE /hr/employees/{id}/               - Delete employee
GET    /hr/employees/minimal/            - Get minimal employee list for dropdowns
GET    /hr/employees/me/                 - Get current user's employee record
GET    /hr/employees/{id}/direct_reports/ - Get employee's direct reports
GET    /hr/employees/org_chart/          - Get organizational chart
POST   /hr/employees/{id}/terminate/     - Initiate employee termination

Filters:
- ?status=active                         - Filter by status
- ?employment_type=full_time             - Filter by employment type
- ?department=1                          - Filter by department ID
- ?manager=1                             - Filter by manager ID
- ?search=john                           - Search by name, email, ID
- ?hire_date_from=2024-01-01             - Filter by hire date range
- ?is_active=true                        - Filter active employees

TIME-OFF TYPES
--------------
GET    /hr/time-off-types/               - List all time-off types
POST   /hr/time-off-types/               - Create time-off type (admin only)
GET    /hr/time-off-types/{id}/          - Get time-off type detail
PUT    /hr/time-off-types/{id}/          - Update time-off type (admin only)
DELETE /hr/time-off-types/{id}/          - Delete time-off type (admin only)

TIME-OFF REQUESTS
-----------------
GET    /hr/time-off-requests/            - List time-off requests (filtered by permission)
POST   /hr/time-off-requests/            - Create time-off request
GET    /hr/time-off-requests/{id}/       - Get request detail
PUT    /hr/time-off-requests/{id}/       - Update request
DELETE /hr/time-off-requests/{id}/       - Delete request
GET    /hr/time-off-requests/my_requests/ - Get current user's requests
GET    /hr/time-off-requests/pending_approval/ - Get requests pending approval
GET    /hr/time-off-requests/balance/    - Get current user's time-off balance
POST   /hr/time-off-requests/{id}/approve/ - Approve request (manager/HR)
POST   /hr/time-off-requests/{id}/reject/  - Reject request (manager/HR)
POST   /hr/time-off-requests/{id}/cancel/  - Cancel request

Filters:
- ?status=pending                        - Filter by status
- ?employee=1                            - Filter by employee ID
- ?time_off_type=1                       - Filter by time-off type
- ?start_date_from=2024-01-01            - Filter by date range
- ?is_current=true                       - Filter current requests

ONBOARDING CHECKLISTS
---------------------
GET    /hr/onboarding-checklists/        - List onboarding checklists
POST   /hr/onboarding-checklists/        - Create checklist (admin only)
GET    /hr/onboarding-checklists/{id}/   - Get checklist detail
PUT    /hr/onboarding-checklists/{id}/   - Update checklist (admin only)
DELETE /hr/onboarding-checklists/{id}/   - Delete checklist (admin only)
POST   /hr/onboarding-checklists/{id}/add_task/ - Add task to checklist

ONBOARDING TASKS
----------------
GET    /hr/onboarding-tasks/             - List onboarding tasks
POST   /hr/onboarding-tasks/             - Create task (admin only)
GET    /hr/onboarding-tasks/{id}/        - Get task detail
PUT    /hr/onboarding-tasks/{id}/        - Update task (admin only)
DELETE /hr/onboarding-tasks/{id}/        - Delete task (admin only)

EMPLOYEE ONBOARDINGS
--------------------
GET    /hr/employee-onboardings/         - List employee onboardings
POST   /hr/employee-onboardings/         - Create employee onboarding
GET    /hr/employee-onboardings/{id}/    - Get onboarding detail
PUT    /hr/employee-onboardings/{id}/    - Update onboarding
DELETE /hr/employee-onboardings/{id}/    - Delete onboarding
GET    /hr/employee-onboardings/{id}/progress/ - Get detailed progress
POST   /hr/employee-onboardings/{id}/complete_task/ - Complete a task

DOCUMENT TEMPLATES
------------------
GET    /hr/document-templates/           - List document templates
POST   /hr/document-templates/           - Create template (admin only)
GET    /hr/document-templates/{id}/      - Get template detail
PUT    /hr/document-templates/{id}/      - Update template (admin only)
DELETE /hr/document-templates/{id}/      - Delete template (admin only)
POST   /hr/document-templates/{id}/generate_for_employee/ - Generate document

EMPLOYEE DOCUMENTS
------------------
GET    /hr/employee-documents/           - List employee documents
POST   /hr/employee-documents/           - Upload document
GET    /hr/employee-documents/{id}/      - Get document detail
PUT    /hr/employee-documents/{id}/      - Update document
DELETE /hr/employee-documents/{id}/      - Delete document
GET    /hr/employee-documents/my_documents/ - Get current user's documents
GET    /hr/employee-documents/pending_signatures/ - Get documents pending signature
POST   /hr/employee-documents/{id}/sign/ - Sign document
POST   /hr/employee-documents/{id}/request_signature/ - Request signature (HR)
POST   /hr/employee-documents/{id}/archive/ - Archive document

Filters:
- ?employee=1                            - Filter by employee ID
- ?category=contract                     - Filter by category
- ?status=pending_signature              - Filter by status
- ?is_expired=true                       - Filter expired documents

OFFBOARDINGS
------------
GET    /hr/offboardings/                 - List offboardings (HR only)
POST   /hr/offboardings/                 - Create offboarding
GET    /hr/offboardings/{id}/            - Get offboarding detail
PUT    /hr/offboardings/{id}/            - Update offboarding
DELETE /hr/offboardings/{id}/            - Delete offboarding
POST   /hr/offboardings/{id}/complete_step/ - Complete checklist step
POST   /hr/offboardings/{id}/record_exit_interview/ - Record exit interview

Filters:
- ?separation_type=resignation           - Filter by separation type
- ?eligible_for_rehire=true              - Filter by rehire eligibility
- ?is_completed=false                    - Filter incomplete offboardings

PERFORMANCE REVIEWS
-------------------
GET    /hr/performance-reviews/          - List performance reviews
POST   /hr/performance-reviews/          - Create review
GET    /hr/performance-reviews/{id}/     - Get review detail
PUT    /hr/performance-reviews/{id}/     - Update review
DELETE /hr/performance-reviews/{id}/     - Delete review
GET    /hr/performance-reviews/my_reviews/ - Get current user's reviews
GET    /hr/performance-reviews/pending_my_action/ - Get reviews needing action
POST   /hr/performance-reviews/{id}/submit/ - Submit self-assessment
POST   /hr/performance-reviews/{id}/complete/ - Complete manager review
POST   /hr/performance-reviews/{id}/approve/ - HR approval
POST   /hr/performance-reviews/{id}/send_back/ - Send back for revision

Filters:
- ?employee=1                            - Filter by employee ID
- ?status=pending_manager                - Filter by status
- ?review_type=annual                    - Filter by review type
- ?year=2024                             - Filter by review year
- ?overall_rating_min=3                  - Filter by minimum rating

SPECIAL ENDPOINTS
-----------------
GET    /hr/org-chart/                    - Get organizational chart
                                           ?root=1 - Start from specific employee
                                           ?depth=3 - Limit hierarchy depth

GET    /hr/team-calendar/                - Get team calendar events
                                           ?start=2024-01-01 - Start date
                                           ?end=2024-01-31 - End date
                                           ?team=1 - Manager's employee ID

GET    /hr/dashboard/stats/              - Get HR dashboard statistics (admin only)

GENERAL FILTERS & PAGINATION
-----------------------------
- ?page=2                                - Pagination
- ?page_size=20                          - Custom page size (max 100)
- ?ordering=-created_at                  - Ordering (prefix - for descending)
- ?search=query                          - Text search (where available)
"""
