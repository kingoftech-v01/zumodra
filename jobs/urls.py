"""
URL configuration for jobs app (ATS - Applicant Tracking System).

Implements dual-layer architecture with nested namespaces:
- Frontend: frontend:jobs:view_name
- API: api:v1:jobs:resource-name

Strictly follows URL_AND_VIEW_CONVENTIONS.md - ZERO DEVIATIONS PERMITTED.

This file consolidates:
- Frontend routes (previously in urls_frontend.py)
- API routes (previously in api/urls.py)
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import template_views
from . import views_api

# ============================================================================
# API LAYER - DRF ViewSets and Endpoints
# ============================================================================

# DRF Router for ViewSets
api_router = DefaultRouter()

# Job Categories
api_router.register(r'categories', views_api.JobCategoryViewSet, basename='category')

# Pipelines and Stages
api_router.register(r'pipelines', views_api.PipelineViewSet, basename='pipeline')
api_router.register(r'stages', views_api.PipelineStageViewSet, basename='stage')

# Jobs
api_router.register(r'jobs', views_api.JobPostingViewSet, basename='job')

# Candidates
api_router.register(r'candidates', views_api.CandidateViewSet, basename='candidate')

# Applications
api_router.register(r'applications', views_api.ApplicationViewSet, basename='application')

# Interviews and Feedback
api_router.register(r'interviews', views_api.InterviewViewSet, basename='interview')
api_router.register(r'feedback', views_api.InterviewFeedbackViewSet, basename='feedback')

# Offers
api_router.register(r'offers', views_api.OfferViewSet, basename='offer')

# Saved Searches
api_router.register(r'saved-searches', views_api.SavedSearchViewSet, basename='saved-search')

# Interview Slots
api_router.register(r'interview-slots', views_api.InterviewSlotViewSet, basename='interview-slot')

# Offer Templates and Approvals
api_router.register(r'offer-templates', views_api.OfferTemplateViewSet, basename='offer-template')
api_router.register(r'approvals', views_api.OfferApprovalViewSet, basename='approval')

# API URL Patterns (Non-ViewSet endpoints)
api_urlpatterns = [
    # Router URLs
    path('', include(api_router.urls)),

    # Dashboard and Statistics
    path(
        'dashboard/stats/',
        views_api.DashboardStatsView.as_view(),
        name='dashboard-stats'
    ),

    # AI Match Score
    path(
        'ai/match-score/',
        views_api.AIMatchScoreView.as_view(),
        name='ai-match-score'
    ),

    # Bulk Operations
    path(
        'bulk/',
        views_api.BulkOperationsView.as_view(),
        name='bulk-operations'
    ),

    # Interview Scheduling
    path(
        'interviews/schedule/',
        views_api.InterviewSchedulingView.as_view(),
        {'action': 'schedule'},
        name='interview-schedule'
    ),
    path(
        'interviews/<uuid:uuid>/reschedule/',
        views_api.InterviewSchedulingView.as_view(),
        {'action': 'reschedule'},
        name='interview-reschedule'
    ),
    path(
        'interviews/<uuid:uuid>/cancel/',
        views_api.InterviewSchedulingView.as_view(),
        {'action': 'cancel'},
        name='interview-cancel'
    ),
    path(
        'interviews/<uuid:uuid>/send-reminders/',
        views_api.InterviewSchedulingView.as_view(),
        {'action': 'send-reminders'},
        name='interview-send-reminders'
    ),

    # Offer Workflow
    path(
        'offers/<uuid:uuid>/generate-letter/',
        views_api.OfferWorkflowView.as_view(),
        {'action': 'generate-letter'},
        name='offer-generate-letter'
    ),
    path(
        'offers/<uuid:uuid>/send-for-signature/',
        views_api.OfferWorkflowView.as_view(),
        {'action': 'send-for-signature'},
        name='offer-send-for-signature'
    ),
    path(
        'offers/<uuid:uuid>/check-signature-status/',
        views_api.OfferWorkflowView.as_view(),
        {'action': 'check-signature-status'},
        name='offer-check-signature-status'
    ),
    path(
        'offers/<uuid:uuid>/counter/',
        views_api.OfferWorkflowView.as_view(),
        {'action': 'counter'},
        name='offer-counter'
    ),
    path(
        'offers/<uuid:uuid>/request-approval/',
        views_api.OfferWorkflowView.as_view(),
        {'action': 'request-approval'},
        name='offer-request-approval'
    ),

    # Pipeline Analytics
    path(
        'pipelines/<int:pk>/analytics/',
        views_api.PipelineAnalyticsView.as_view(),
        {'action': 'analytics'},
        name='pipeline-analytics'
    ),

    # Advanced Reports
    path(
        'reports/advanced/',
        views_api.AdvancedReportsView.as_view(),
        name='advanced-reports'
    ),
]

# ============================================================================
# FRONTEND LAYER - HTML Template Views
# ============================================================================

frontend_urlpatterns = [
    # Job Management
    path(
        'jobs/',
        template_views.JobListView.as_view(),
        name='job_list'
    ),
    path(
        'jobs/create/',
        template_views.JobCreateView.as_view(),
        name='job_create'
    ),
    path(
        'jobs/<uuid:pk>/',
        template_views.JobDetailView.as_view(),
        name='job_detail'
    ),
    path(
        'jobs/<uuid:pk>/edit/',
        template_views.JobEditView.as_view(),
        name='job_edit'
    ),
    path(
        'jobs/<uuid:pk>/publish/',
        template_views.JobPublishView.as_view(),
        name='job_publish'
    ),
    path(
        'jobs/<uuid:pk>/close/',
        template_views.JobCloseView.as_view(),
        name='job_close'
    ),
    path(
        'jobs/<uuid:pk>/duplicate/',
        template_views.JobDuplicateView.as_view(),
        name='job_duplicate'
    ),
    path(
        'jobs/<uuid:pk>/delete/',
        template_views.JobDeleteView.as_view(),
        name='job_delete'
    ),

    # Candidate Management
    path(
        'candidates/',
        template_views.CandidateListView.as_view(),
        name='candidate_list'
    ),
    path(
        'candidates/create/',
        template_views.CandidateCreateView.as_view(),
        name='candidate_create'
    ),
    path(
        'candidates/<uuid:pk>/',
        template_views.CandidateDetailView.as_view(),
        name='candidate_detail'
    ),
    path(
        'candidates/<uuid:pk>/add-to-job/',
        template_views.CandidateAddToJobView.as_view(),
        name='candidate_add_to_job'
    ),

    # Pipeline Management
    path(
        'pipeline/',
        template_views.PipelineBoardView.as_view(),
        name='pipeline_board'
    ),

    # Application Management
    path(
        'applications/<uuid:pk>/',
        template_views.ApplicationDetailView.as_view(),
        name='application_detail'
    ),
    path(
        'applications/<uuid:application_pk>/note/',
        template_views.ApplicationNoteView.as_view(),
        name='application_add_note'
    ),
    path(
        'applications/<uuid:pk>/reject/',
        template_views.ApplicationRejectView.as_view(),
        name='application_reject'
    ),

    # Interview Management
    path(
        'interviews/',
        template_views.InterviewListView.as_view(),
        name='interview_list'
    ),
    path(
        'interviews/<uuid:pk>/',
        template_views.InterviewDetailView.as_view(),
        name='interview_detail'
    ),
    path(
        'interviews/<uuid:pk>/reschedule/',
        template_views.InterviewRescheduleView.as_view(),
        name='interview_reschedule'
    ),
    path(
        'interviews/<uuid:pk>/cancel/',
        template_views.InterviewCancelView.as_view(),
        name='interview_cancel'
    ),

    # Offer Management
    path(
        'offers/',
        template_views.OfferListView.as_view(),
        name='offer_list'
    ),
    path(
        'offers/<uuid:pk>/',
        template_views.OfferDetailView.as_view(),
        name='offer_detail'
    ),
    path(
        'offers/create/<uuid:application_pk>/',
        template_views.OfferCreateView.as_view(),
        name='offer_create'
    ),
    path(
        'offers/<uuid:pk>/<str:action>/',
        template_views.OfferActionView.as_view(),
        name='offer_action'
    ),

    # HTMX Endpoints
    # Email composition
    path(
        'htmx/email/compose/',
        template_views.EmailComposeView.as_view(),
        name='email_compose'
    ),

    # Application drag-and-drop
    path(
        'htmx/applications/<uuid:pk>/move/',
        template_views.ApplicationMoveView.as_view(),
        name='application_move'
    ),

    # Bulk actions
    path(
        'htmx/applications/bulk/',
        template_views.ApplicationBulkActionView.as_view(),
        name='application_bulk_action'
    ),

    # Interview scheduling
    path(
        'htmx/interviews/schedule/',
        template_views.InterviewScheduleView.as_view(),
        name='interview_schedule'
    ),
    path(
        'htmx/interviews/schedule/<uuid:application_pk>/',
        template_views.InterviewScheduleView.as_view(),
        name='interview_schedule_for_application'
    ),

    # Interview feedback
    path(
        'htmx/interviews/<uuid:interview_pk>/feedback/',
        template_views.InterviewFeedbackView.as_view(),
        name='interview_feedback'
    ),

    # Team member search
    path(
        'htmx/team-members/search/',
        template_views.TeamMemberSearchView.as_view(),
        name='team_member_search'
    ),

    # Background Check Routes
    path(
        'applications/<uuid:uuid>/background-check/initiate/',
        template_views.InitiateBackgroundCheckView.as_view(),
        name='background_check_initiate'
    ),
    path(
        'applications/<uuid:uuid>/background-check/status/',
        template_views.BackgroundCheckStatusView.as_view(),
        name='background_check_status'
    ),
    path(
        'applications/<uuid:uuid>/background-check/report/',
        template_views.BackgroundCheckReportView.as_view(),
        name='background_check_report'
    ),

    # HTMX partial for background check status badge
    path(
        'htmx/applications/<uuid:uuid>/background-check/status-badge/',
        template_views.BackgroundCheckStatusPartialView.as_view(),
        name='background_check_status_partial'
    ),
]

# ============================================================================
# ROOT URL CONFIGURATION - Dual-Layer Architecture
# ============================================================================

app_name = 'jobs'

urlpatterns = [
    # API Layer (Namespace: api:v1:jobs:*)
    path('api/', include((api_urlpatterns, 'api'))),

    # Frontend Layer (Namespace: frontend:jobs:*)
    path('', include((frontend_urlpatterns, 'frontend'))),
]
