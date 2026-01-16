"""
ATS Frontend URL Configuration.

Routes for ATS template views and HTMX endpoints.
"""

from django.urls import path

from .template_views import (
    # Job views
    JobListView,
    JobDetailView,
    JobCreateView,
    JobEditView,
    JobPublishView,
    JobCloseView,
    JobDuplicateView,
    JobDeleteView,

    # Candidate views
    CandidateListView,
    CandidateDetailView,
    CandidateCreateView,
    CandidateAddToJobView,

    # Pipeline views
    PipelineBoardView,
    ApplicationMoveView,
    ApplicationBulkActionView,

    # Application views
    ApplicationDetailView,
    ApplicationNoteView,
    ApplicationRejectView,
    EmailComposeView,

    # Interview views
    InterviewListView,
    InterviewDetailView,
    InterviewScheduleView,
    InterviewFeedbackView,
    InterviewRescheduleView,
    InterviewCancelView,

    # Offer views (Step 5)
    OfferListView,
    OfferDetailView,
    OfferCreateView,
    OfferActionView,

    # Utility views
    TeamMemberSearchView,

    # Background check views
    InitiateBackgroundCheckView,
    BackgroundCheckStatusView,
    BackgroundCheckReportView,
    BackgroundCheckStatusPartialView,
)

# TODO: These views need to be implemented
# from .views import (
#     CandidateEditView,
#     CandidateImportView,
#     CandidateAddNoteView,
#     CandidateEditTagsView,
#     ApplicationListView,
# )

app_name = 'ats'

urlpatterns = [
    # ===== JOB ROUTES =====
    path('jobs/', JobListView.as_view(), name='job_list'),
    path('jobs/create/', JobCreateView.as_view(), name='job_create'),
    path('jobs/<uuid:pk>/', JobDetailView.as_view(), name='job_detail'),
    path('jobs/<uuid:pk>/edit/', JobEditView.as_view(), name='job_edit'),
    path('jobs/<uuid:pk>/publish/', JobPublishView.as_view(), name='job_publish'),
    path('jobs/<uuid:pk>/close/', JobCloseView.as_view(), name='job_close'),
    path('jobs/<uuid:pk>/duplicate/', JobDuplicateView.as_view(), name='job_duplicate'),
    path('jobs/<uuid:pk>/delete/', JobDeleteView.as_view(), name='job_delete'),

    # ===== CANDIDATE ROUTES =====
    path('candidates/', CandidateListView.as_view(), name='candidate_list'),
    path('candidates/create/', CandidateCreateView.as_view(), name='candidate_create'),
    path('candidates/<uuid:pk>/', CandidateDetailView.as_view(), name='candidate_detail'),
    path('candidates/<uuid:pk>/add-to-job/', CandidateAddToJobView.as_view(), name='candidate_add_to_job'),

    # ===== PIPELINE ROUTES =====
    path('pipeline/', PipelineBoardView.as_view(), name='pipeline_board'),

    # ===== APPLICATION ROUTES =====
    path('applications/<uuid:pk>/', ApplicationDetailView.as_view(), name='application_detail'),
    path('applications/<uuid:application_pk>/note/', ApplicationNoteView.as_view(), name='application_add_note'),
    path('applications/<uuid:pk>/reject/', ApplicationRejectView.as_view(), name='application_reject'),

    # ===== INTERVIEW ROUTES =====
    path('interviews/', InterviewListView.as_view(), name='interview_list'),
    path('interviews/<uuid:pk>/', InterviewDetailView.as_view(), name='interview_detail'),
    path('interviews/<uuid:pk>/reschedule/', InterviewRescheduleView.as_view(), name='interview_reschedule'),
    path('interviews/<uuid:pk>/cancel/', InterviewCancelView.as_view(), name='interview_cancel'),

    # ===== OFFER ROUTES (Step 5 - End-to-End Hiring) =====
    path('offers/', OfferListView.as_view(), name='offer_list'),
    path('offers/<uuid:pk>/', OfferDetailView.as_view(), name='offer_detail'),
    path('offers/create/<uuid:application_pk>/', OfferCreateView.as_view(), name='offer_create'),
    path('offers/<uuid:pk>/<str:action>/', OfferActionView.as_view(), name='offer_action'),

    # ===== HTMX ENDPOINTS =====
    # Email composition
    path('htmx/email/compose/', EmailComposeView.as_view(), name='email_compose'),

    # Application drag-and-drop
    path('htmx/applications/<uuid:pk>/move/', ApplicationMoveView.as_view(), name='application_move'),

    # Bulk actions
    path('htmx/applications/bulk/', ApplicationBulkActionView.as_view(), name='application_bulk_action'),

    # Interview scheduling
    path('htmx/interviews/schedule/', InterviewScheduleView.as_view(), name='interview_schedule'),
    path('htmx/interviews/schedule/<uuid:application_pk>/', InterviewScheduleView.as_view(), name='interview_schedule_for_application'),

    # Interview feedback
    path('htmx/interviews/<uuid:interview_pk>/feedback/', InterviewFeedbackView.as_view(), name='interview_feedback'),

    # Team member search
    path('htmx/team-members/search/', TeamMemberSearchView.as_view(), name='team_member_search'),

    # ===== BACKGROUND CHECK ROUTES =====
    path('applications/<uuid:uuid>/background-check/initiate/', InitiateBackgroundCheckView.as_view(), name='background_check_initiate'),
    path('applications/<uuid:uuid>/background-check/status/', BackgroundCheckStatusView.as_view(), name='background_check_status'),
    path('applications/<uuid:uuid>/background-check/report/', BackgroundCheckReportView.as_view(), name='background_check_report'),

    # HTMX partial for background check status badge
    path('htmx/applications/<uuid:uuid>/background-check/status-badge/', BackgroundCheckStatusPartialView.as_view(), name='background_check_status_partial'),

    # ===== PLACEHOLDER ROUTES (TODO: Implement these views) =====
    # These URL patterns are referenced in templates but views are not yet implemented
    # Commenting them out to prevent import errors - uncomment when views are ready

    # path('candidates/<uuid:pk>/edit/', CandidateEditView.as_view(), name='candidate_edit'),
    # path('candidates/import/', CandidateImportView.as_view(), name='candidate_import'),
    # path('candidates/<uuid:pk>/add-note/', CandidateAddNoteView.as_view(), name='candidate_add_note'),
    # path('candidates/<uuid:pk>/edit-tags/', CandidateEditTagsView.as_view(), name='candidate_edit_tags'),
    # path('applications/', ApplicationListView.as_view(), name='application_list'),
]
