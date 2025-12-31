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
    JobPublishView,
    JobCloseView,

    # Candidate views
    CandidateListView,
    CandidateDetailView,

    # Pipeline views
    PipelineBoardView,
    ApplicationMoveView,
    ApplicationBulkActionView,

    # Application views
    ApplicationDetailView,
    ApplicationNoteView,

    # Interview views
    InterviewScheduleView,
    InterviewFeedbackView,

    # Offer views (Step 5)
    OfferListView,
    OfferDetailView,
    OfferCreateView,
    OfferActionView,
)

app_name = 'ats'

urlpatterns = [
    # ===== JOB ROUTES =====
    path('jobs/', JobListView.as_view(), name='job-list'),
    path('jobs/create/', JobCreateView.as_view(), name='job-create'),
    path('jobs/<uuid:pk>/', JobDetailView.as_view(), name='job-detail'),
    path('jobs/<uuid:pk>/publish/', JobPublishView.as_view(), name='job-publish'),
    path('jobs/<uuid:pk>/close/', JobCloseView.as_view(), name='job-close'),

    # ===== CANDIDATE ROUTES =====
    path('candidates/', CandidateListView.as_view(), name='candidate-list'),
    path('candidates/<uuid:pk>/', CandidateDetailView.as_view(), name='candidate-detail'),

    # ===== PIPELINE ROUTES =====
    path('pipeline/', PipelineBoardView.as_view(), name='pipeline-board'),

    # ===== APPLICATION ROUTES =====
    path('applications/<uuid:pk>/', ApplicationDetailView.as_view(), name='application-detail'),
    path('applications/<uuid:application_pk>/note/', ApplicationNoteView.as_view(), name='application-add-note'),

    # ===== OFFER ROUTES (Step 5 - End-to-End Hiring) =====
    path('offers/', OfferListView.as_view(), name='offer-list'),
    path('offers/<uuid:pk>/', OfferDetailView.as_view(), name='offer-detail'),
    path('offers/create/<uuid:application_pk>/', OfferCreateView.as_view(), name='offer-create'),
    path('offers/<uuid:pk>/<str:action>/', OfferActionView.as_view(), name='offer-action'),

    # ===== HTMX ENDPOINTS =====
    # Application drag-and-drop
    path('htmx/applications/<uuid:pk>/move/', ApplicationMoveView.as_view(), name='application-move'),

    # Bulk actions
    path('htmx/applications/bulk/', ApplicationBulkActionView.as_view(), name='application-bulk-action'),

    # Interview scheduling
    path('htmx/interviews/schedule/', InterviewScheduleView.as_view(), name='interview-schedule'),
    path('htmx/interviews/schedule/<uuid:application_pk>/', InterviewScheduleView.as_view(), name='interview-schedule-for-application'),

    # Interview feedback
    path('htmx/interviews/<uuid:interview_pk>/feedback/', InterviewFeedbackView.as_view(), name='interview-feedback'),
]
